# st7789p3.py
# Driver for the 1.69" ST7789P3 240x280 RGB TFT LCD used on the PiSugar
# WHISPLAY HAT (and other 1.69" breakout boards that expose the same panel).
#
# Exposes the same interface as Waveshare e-Paper drivers so it integrates
# transparently with EPDHelper and the rest of Ragnar:
#   width, height, init(), Clear(), getbuffer(image), display(buf),
#   displayPartial(buf), sleep()
#
# Wiring (PiSugar WHISPLAY HAT default — adjust the *_PIN constants below
# if your board uses a different pinout):
#   VCC  → 3.3V
#   GND  → GND
#   DIN  → GPIO10 / MOSI  (pin 19)
#   CLK  → GPIO11 / SCLK  (pin 23)
#   CS   → GPIO8  / CE0   (pin 24)
#   DC   → GPIO22         (pin 15)
#   RST  → GPIO27         (pin 13)
#   BL   → GPIO13         (pin 33, PWM-capable)

import logging
import time
import struct

logger = logging.getLogger(__name__)

# Visible panel dimensions
EPD_WIDTH  = 240
EPD_HEIGHT = 280

# The ST7789 controller has a 240x320 RAM.  For a 240x280 panel the visible
# area is offset inside that RAM.  On the PiSugar WHISPLAY the panel is
# top-aligned (y_offset = 20).  Flip these if the picture appears shifted.
X_OFFSET = 0
Y_OFFSET = 20

RST_PIN  = 27
DC_PIN   = 22
CS_PIN   = 8
BL_PIN   = 13

SPI_BUS    = 0
SPI_DEVICE = 0
SPI_MAX_HZ = 40_000_000


class EPD:
    """ST7789P3 1.69" 240x280 TFT LCD driver with EPD-compatible interface."""

    def __init__(self):
        self.width  = EPD_WIDTH
        self.height = EPD_HEIGHT
        self._spi  = None
        self._gpio = {}
        self._initialized = False

    # ------------------------------------------------------------------
    # Public EPD-compatible interface
    # ------------------------------------------------------------------

    def init(self, *args):
        """Initialise SPI, GPIO and the ST7789P3 controller.

        Called every display loop iteration for e-Paper partial-update
        compatibility; the actual hardware reset + init sequence only runs
        once to avoid backlight flicker.
        """
        if self._initialized:
            return
        self._setup_hardware()
        self._reset()
        self._send_init_sequence()
        self._initialized = True
        logger.info("ST7789P3 initialised (%dx%d)", self.width, self.height)

    def Clear(self, color=0xFFFF):
        """Fill the entire display with a solid RGB565 colour (default white)."""
        if not self._initialized:
            self.init()
        hi = (color >> 8) & 0xFF
        lo = color & 0xFF
        buf = bytes([hi, lo]) * (self.width * self.height)
        self._set_window(0, 0, self.width - 1, self.height - 1)
        self._write_data_bulk(buf)
        logger.info("ST7789P3 cleared")

    def getbuffer(self, image):
        """Convert a PIL image (any mode) to a packed RGB565 byte string."""
        img = image.convert("RGB")

        if img.width != self.width or img.height != self.height:
            logger.warning(
                "Image size %dx%d → resizing to %dx%d",
                img.width, img.height, self.width, self.height,
            )
            img = img.resize((self.width, self.height))

        pixels = img.getdata()
        buf = bytearray(self.width * self.height * 2)
        idx = 0
        for r, g, b in pixels:
            rgb565 = ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)
            buf[idx]     = (rgb565 >> 8) & 0xFF
            buf[idx + 1] = rgb565 & 0xFF
            idx += 2
        return bytes(buf)

    def display(self, buf):
        """Write a full-screen RGB565 buffer to the display."""
        if not self._initialized:
            self.init()
        self._set_window(0, 0, self.width - 1, self.height - 1)
        self._write_data_bulk(buf)

    def displayPartial(self, buf):
        """TFT supports instant full-frame updates; treated same as display()."""
        self.display(buf)

    def sleep(self):
        """Enter sleep mode and turn off backlight."""
        self._write_cmd(0x10)   # SLPIN
        time.sleep(0.005)
        if "bl" in self._gpio:
            self._gpio["bl"].off()
        logger.info("ST7789P3 sleeping")

    # ------------------------------------------------------------------
    # Hardware helpers
    # ------------------------------------------------------------------

    def _setup_hardware(self):
        if self._spi is not None:
            return
        try:
            import spidev
            import gpiozero

            self._spi = spidev.SpiDev()
            self._spi.open(SPI_BUS, SPI_DEVICE)
            self._spi.max_speed_hz = SPI_MAX_HZ
            self._spi.mode = 0

            self._gpio["rst"] = gpiozero.LED(RST_PIN)
            self._gpio["dc"]  = gpiozero.LED(DC_PIN)
            self._gpio["bl"]  = gpiozero.LED(BL_PIN)

            self._gpio["bl"].on()
        except Exception as e:
            logger.error("ST7789P3 hardware setup failed: %s", e)
            raise

    def _reset(self):
        self._gpio["rst"].on()
        time.sleep(0.01)
        self._gpio["rst"].off()
        time.sleep(0.01)
        self._gpio["rst"].on()
        time.sleep(0.12)

    def _write_cmd(self, cmd):
        self._gpio["dc"].off()
        self._spi.writebytes([cmd])

    def _write_data(self, data):
        self._gpio["dc"].on()
        if isinstance(data, int):
            self._spi.writebytes([data])
        else:
            self._spi.writebytes(list(data))

    def _write_data_bulk(self, data):
        """Write large payloads in chunks to avoid spidev buffer limits."""
        self._gpio["dc"].on()
        chunk = 4096
        view = memoryview(data) if not isinstance(data, memoryview) else data
        for i in range(0, len(view), chunk):
            self._spi.writebytes2(view[i : i + chunk])

    def _set_window(self, x0, y0, x1, y1):
        x0 += X_OFFSET
        x1 += X_OFFSET
        y0 += Y_OFFSET
        y1 += Y_OFFSET
        self._write_cmd(0x2A)   # CASET
        self._write_data(struct.pack(">HH", x0, x1))
        self._write_cmd(0x2B)   # RASET
        self._write_data(struct.pack(">HH", y0, y1))
        self._write_cmd(0x2C)   # RAMWR

    def _send_init_sequence(self):
        """ST7789P3 power-on initialisation sequence (standard ST7789 command set)."""
        self._write_cmd(0x11)   # SLPOUT — exit sleep
        time.sleep(0.12)

        self._write_cmd(0x36)   # MADCTL — memory access / scan direction
        self._write_data(0x00)  # portrait, RGB order

        self._write_cmd(0x3A)   # COLMOD — pixel format
        self._write_data(0x05)  # 16-bit RGB565

        self._write_cmd(0xB2)   # PORCTRL — porch control
        self._write_data([0x0C, 0x0C, 0x00, 0x33, 0x33])

        self._write_cmd(0xB7)   # GCTRL — gate control
        self._write_data(0x35)

        self._write_cmd(0xBB)   # VCOMS
        self._write_data(0x19)

        self._write_cmd(0xC0)   # LCMCTRL
        self._write_data(0x2C)

        self._write_cmd(0xC2)   # VDVVRHEN
        self._write_data(0x01)

        self._write_cmd(0xC3)   # VRHS
        self._write_data(0x12)

        self._write_cmd(0xC4)   # VDVS
        self._write_data(0x20)

        self._write_cmd(0xC6)   # FRCTRL2 — 60 Hz frame rate in normal mode
        self._write_data(0x0F)

        self._write_cmd(0xD0)   # PWCTRL1
        self._write_data([0xA4, 0xA1])

        self._write_cmd(0xE0)   # PVGAMCTRL — positive gamma
        self._write_data([0xD0, 0x04, 0x0D, 0x11, 0x13, 0x2B, 0x3F,
                          0x54, 0x4C, 0x18, 0x0D, 0x0B, 0x1F, 0x23])

        self._write_cmd(0xE1)   # NVGAMCTRL — negative gamma
        self._write_data([0xD0, 0x04, 0x0C, 0x11, 0x13, 0x2C, 0x3F,
                          0x44, 0x51, 0x2F, 0x1F, 0x1F, 0x20, 0x23])

        self._write_cmd(0x21)   # INVON — display inversion required for most
                                # ST7789 panels to show correct colours
        self._write_cmd(0x29)   # DISPON
        time.sleep(0.02)
