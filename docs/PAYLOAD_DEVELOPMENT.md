# WiFi Pineapple Pager — Payload Development Guide

This document describes what you need to build new payloads for the WiFi Pineapple Pager, based on the structure of the existing Ragnar payload.

---

## 1. Required Files

Every payload needs these three pieces at minimum:

| File | Purpose |
|------|---------|
| `payload.sh` | Shell entry point — the Pager calls this |
| `main.py` | Python entry point — does the actual work |
| `lib/libpagerctl.so` | Hardware control library (copy from Ragnar or PAGERCTL payload) |

---

## 2. Shell Entry Point (`payload.sh`)

The Pager executes a shell script from the payload directory. At minimum it must:

### Required header (Pager reads these comments)
```sh
#!/bin/sh
# Title: Your Payload Name
# Description: One-line description
# Author: Your Name
# Version: 1.0
# Category: Reconnaissance   # or Exploitation, Exfiltration, etc.
# Library: libpagerctl.so (pagerctl)
```

### Standard paths
```sh
PAYLOAD_DIR="/root/payloads/user/<category>/<payload_name>"
DATA_DIR="$PAYLOAD_DIR/data"
LOG_FILE="$DATA_DIR/payload.log"
mkdir -p "$DATA_DIR"
```

### Environment setup
```sh
export PATH="/mmc/usr/bin:$PAYLOAD_DIR/bin:$PATH"
export PYTHONPATH="$PAYLOAD_DIR/lib:$PAYLOAD_DIR:$PYTHONPATH"
export LD_LIBRARY_PATH="/mmc/usr/lib:$PAYLOAD_DIR/lib:$PAYLOAD_DIR:$LD_LIBRARY_PATH"
export CRYPTOGRAPHY_OPENSSL_NO_LEGACY=1
```

### Display takeover
Before rendering to the LCD you must stop the Pager's own service:
```sh
/etc/init.d/pineapplepager stop 2>/dev/null
sleep 0.5
```

And restore it on exit via a trap:
```sh
cleanup() {
    /etc/init.d/pineapplepager start 2>/dev/null
}
trap cleanup EXIT
```

### DuckyScript-compatible logging
The Pager provides `LOG` and `WAIT_FOR_INPUT` as built-in commands in the shell environment:
```sh
LOG "message"                 # print to LCD
LOG "green" "success text"    # coloured output
BUTTON=$(WAIT_FOR_INPUT)      # blocks until GREEN (A) or RED (B)
```

### Button handling pattern
```sh
LOG "green" "GREEN = Start"
LOG "red"   "RED   = Exit"
while true; do
    BUTTON=$(WAIT_FOR_INPUT 2>/dev/null)
    case "$BUTTON" in
        "GREEN"|"A") break ;;
        "RED"|"B")   exit 0 ;;
    esac
done
```

### Exit codes
| Code | Meaning |
|------|---------|
| `0` | Normal exit |
| `42` | Hand off to another payload (path written to `$DATA_DIR/.next_payload`) |
| `99` | Return to main menu (loop back) |

---

## 3. Python Side

### Accessing hardware via `pagerctl`
`libpagerctl.so` is wrapped by `pagerctl.py` (a ctypes bridge). Put both in `lib/`:

```python
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))

from pagerctl import Pager

pager = Pager()
pager.display_clear()
pager.display_text(0, 0, "Hello Pager", font_size=20)
pager.display_refresh()
```

### Hardware capabilities exposed by `pagerctl`

| Feature | What it controls |
|---------|-----------------|
| LCD display | 480 × 222 px colour screen |
| TTF text rendering | Draw text with custom fonts and sizes |
| BMP image display | Show bitmap images on screen |
| LEDs | Blue / Cyan / Red / Yellow status indicators |
| Buttons | GREEN (A) and RED (B) physical buttons |

### LED colour conventions (follow these for consistency)

| Colour | Meaning |
|--------|---------|
| Blue | Idle |
| Cyan | Scanning |
| Red | Attacking / brute force |
| Yellow | Data exfiltration |

---

## 4. Directory Layout

```
/root/payloads/user/<category>/<payload_name>/
├── payload.sh              # Shell entry point
├── main.py                 # Python entry point
├── lib/
│   ├── libpagerctl.so      # Required — hardware control
│   └── pagerctl.py         # Required — Python wrapper
├── bin/                    # Optional compiled binaries (MIPS)
├── data/
│   └── payload.log         # Written at runtime
└── resources/
    └── fonts/              # Optional TTF fonts
```

---

## 5. Dependency Handling

The Pager runs OpenWrt on MIPS. Do not assume standard Python packages are installed.

**Check and install at runtime:**
```sh
if ! command -v nmap >/dev/null 2>&1; then
    opkg update
    opkg -d mmc install nmap
fi
```

**Bundle Python packages** that are not in opkg by copying them into `lib/` as plain directories (pure-Python wheels unpacked). For packages with C extensions you need MIPS-compiled `.so` files — copy them from Ragnar's `pager_lib/`.

**Pre-flight check** before taking over the display:
```sh
python3 -c "
from pagerctl import Pager
import json, threading
" 2>/dev/null || { LOG "red" "Import failed"; exit 1; }
```

---

## 6. Getting `libpagerctl.so`

Two sources, in priority order:

1. **Bundle it** — copy `libpagerctl.so` and `pagerctl.py` from this repo's `pager/` directory into your payload's `lib/` folder before deployment.
2. **Fall back to PAGERCTL** — at runtime check `/root/payloads/user/utilities/PAGERCTL/libpagerctl.so` and copy from there if found.

```sh
for dir in "$PAYLOAD_DIR/lib" "/root/payloads/user/utilities/PAGERCTL"; do
    if [ -f "$dir/libpagerctl.so" ]; then
        PAGERCTL_DIR="$dir"; break
    fi
done
```

---

## 7. Deployment

```sh
# From your development machine
PAGER_IP=172.16.42.1          # default Pager IP
PAYLOAD_NAME=my_payload
CATEGORY=reconnaissance

scp -r ./ root@$PAGER_IP:/root/payloads/user/$CATEGORY/$PAYLOAD_NAME/
ssh root@$PAGER_IP chmod +x /root/payloads/user/$CATEGORY/$PAYLOAD_NAME/payload.sh
```

Or adapt `scripts/install_pineapple_pager.sh` to suit your payload.

---

## 8. Minimal Working Example

### `payload.sh`
```sh
#!/bin/sh
# Title: Hello Pager
# Description: Minimal payload example
# Author: YourName
# Version: 1.0
# Category: Reconnaissance
# Library: libpagerctl.so (pagerctl)

PAYLOAD_DIR="/root/payloads/user/reconnaissance/hello_pager"
DATA_DIR="$PAYLOAD_DIR/data"
mkdir -p "$DATA_DIR"

export PYTHONPATH="$PAYLOAD_DIR/lib:$PAYLOAD_DIR:$PYTHONPATH"
export LD_LIBRARY_PATH="/mmc/usr/lib:$PAYLOAD_DIR/lib:$LD_LIBRARY_PATH"

cleanup() { /etc/init.d/pineapplepager start 2>/dev/null; }
trap cleanup EXIT

LOG "green" "GREEN = Run  |  RED = Exit"
while true; do
    BUTTON=$(WAIT_FOR_INPUT 2>/dev/null)
    case "$BUTTON" in
        "GREEN"|"A") break ;;
        "RED"|"B")   exit 0 ;;
    esac
done

/etc/init.d/pineapplepager stop 2>/dev/null
sleep 0.3

python3 "$PAYLOAD_DIR/main.py" >> "$DATA_DIR/payload.log" 2>&1
```

### `main.py`
```python
import sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))

from pagerctl import Pager

pager = Pager()
pager.set_led('cyan')
pager.display_clear()
pager.display_text(10, 10, "Hello, Pager!", font_size=24)
pager.display_refresh()
time.sleep(3)

pager.set_led('blue')
pager.display_clear()
pager.display_text(10, 10, "Done.", font_size=20)
pager.display_refresh()
time.sleep(1)
```

---

## 9. Quick Reference

| Thing you need | Where to get it |
|---------------|----------------|
| `libpagerctl.so` | `pager/` in this repo |
| `pagerctl.py` | `pager/pagerctl.py` in this repo |
| Pure-Python packages | Copy directory into `lib/` |
| MIPS C-extension packages | Copy from `pager_lib/` in this repo |
| TTF fonts | `resources/fonts/` in this repo |
| BMP status images | `resources/images/status/` in this repo |
| Install script template | `scripts/install_pineapple_pager.sh` |
