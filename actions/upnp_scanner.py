"""
UPnP / SSDP scanner action.

Sends a unicast SSDP M-SEARCH to UDP/1900 on the target host.  Any device
that responds exposes its SSDP service table, which typically includes
IGD (Internet Gateway Device) endpoints — historically abused by CVEs
like CallStranger and the Cable Haunt family.

The finding records the device server banner and the LOCATION URL of the
device description so operators can follow up manually.
"""

import socket
import urllib.parse

from actions.vuln_scanner_base import Finding, VulnScannerBase

b_class = "UPnPScanner"
b_module = "upnp_scanner"
b_status = "upnp_scan"
b_port = None
b_parent = None


class UPnPScanner(VulnScannerBase):
    plugin_name = "UPnPScanner"

    SSDP_TIMEOUT = 3.0
    SSDP_MX = 2
    SSDP_TARGETS = (
        "upnp:rootdevice",
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    )

    def scan_host(self, ip, row):
        # SSDP runs on UDP; Ragnar's Ports column is TCP-only so we always
        # probe once per host instead of gating on port presence.
        response = self._ssdp_probe(ip)
        if not response:
            return []

        headers = self._parse_ssdp(response)
        server = headers.get('server', '')
        location = headers.get('location', '')
        st = headers.get('st', '')

        severity = 'medium'
        description_parts = ["UPnP service exposed"]
        if server:
            description_parts.append(server)
        if st:
            description_parts.append(f"ST={st}")

        # IGD (gateway) endpoints are especially sensitive: external port
        # forwarding can often be requested without authentication.
        if 'InternetGatewayDevice' in st or 'InternetGatewayDevice' in server:
            severity = 'high'
            description_parts.append("IGD (gateway) control endpoint")

        self.logger.warning(
            f"{ip}: UPnP/SSDP response — {server or 'unknown'} @ {location}"
        )

        return [Finding(
            port=1900,
            service='upnp',
            vulnerability=' | '.join(description_parts),
            severity=severity,
            details={
                'server': server,
                'location': location,
                'st': st,
                'description_host': self._safe_host_from_url(location),
            }
        )]

    # ------------------------------------------------------------------

    def _ssdp_probe(self, ip: str) -> bytes:
        responses = b''
        for st in self.SSDP_TARGETS:
            msg = (
                "M-SEARCH * HTTP/1.1\r\n"
                f"HOST: {ip}:1900\r\n"
                "MAN: \"ssdp:discover\"\r\n"
                f"MX: {self.SSDP_MX}\r\n"
                f"ST: {st}\r\n"
                "\r\n"
            ).encode()
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(self.SSDP_TIMEOUT)
                    sock.sendto(msg, (ip, 1900))
                    data, _ = sock.recvfrom(4096)
                    if data:
                        return data
            except (socket.timeout, socket.gaierror, OSError):
                continue
        return responses

    @staticmethod
    def _parse_ssdp(raw: bytes) -> dict:
        headers: dict = {}
        for line in raw.split(b"\r\n"):
            if b":" not in line:
                continue
            key, _, value = line.partition(b":")
            headers[key.strip().lower().decode('ascii', 'replace')] = \
                value.strip().decode('utf-8', 'replace')
        return headers

    @staticmethod
    def _safe_host_from_url(url: str) -> str:
        try:
            return urllib.parse.urlsplit(url).netloc if url else ''
        except Exception:
            return ''
