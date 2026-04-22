"""
VPN portal detector action.

Fingerprints HTTPS services for the login pages of common enterprise
VPN appliances (Cisco AnyConnect, Fortinet SSL-VPN, Palo Alto
GlobalProtect, Pulse Secure, Check Point Mobile Access, OpenVPN Access
Server, …).  A match is flagged as an informational finding so that
operators can follow up with credential-testing tools manually.

This is the HTTPS half of PenDonn's VPN cred-stealer — the SMB half is
already covered by smb_cred_stealer.py (which includes .ovpn/.pcf/.pbk
in its sensitive-file pattern list).
"""

import socket
import ssl

import urllib3
import requests

from actions.vuln_scanner_base import Finding, VulnScannerBase

try:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:  # pragma: no cover
    pass

b_class = "VPNPortalDetector"
b_module = "vpn_portal_detector"
b_status = "vpn_portal_scan"
b_port = None
b_parent = None


# (signature substring, product label) pairs.  Matched against both the
# response body (lower-cased) and the Server/WWW-Authenticate/Set-Cookie
# headers.  Order is stable so the most specific match wins.
_VPN_SIGNATURES = (
    ("anyconnect",                 "Cisco AnyConnect"),
    ("cisco ssl vpn",              "Cisco SSL VPN"),
    ("/+cscoe+/",                  "Cisco ASA / AnyConnect"),
    ("fortinet",                   "Fortinet SSL-VPN"),
    ("fortigate",                  "FortiGate SSL-VPN"),
    ("/remote/login",              "Fortinet SSL-VPN"),
    ("globalprotect",              "Palo Alto GlobalProtect"),
    ("paloaltonetworks",           "Palo Alto GlobalProtect"),
    ("pulse secure",               "Pulse Secure Connect"),
    ("juniper",                    "Juniper SSL-VPN"),
    ("/dana-na/",                  "Juniper / Pulse Secure"),
    ("checkpoint",                 "Check Point Mobile Access"),
    ("sslvpn",                     "Generic SSL-VPN portal"),
    ("openvpn",                    "OpenVPN Access Server"),
    ("sonicwall",                  "SonicWall NetExtender"),
    ("array networks",             "Array Networks AG"),
)


class VPNPortalDetector(VulnScannerBase):
    plugin_name = "VPNPortalDetector"

    HTTPS_PORTS = (443, 8443, 10443)
    USER_AGENT = "Mozilla/5.0 (compatible; RagnarVPNProbe/1.0)"
    REQUEST_TIMEOUT = 5.0

    def scan_host(self, ip, row):
        findings = []
        for port in self.HTTPS_PORTS:
            if not self.host_has_port(row, port):
                continue
            product = self._fingerprint(ip, port)
            if product is None:
                continue
            findings.append(Finding(
                port=port,
                service='https',
                vulnerability=f"VPN portal detected: {product}",
                severity='medium',
                details={
                    'product': product,
                    'url': f"https://{ip}:{port}/",
                    'check': 'vpn_portal_fingerprint',
                },
            ))
        return findings

    # ------------------------------------------------------------------

    def _fingerprint(self, ip: str, port: int):
        try:
            resp = requests.get(
                f"https://{ip}:{port}/",
                timeout=self.REQUEST_TIMEOUT,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": self.USER_AGENT},
            )
        except (requests.RequestException, ssl.SSLError,
                ConnectionError, socket.timeout, OSError):
            return None

        haystack_parts = []
        try:
            haystack_parts.append(resp.text[:20000].lower())
        except Exception:
            pass

        for key, value in resp.headers.items():
            haystack_parts.append(f"{key.lower()}: {str(value).lower()}")
        final_url = resp.url.lower() if hasattr(resp, 'url') else ''
        haystack_parts.append(final_url)

        haystack = "\n".join(haystack_parts)

        for needle, label in _VPN_SIGNATURES:
            if needle in haystack:
                self.logger.warning(
                    f"{ip}:{port} looks like a {label} VPN portal"
                )
                return label
        return None
