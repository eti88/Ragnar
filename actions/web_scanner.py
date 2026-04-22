"""
Web vulnerability scanner action.

Passive checks against every HTTP(S) listener discovered on a host:
  * Directory listing enabled (low severity)
  * Missing key security response headers (low severity)
  * Exposed sensitive files (.env, .git/config, wp-config.php, …)

Heavier checks from PenDonn's original module were intentionally dropped:
  * Nikto subprocess — requires an external binary + 5 minute timeouts
  * Default-credential POST loops — duplicates Ragnar's dedicated
    bruteforce plugins and risks locking out real accounts

The scanner probes any of ports 80/443/8080/8443 reported as open in the
netkb row, so it is registered with b_port=null to let the orchestrator
invoke it for every alive host.
"""

import os
import socket
import ssl

import urllib3
import requests

from actions.vuln_scanner_base import Finding, VulnScannerBase

# Silence the self-signed TLS warnings that will be common on LAN devices.
try:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:  # pragma: no cover - very old urllib3
    pass

b_class = "WebScanner"
b_module = "web_scanner"
b_status = "web_scan"
b_port = None
b_parent = None


class WebScanner(VulnScannerBase):
    plugin_name = "WebScanner"

    HTTP_PORTS = (80, 8080)
    HTTPS_PORTS = (443, 8443)
    USER_AGENT = "Mozilla/5.0 (compatible; RagnarWebScanner/1.0)"
    REQUEST_TIMEOUT = 4.0

    DIRECTORY_LISTING_MARKERS = (
        "Index of /",
        "Directory listing for",
        "<title>Index of",
        "Parent Directory",
    )

    SECURITY_HEADERS = (
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "Referrer-Policy",
    )

    SENSITIVE_FILES = (
        "/.git/config",
        "/.git/HEAD",
        "/.env",
        "/.env.local",
        "/config.php",
        "/configuration.php",
        "/wp-config.php",
        "/wp-config.php.bak",
        "/web.config",
        "/.htaccess",
        "/backup.sql",
        "/database.sql",
        "/dump.sql",
        "/phpinfo.php",
        "/info.php",
        "/.DS_Store",
        "/server-status",
    )

    def scan_host(self, ip, row):
        endpoints = self._endpoints_for_host(row)
        if not endpoints:
            return []

        findings = []
        for scheme, port in endpoints:
            base_url = f"{scheme}://{ip}:{port}"

            index_resp = self._get(base_url + "/")
            if index_resp is None:
                # Port was reported open but the service didn't answer HTTP.
                continue

            if self._has_directory_listing(index_resp):
                findings.append(Finding(
                    port=port,
                    service=scheme,
                    vulnerability="Directory listing enabled",
                    severity="low",
                    details={"url": base_url + "/", "check": "directory_listing"},
                ))

            missing = self._missing_security_headers(index_resp)
            if missing:
                findings.append(Finding(
                    port=port,
                    service=scheme,
                    vulnerability=f"Missing security headers: {', '.join(missing)}",
                    severity="low",
                    details={
                        "url": base_url + "/",
                        "missing_headers": missing,
                        "check": "security_headers",
                    },
                ))

            exposed = self._find_sensitive_files(base_url)
            if exposed:
                findings.append(Finding(
                    port=port,
                    service=scheme,
                    vulnerability=f"Sensitive files exposed: {', '.join(exposed)}",
                    severity="medium",
                    details={
                        "url": base_url,
                        "exposed_files": exposed,
                        "check": "sensitive_files",
                    },
                ))

        return findings

    # ------------------------------------------------------------------

    def _endpoints_for_host(self, row):
        endpoints = []
        for port in self.HTTP_PORTS:
            if self.host_has_port(row, port):
                endpoints.append(("http", port))
        for port in self.HTTPS_PORTS:
            if self.host_has_port(row, port):
                endpoints.append(("https", port))
        return endpoints

    def _get(self, url: str):
        try:
            return requests.get(
                url,
                timeout=self.REQUEST_TIMEOUT,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": self.USER_AGENT},
            )
        except (requests.RequestException, ssl.SSLError,
                ConnectionError, socket.timeout, OSError):
            return None

    def _has_directory_listing(self, response) -> bool:
        try:
            body = response.text
        except Exception:
            return False
        return any(marker in body for marker in self.DIRECTORY_LISTING_MARKERS)

    def _missing_security_headers(self, response):
        headers = {k.lower(): v for k, v in response.headers.items()}
        missing = [h for h in self.SECURITY_HEADERS if h.lower() not in headers]
        return missing

    def _find_sensitive_files(self, base_url: str):
        found = []
        for path in self.SENSITIVE_FILES:
            resp = self._get(base_url + path)
            if resp is None:
                continue
            if resp.status_code != 200:
                continue
            content = resp.content or b""
            if not content:
                continue
            # Many servers return a custom 200 HTML error page for missing
            # files — filter those out by looking for typical error markers.
            lowered = content[:400].lower()
            if b"<!doctype html" in lowered and b"not found" in lowered:
                continue
            found.append(path)
        return found
