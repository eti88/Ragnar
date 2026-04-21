"""
DNS vulnerability scanner action.

Checks every host exposing port 53 for two common DNS misconfigurations:
  * Unauthenticated zone transfers (AXFR) — severity high
  * Open recursive resolver — severity medium (DNS amplification risk)

Findings are fed into Ragnar's Network Intelligence via the base class.
"""

import socket

import dns.exception
import dns.query
import dns.resolver
import dns.zone

from actions.vuln_scanner_base import Finding, VulnScannerBase

b_class = "DNSScanner"
b_module = "dns_scanner"
b_status = "dns_scan"
b_port = 53
b_parent = None


class DNSScanner(VulnScannerBase):
    plugin_name = "DNSScanner"

    ZONE_PROBE_DOMAINS = (
        "localhost", "local", "internal", "lan", "home", "corp"
    )

    def scan_host(self, ip, row):
        if not self.host_has_port(row, 53):
            return []

        findings = []

        if self._has_zone_transfer(ip):
            findings.append(Finding(
                port=53,
                service='dns',
                vulnerability='DNS zone transfer (AXFR) allowed',
                severity='high',
                details={'check': 'axfr_anonymous'}
            ))

        if self._has_open_recursion(ip):
            findings.append(Finding(
                port=53,
                service='dns',
                vulnerability='Open DNS recursion (amplification risk)',
                severity='medium',
                details={'check': 'open_recursion'}
            ))

        return findings

    # ------------------------------------------------------------------

    def _has_zone_transfer(self, ip: str) -> bool:
        for zone in self.ZONE_PROBE_DOMAINS:
            try:
                xfr = dns.query.xfr(ip, zone, timeout=5, lifetime=5)
                dns.zone.from_xfr(xfr)
                self.logger.warning(f"{ip}: AXFR allowed for zone {zone}")
                return True
            except (dns.exception.DNSException, ConnectionError,
                    socket.timeout, socket.gaierror, OSError):
                continue
        return False

    def _has_open_recursion(self, ip: str) -> bool:
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [ip]
            resolver.timeout = 3
            resolver.lifetime = 5
            answer = resolver.resolve('google.com', 'A', raise_on_no_answer=False)
            if answer.rrset is not None and len(answer.rrset) > 0:
                self.logger.warning(f"{ip}: open recursive resolver")
                return True
        except (dns.exception.DNSException, ConnectionError,
                socket.timeout, socket.gaierror, OSError):
            pass
        return False
