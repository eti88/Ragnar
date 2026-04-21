"""
Shared helpers for vulnerability-scanner plugins.

Ragnar's orchestrator expects every action to expose:
    __init__(self, shared_data)
    execute(self, ip, port, row, status_key) -> 'success' | 'failed'

VulnScannerBase provides a thin template for plugins that only need to
probe a host and report findings to network intelligence.  Subclasses
override scan_host() and yield Finding objects; the base class takes care
of error handling and routing the results to Network Intelligence.
"""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass, field
from typing import Iterable, Optional

parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from logger import Logger


@dataclass
class Finding:
    port: int
    service: str
    vulnerability: str      # short headline used by the dashboard
    severity: str = "medium"   # low / medium / high / critical
    details: dict = field(default_factory=dict)


class VulnScannerBase:
    """Minimal scaffolding for passive vulnerability scanners."""

    plugin_name: str = "VulnScannerBase"

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.logger = Logger(name=f"{self.plugin_name}.py", level=logging.INFO)

    # ------------------------------------------------------------------
    # Entry point called by the orchestrator
    # ------------------------------------------------------------------

    def execute(self, ip, port, row, status_key):
        try:
            findings = list(self.scan_host(ip, row) or [])
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.warning(f"{self.plugin_name} failed on {ip}: {exc}")
            return 'failed'

        for finding in findings:
            self._report(ip, finding)

        if findings:
            self.logger.info(
                f"{self.plugin_name} reported {len(findings)} finding(s) on {ip}"
            )
        return 'success'

    # ------------------------------------------------------------------
    # Hook for subclasses
    # ------------------------------------------------------------------

    def scan_host(self, ip: str, row: dict) -> Iterable[Finding]:
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def _report(self, ip: str, finding: Finding) -> None:
        ni = getattr(self.shared_data, "network_intelligence", None)
        if ni is None:
            self.logger.debug("Network intelligence unavailable; skipping report")
            return
        try:
            ni.add_vulnerability(
                host=ip,
                port=int(finding.port),
                service=finding.service,
                vulnerability=finding.vulnerability,
                severity=finding.severity,
                details={
                    **finding.details,
                    'source': self.plugin_name,
                }
            )
        except Exception as exc:
            self.logger.warning(
                f"Failed to add vulnerability from {self.plugin_name} "
                f"for {ip}: {exc}"
            )

    # ------------------------------------------------------------------
    # Convenience: check if a port appears in the netkb row
    # ------------------------------------------------------------------

    @staticmethod
    def host_has_port(row: dict, port: int) -> bool:
        ports_field = row.get('Ports') if isinstance(row, dict) else None
        if not ports_field:
            return False
        if isinstance(ports_field, (list, tuple, set)):
            values = ports_field
        else:
            text = str(ports_field).strip().strip('[]').replace('"', '').replace("'", '')
            values = [p for p in text.replace(';', ',').split(',') if p]
        try:
            return any(int(str(v).strip()) == port for v in values if str(v).strip())
        except ValueError:
            return False
