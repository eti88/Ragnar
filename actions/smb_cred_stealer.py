"""
SMB credential / sensitive-file stealer action.

Attaches to every host exposing SMB (TCP/445) with a NULL session
(anonymous guest) and enumerates the advertised shares.  For every
non-administrative share reachable without credentials it lists a
bounded number of files and flags any whose name matches a sensitive
file pattern (SSH keys, *.ovpn, wp-config, *.rdp, id_rsa, …).

Complements Ragnar's existing StealFilesSMB action, which operates on
authenticated shares after SMBBruteforce succeeds: this module catches
the much more common case of misconfigured anonymous SMB shares that
leak credentials long before any bruteforce is attempted.  No files are
downloaded — the finding reports filenames only.
"""

import logging
import re
import socket

from actions.vuln_scanner_base import Finding, VulnScannerBase

try:
    from smb.SMBConnection import SMBConnection
    from smb.base import NotReadyError, SMBTimeout
    _SMB_AVAILABLE = True
except Exception:  # pragma: no cover - pysmb missing
    SMBConnection = None
    NotReadyError = Exception
    SMBTimeout = Exception
    _SMB_AVAILABLE = False

b_class = "SMBCredStealer"
b_module = "smb_cred_stealer"
b_status = "smb_cred_stealer"
b_port = 445
b_parent = None


_SENSITIVE_PATTERNS = [re.compile(p, re.IGNORECASE) for p in (
    # Authentication material
    r"id_rsa(\.pub)?$",
    r".*\.ppk$",
    r".*\.pem$",
    r".*\.pfx$",
    r".*\.key$",
    # Remote access / VPN
    r".*\.rdp$",
    r".*\.ovpn$",
    r".*\.pcf$",       # Cisco VPN
    r".*\.pbk$",       # Windows VPN
    r".*\.vnc$",
    # Credential stores
    r"(^|.*/)password.*\.(txt|csv|xlsx|docx?)$",
    r"(^|.*/)passwd.*\.(txt|csv)$",
    r"(^|.*/)credential.*\.(txt|json|xml)$",
    r"(^|.*/)secret.*\.(txt|json|xml)$",
    r"unattend\.xml$",
    # Config files that often contain creds
    r"wp-config(\.php)?(\.bak)?$",
    r"web\.config$",
    r".*\.env(\.local)?$",
)]

_SKIP_DIRS = {".", "..", "System Volume Information", "$RECYCLE.BIN"}
_MAX_FILES_PER_SHARE = 500   # bounded traversal to avoid hanging on huge trees
_MAX_DEPTH = 4


class SMBCredStealer(VulnScannerBase):
    plugin_name = "SMBCredStealer"

    def scan_host(self, ip, row):
        if not _SMB_AVAILABLE:
            self.logger.debug("pysmb not available; skipping SMB cred stealer")
            return []

        conn = self._connect(ip)
        if conn is None:
            return []

        try:
            shares = self._list_shares(conn)
        except Exception as exc:
            self.logger.debug(f"{ip}: share enumeration failed: {exc}")
            shares = []

        findings = []
        for share in shares:
            sensitive = self._scan_share(conn, share)
            if sensitive:
                preview = ', '.join(sensitive[:10])
                extra = f" (+{len(sensitive) - 10} more)" if len(sensitive) > 10 else ""
                findings.append(Finding(
                    port=445,
                    service='smb',
                    vulnerability=(
                        f"Anonymous SMB share '{share}' exposes sensitive files: "
                        f"{preview}{extra}"
                    ),
                    severity='high',
                    details={
                        'share': share,
                        'files': sensitive[:50],
                        'total_count': len(sensitive),
                        'check': 'anonymous_smb_sensitive_files',
                    },
                ))

        try:
            conn.close()
        except Exception:
            pass

        return findings

    # ------------------------------------------------------------------

    def _connect(self, ip: str):
        try:
            conn = SMBConnection(
                username='',
                password='',
                my_name='ragnar',
                remote_name=ip,
                use_ntlm_v2=True,
                is_direct_tcp=True,
            )
            if conn.connect(ip, 445, timeout=6):
                return conn
        except (NotReadyError, SMBTimeout, ConnectionError,
                socket.timeout, socket.gaierror, OSError) as exc:
            self.logger.debug(f"{ip}: anonymous SMB connect failed: {exc}")
        except Exception as exc:
            self.logger.debug(f"{ip}: unexpected SMB error: {exc}")
        return None

    def _list_shares(self, conn):
        shares = []
        for share in conn.listShares(timeout=8):
            name = share.name
            if share.isSpecial or share.type != 0:  # 0 == DISK_TREE
                continue
            if name.endswith('$') and name.upper() not in ('C$', 'D$', 'E$'):
                continue
            shares.append(name)
        return shares

    def _scan_share(self, conn, share_name: str):
        sensitive = []
        budget = _MAX_FILES_PER_SHARE
        try:
            self._walk(conn, share_name, '/', depth=0, sensitive=sensitive,
                       budget=[budget])
        except Exception as exc:
            self.logger.debug(f"walk of {share_name} aborted: {exc}")
        return sensitive

    def _walk(self, conn, share, path, depth, sensitive, budget):
        if depth > _MAX_DEPTH or budget[0] <= 0:
            return
        try:
            entries = conn.listPath(share, path, timeout=6)
        except Exception as exc:
            self.logger.debug(f"listPath {share}:{path} failed: {exc}")
            return

        for entry in entries:
            if budget[0] <= 0:
                return
            budget[0] -= 1

            name = entry.filename
            if name in _SKIP_DIRS:
                continue

            full = f"{path.rstrip('/')}/{name}"
            if entry.isDirectory:
                self._walk(conn, share, full, depth + 1, sensitive, budget)
                continue

            lowered = full.lower()
            for pattern in _SENSITIVE_PATTERNS:
                if pattern.search(lowered):
                    sensitive.append(full)
                    break
