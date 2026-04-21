"""
SNMP vulnerability scanner action.

Probes UDP/161 with a short list of common community strings.  Any host
that responds to a GET for sysDescr.0 reveals both the community string
(an authentication failure in itself) and the device description, which
is logged as a finding.

Uses raw SNMPv1 packets so it avoids the heavy pysnmp dependency.
"""

import socket
import struct

from actions.vuln_scanner_base import Finding, VulnScannerBase

b_class = "SNMPScanner"
b_module = "snmp_scanner"
b_status = "snmp_scan"
b_port = 161
b_parent = None


# sysDescr.0 — 1.3.6.1.2.1.1.1.0
_SYSDESCR_OID = (1, 3, 6, 1, 2, 1, 1, 1, 0)


class SNMPScanner(VulnScannerBase):
    plugin_name = "SNMPScanner"

    COMMUNITY_STRINGS = (
        "public", "private", "admin", "cisco", "community",
        "manager", "read", "write", "default", "internal"
    )

    UDP_TIMEOUT = 2.5

    def scan_host(self, ip, row):
        findings = []
        for community in self.COMMUNITY_STRINGS:
            response = self._snmp_get_sysdescr(ip, community)
            if response is None:
                continue

            severity = 'high' if community in ('public', 'private') else 'medium'
            self.logger.warning(
                f"{ip}: SNMP responds to community '{community}'"
            )
            findings.append(Finding(
                port=161,
                service='snmp',
                vulnerability=f"SNMP weak community string: {community}",
                severity=severity,
                details={
                    'community': community,
                    'sys_descr': response[:240],
                    'check': 'community_string_guess',
                }
            ))
            # One successful guess is enough to flag the host — don't flood
            # Network Intelligence with 10 findings per device.
            break

        return findings

    # ------------------------------------------------------------------
    # Minimal SNMPv1 GET implementation (BER-encoded)
    # ------------------------------------------------------------------

    def _snmp_get_sysdescr(self, ip: str, community: str):
        try:
            packet = self._build_get_request(community, _SYSDESCR_OID)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.UDP_TIMEOUT)
                sock.sendto(packet, (ip, 161))
                data, _ = sock.recvfrom(4096)
            return self._extract_sysdescr(data)
        except (socket.timeout, socket.gaierror, OSError):
            return None

    @staticmethod
    def _tlv(tag: int, value: bytes) -> bytes:
        if len(value) < 0x80:
            return bytes([tag, len(value)]) + value
        length = len(value)
        length_bytes = []
        while length:
            length_bytes.insert(0, length & 0xFF)
            length >>= 8
        return bytes([tag, 0x80 | len(length_bytes)]) + bytes(length_bytes) + value

    @classmethod
    def _encode_integer(cls, n: int) -> bytes:
        length = max(1, (n.bit_length() + 8) // 8)
        return cls._tlv(0x02, n.to_bytes(length, 'big', signed=False))

    @classmethod
    def _encode_octet_string(cls, s: bytes) -> bytes:
        return cls._tlv(0x04, s)

    @classmethod
    def _encode_null(cls) -> bytes:
        return cls._tlv(0x05, b'')

    @classmethod
    def _encode_sequence(cls, body: bytes) -> bytes:
        return cls._tlv(0x30, body)

    @classmethod
    def _encode_oid(cls, oid: tuple) -> bytes:
        first = oid[0] * 40 + oid[1]
        body = bytearray([first])
        for subid in oid[2:]:
            if subid < 0x80:
                body.append(subid)
            else:
                chunks = []
                while subid:
                    chunks.insert(0, subid & 0x7F)
                    subid >>= 7
                for i in range(len(chunks) - 1):
                    chunks[i] |= 0x80
                body.extend(chunks)
        return cls._tlv(0x06, bytes(body))

    @classmethod
    def _build_get_request(cls, community: str, oid: tuple) -> bytes:
        version = cls._encode_integer(0)  # SNMPv1
        comm = cls._encode_octet_string(community.encode())
        request_id = cls._encode_integer(1)
        err_status = cls._encode_integer(0)
        err_index = cls._encode_integer(0)
        varbind = cls._encode_sequence(cls._encode_oid(oid) + cls._encode_null())
        varbind_list = cls._encode_sequence(varbind)
        pdu_body = request_id + err_status + err_index + varbind_list
        pdu = cls._tlv(0xA0, pdu_body)  # GetRequest PDU
        return cls._encode_sequence(version + comm + pdu)

    @staticmethod
    def _extract_sysdescr(data: bytes):
        """Walk the BER response looking for the first OCTET STRING after
        the varbind OID.  Returns the decoded string on success."""
        i = 0
        last_tag = None
        while i < len(data):
            tag = data[i]
            i += 1
            if i >= len(data):
                return None
            length = data[i]
            i += 1
            if length & 0x80:
                n = length & 0x7F
                if n == 0 or i + n > len(data):
                    return None
                length = int.from_bytes(data[i:i + n], 'big')
                i += n
            if tag in (0x30, 0xA0, 0xA1, 0xA2):
                # Recurse into SEQUENCE / PDU
                continue
            if tag == 0x04 and last_tag == 0x06:
                try:
                    return data[i:i + length].decode('utf-8', errors='replace')
                except Exception:
                    return None
            last_tag = tag
            i += length
        return None
