"""
scanner.py

Mastercard IPM Scanner

Walks the file using the 4-byte big-endian length prefix of every
record and returns RawRecord objects. No DE / bitmap / PDS parsing
happens here.
"""

from dataclasses import dataclass

VALID_MTI = {
    "1240",
    "1241",
    "1242",
    "1243",
    "1244",
    "1442",
    "1644",
    "1645",
    "1646",
    "1740",
    "1741",
}


@dataclass
class RawRecord:
    offset: int
    length: int
    mti: str
    payload: bytes
    repairs: list = None
    trailing: bytes = None

    def __post_init__(self):
        if self.repairs is None:
            self.repairs = []
        if self.trailing is None:
            self.trailing = b""


class Scanner:

    def __init__(self, verbose=True):
        self.verbose = verbose

    # ------------------------------------------------------------------

    def scan(self, filename):
        with open(filename, "rb") as f:
            data = f.read()

        records = []
        offset = 0

        while True:
            rec = self.read_record(data, offset)
            if rec is None:
                break

            records.append(rec)

            next_offset = self.find_next_record(
                data,
                offset,
                rec.length
            )

            if next_offset is None:
                break

            declared_end = offset + 4 + rec.length
            if next_offset > declared_end:
                rec.trailing = data[declared_end:next_offset]

            offset = next_offset

        return records

    # ------------------------------------------------------------------

    @staticmethod
    def _classify_payload(payload):
        """Return ``(mti, clean_payload)`` or ``(None, None)``.

        A handful of records have stray bytes (0x00 / 0x0D) inserted
        inside the MTI, splitting it (e.g. "12\\x00\\x0040"). Rebuild the
        MTI from the first 8 payload bytes and glue the rest of the
        payload back on. Only the first 8 bytes are inspected, so the
        bitmap / binary header bytes that follow are never touched.
        """
        try:
            mti = payload[:4].decode("cp037")
        except Exception:
            mti = ""

        if mti in VALID_MTI:
            return mti, payload

        first8 = payload[:8]
        if len(first8) < 4:
            return None, None

        cleaned = bytes(b for b in first8 if b not in (0x00, 0x0D))
        if len(cleaned) < 4:
            return None, None

        try:
            mti = cleaned[:4].decode("cp037")
        except Exception:
            return None, None

        if mti in VALID_MTI:
            return mti, cleaned[:4] + payload[8:]

        return None, None

    # ------------------------------------------------------------------

    @staticmethod
    def _repair_payload(payload):
        """Return ``(payload, repairs)``.

        A handful of records have stray null bytes inserted into / before
        the bitmap region right after the MTI, or are missing the first
        two bitmap bytes. Only exact signatures are repaired:

            - ``07 C3 8D E1`` right after the MTI: missing ``F0 10``
            - ``00 00 F0 10`` after the MTI: nulls before the bitmap
            - ``F0 00 00 10`` after the MTI: nulls inside first bitmap word
            - ``F0 10 07 00 00 C3``: nulls after bitmap byte 07
            - ``F0 10 00 00`` after the MTI: nulls after ``F0 10``
            - ``F0 10 07 C3 00 00 8D``: nulls after bitmap byte C3
            - ``F0 10 07 C3 8D 00 00``: nulls after bitmap byte 8D
        """
        repairs = []
        p = payload

        if len(p) < 20:
            return p, repairs

        if p[4:8] == b"\x07\xc3\x8d\xe1":
            p = p[:4] + b"\xf0\x10" + p[4:]
            repairs.append("missing-bitmap-f010")

        elif p[4:6] == b"\x00\x00" and p[6:8] == b"\xf0\x10":
            p = p[:4] + p[6:]
            repairs.append("nulls-before-bitmap")

        elif p[4:8] == b"\xf0\x00\x00\x10":
            p = p[:5] + p[7:]
            repairs.append("nulls-in-bitmap")

        elif p[4:9] == b"\xf0\x10\x07\x00\x00":
            p = p[:4] + p[4:7] + p[9:]
            repairs.append("nulls-in-bitmap")

        elif p[4:8] == b"\xf0\x10\x00\x00":
            p = p[:4] + p[4:6] + p[8:]
            repairs.append("nulls-in-bitmap")

        elif p[4:11] == b"\xf0\x10\x07\xc3\x00\x00\x8d":
            p = p[:4] + p[4:8] + p[10:]
            repairs.append("nulls-in-bitmap")

        elif p[4:11] == b"\xf0\x10\x07\xc3\x8d\x00\x00":
            p = p[:4] + p[4:9] + p[11:]
            repairs.append("nulls-in-bitmap")

        return p, repairs

    # ------------------------------------------------------------------

    def read_record(self, data, offset):
        """Read the RawRecord at ``offset``, or None if not a record."""
        if offset + 8 > len(data):
            return None

        length = int.from_bytes(
            data[offset:offset + 4],
            "big"
        )

        if not (20 <= length <= 5000):
            return None

        if offset + 4 + length > len(data):
            return None

        payload = data[
            offset + 4:
            offset + 4 + length
        ]

        mti, cleaned = self._classify_payload(payload)

        if mti is None:
            recovered = self._recover_shifted_record(data, offset, length)
            if recovered is None:
                return None
            return recovered

        cleaned, repairs = self._repair_payload(cleaned)

        return RawRecord(
            offset=offset,
            length=length,
            mti=mti,
            payload=cleaned,
            repairs=repairs
        )

    # ------------------------------------------------------------------

    def _recover_shifted_record(self, data, offset, declared_length):
        """Recover records with junk bytes before a valid MTI.

        This is deliberately narrow: the declared record must fail normal
        MTI classification, skipping at most four bytes must expose a valid
        MTI, and a following normal record header must prove the physical
        end of the recovered record.
        """
        if not (20 <= declared_length <= 5000):
            return None
        if offset + 4 + declared_length > len(data):
            return None

        record_start = offset + 4

        for skip in range(1, 5):
            payload_start = record_start + skip
            if payload_start + 4 > len(data):
                continue

            try:
                mti = data[payload_start:payload_start + 4].decode("cp037")
            except Exception:
                continue

            if mti not in VALID_MTI:
                continue

            search_start = max(
                record_start + declared_length,
                payload_start + 20,
            )
            search_end = min(record_start + 5000, len(data))

            for next_offset in range(search_start, search_end):
                if not self.is_valid_header(data, next_offset):
                    continue

                physical_length = next_offset - record_start
                payload = data[payload_start:next_offset]
                if not (20 <= len(payload) <= 5000):
                    continue

                cleaned, repairs = self._repair_payload(payload)
                return RawRecord(
                    offset=offset,
                    length=physical_length,
                    mti=mti,
                    payload=cleaned,
                    repairs=[
                        f"skipped-prefix-bytes-{skip}",
                        "recovered-length-from-next-header",
                        *repairs,
                    ],
                )

        return None

    # ------------------------------------------------------------------

    def is_valid_header(self, data, offset):
        if offset + 8 > len(data):
            return False

        length = int.from_bytes(
            data[offset:offset + 4],
            "big"
        )

        if length <= 0:
            return False

        if offset + 4 + length > len(data):
            return False

        mti, _ = self._classify_payload(
            data[offset + 4:offset + 4 + length]
        )

        return mti is not None

    # ------------------------------------------------------------------

    def find_next_record(self, data, current_offset, current_length):
        """Locate the next record after the current one."""
        expected = current_offset + 4 + current_length

        #
        # First try the obvious positions
        #
        for delta in (0, 2, -2, 1, -1, 3, -3, 4, -4):
            pos = expected + delta
            if pos < 0:
                continue
            if self.is_valid_header(data, pos):
                return pos
            length = int.from_bytes(data[pos:pos + 4], "big")
            if self._recover_shifted_record(data, pos, length) is not None:
                return pos

        #
        # Search ahead for candidates
        #
        end = min(expected + 4096, len(data))

        candidates = [
            pos
            for pos in range(expected, end)
            if self.is_valid_header(data, pos)
            or self._recover_shifted_record(
                data,
                pos,
                int.from_bytes(data[pos:pos + 4], "big"),
            ) is not None
        ]

        for pos in candidates:
            length = int.from_bytes(
                data[pos:pos + 4],
                "big"
            )
            next_expected = pos + 4 + length

            for delta in (0, 2, -2, 1, -1, 3, -3, 4, -4):
                nxt = next_expected + delta
                if nxt < 0:
                    continue
                if self.is_valid_header(data, nxt):
                    return pos

        return None
