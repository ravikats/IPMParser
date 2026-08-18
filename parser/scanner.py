"""
scanner.py

Mastercard IPM Scanner

Walks the file using the 4-byte big-endian length prefix of every
record and returns RawRecord objects.

The scanner contains narrowly-scoped recovery for known physical
record/MTI corruption and bitmap corruption caused by inserted 00 00
pairs.

Important bitmap rules:
    - Primary bitmap is exactly 8 bytes.
    - If bit 1 of the primary bitmap is set, exactly 8 more bytes
      belong to the secondary bitmap.
    - A normal 8-byte secondary bitmap is left untouched, including
      legitimate 00 00 bytes.
    - When bit 2 is set, DE2's EBCDIC LLVAR length validates the end of
      the complete bitmap.
    - If that boundary is invalid, an inserted 00 00 pair in the
      secondary bitmap may be repaired using the DE94/bit-71 structure
      of the Mastercard 1240 bitmap seen in the supplied files.
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

        Some IPM records contain inserted 0x00 / 0x0D bytes before or
        inside the four-byte EBCDIC MTI.  Do not rebuild the payload by
        blindly taking ``payload[8:]``: doing that can discard the first
        bytes of the bitmap when the corruption occurs before byte 8.

        Instead, locate the valid MTI within the first eight source bytes,
        remove only the inserted bytes belonging to the MTI, and preserve
        everything immediately after the actual MTI.  This keeps the
        bitmap and all following DE/PDS data byte-for-byte aligned.
        """
        if payload is None or len(payload) < 4:
            return None, None

        # Normal record: MTI is already in the first four bytes.
        try:
            mti = payload[:4].decode("cp037")
        except Exception:
            mti = ""

        if mti in VALID_MTI:
            return mti, payload

        # Corruption is restricted to the first eight bytes.  Remove only
        # 00/0D bytes while looking for the first four EBCDIC MTI bytes.
        # The last selected source byte tells us exactly where the MTI ends;
        # the remainder must start immediately after that byte.
        scan_end = min(8, len(payload))
        source = payload[:scan_end]
        selected = []

        for index, byte in enumerate(source):
            if byte in (0x00, 0x0D):
                continue

            selected.append(index)
            if len(selected) == 4:
                break

        if len(selected) != 4:
            return None, None

        try:
            mti = bytes(source[i] for i in selected).decode("cp037")
        except Exception:
            return None, None

        if mti not in VALID_MTI:
            return None, None

        # Rebuild using only the actual MTI source span.  Any inserted
        # bytes before/inside the MTI are removed; bitmap starts exactly
        # after the fourth real MTI byte.
        mti_end = selected[-1] + 1
        cleaned = (
            mti.encode("cp037")
            + payload[mti_end:]
        )

        return mti, cleaned

    # ------------------------------------------------------------------

    @staticmethod
    def _is_ebcdic_numeric(data):
        """True when every byte is an EBCDIC digit F0-F9."""
        return (
            len(data) > 0
            and all(0xF0 <= b <= 0xF9 for b in data)
        )

    # ------------------------------------------------------------------

    @staticmethod
    def _bitmap_candidate_valid(payload, primary, consumed):
        """
        Validate a candidate reconstructed primary bitmap.

        ``consumed`` is the number of source bytes consumed after the MTI
        while reconstructing the primary bitmap.

        Returns:
            (valid, bitmap_len, secondary)
        """
        MTI_LEN = 4
        PRIMARY_LEN = 8

        if len(primary) != PRIMARY_LEN:
            return False, 0, b""

        # Bit 1 of the first primary bitmap byte indicates secondary.
        has_secondary = bool(primary[0] & 0x80)

        # Bit 2 indicates DE2.
        has_de2 = bool(primary[0] & 0x40)

        bitmap_len = 16 if has_secondary else 8

        # The source bytes immediately after the reconstructed primary
        # are the secondary bitmap, if present.
        secondary = b""
        if has_secondary:
            sec_start = MTI_LEN + consumed
            sec_end = sec_start + 8

            if sec_end > len(payload):
                return False, 0, b""

            secondary = payload[sec_start:sec_end]

        # After the complete bitmap, DE2 starts here.
        de2_start = (
            MTI_LEN
            + consumed
            + (8 if has_secondary else 0)
        )

        if has_de2:
            # DE2 is LLVAR in these records. Its two-byte EBCDIC
            # length must be numeric. This is our strong boundary check.
            if de2_start + 2 > len(payload):
                return False, 0, b""

            if not Scanner._is_ebcdic_numeric(
                payload[de2_start:de2_start + 2]
            ):
                return False, 0, b""

        return True, bitmap_len, secondary

    # ------------------------------------------------------------------

    @staticmethod
    def _generate_primary_candidates(payload, max_removed_pairs=4):
        """
        Generate possible 8-byte primary bitmaps by optionally removing
        00 00 pairs.

        Only the PRIMARY bitmap is reconstructed. Once 8 bitmap bytes
        have been produced, scanning stops. Therefore 00 00 values in
        the secondary bitmap are never considered repair candidates.

        Yields:
            (primary_bytes, consumed_source_bytes, removed_positions)

        ``removed_positions`` are positions within the original primary
        scan where a 00 00 pair was removed.
        """
        start = 4
        primary_len = 8

        results = []
        seen = set()

        def walk(index, out, removed, depth):
            if len(out) == primary_len:
                key = (bytes(out), index, tuple(removed))
                if key not in seen:
                    seen.add(key)
                    results.append(
                        (bytes(out), index - start, tuple(removed))
                    )
                return

            # We only need a small prefix of the source. The maximum
            # supported repair is intentionally bounded.
            if index >= len(payload):
                return

            # Keep the current byte.
            walk(
                index + 1,
                out + bytes([payload[index]]),
                removed,
                depth
            )

            # Or remove an inserted 00 00 pair.
            if (
                depth < max_removed_pairs
                and index + 1 < len(payload)
                and payload[index:index + 2] == b"\x00\x00"
            ):
                walk(
                    index + 2,
                    out,
                    removed + (index - start,),
                    depth + 1
                )

        walk(start, bytearray(), tuple(), 0)
        return results

    # ------------------------------------------------------------------

    @staticmethod
    def _generate_secondary_candidates(payload, primary_consumed=8, max_removed_pairs=4):
        """Generate candidate 8-byte secondary bitmaps by removing inserted
        00 00 pairs. Candidates are accepted only when DE2's EBCDIC LLVAR
        length is valid immediately after the reconstructed bitmap.
        """
        MTI_LEN = 4
        SECONDARY_LEN = 8
        start = MTI_LEN + primary_consumed

        results = []
        seen = set()

        def de2_valid(consumed):
            de2_start = start + consumed
            if de2_start + 2 > len(payload):
                return False
            return Scanner._is_ebcdic_numeric(
                payload[de2_start:de2_start + 2]
            )

        max_source = start + SECONDARY_LEN + (2 * max_removed_pairs)

        def walk(index, out, removed, depth):
            if index > max_source:
                return

            if len(out) == SECONDARY_LEN:
                consumed = index - start
                if not de2_valid(consumed):
                    return

                # If an inserted pair sits inside an existing run of
                # identical 00 bytes, there can be multiple equivalent
                # deletion positions that produce the exact same repaired
                # bitmap. Those are not genuinely different repairs.
                key = (bytes(out), consumed)
                if key not in seen:
                    seen.add(key)
                    results.append(
                        (bytes(out), consumed, tuple(removed))
                    )
                return

            if index >= len(payload) or index >= max_source:
                return

            # Keep this byte.
            walk(
                index + 1,
                out + bytes([payload[index]]),
                removed,
                depth,
            )

            # Or remove an inserted NULL pair.
            if (
                depth < max_removed_pairs
                and index + 1 < len(payload)
                and payload[index:index + 2] == b"\x00\x00"
            ):
                walk(
                    index + 2,
                    out,
                    removed + (index - start,),
                    depth + 1,
                )

        walk(start, bytearray(), tuple(), 0)
        return results

    # ------------------------------------------------------------------

    @staticmethod
    def _repair_payload(payload):
        """Repair known IPM bitmap corruption.

        Rules:
          * Primary bitmap = exactly 8 bytes.
          * Primary bit 1 => secondary bitmap exists and is exactly 8 bytes.
          * Primary bit 2 => DE2 is present; its EBCDIC LLVAR length is used
            to validate where the complete bitmap ends.
          * If the normal secondary boundary produces a valid DE2 length,
            the secondary bitmap is left completely untouched, including any
            legitimate 00 00 bytes.
          * If the normal secondary boundary is invalid, inserted 00 00 pairs
            inside the secondary bitmap are considered. A repair is applied
            only when there is a unique valid reconstruction.
          * No record offset or specific bitmap byte values are hard-coded.

        Existing MTI/bitmap-prefix exceptions are retained.
        """
        repairs = []

        if payload is None:
            return payload, repairs

        MTI_LEN = 4
        PRIMARY_LEN = 8
        SECONDARY_LEN = 8
        NULL_PAIR = b"\x00\x00"

        if len(payload) < MTI_LEN + PRIMARY_LEN:
            return payload, repairs

        p = payload

        # --------------------------------------------------------------
        # Existing exception: F0 10 missing immediately before bitmap.
        # --------------------------------------------------------------
        if p[4:8] == b"\x07\xc3\x8d\xe1":
            p = p[:4] + b"\xf0\x10" + p[4:]
            repairs.append("missing-bitmap-f010")
            return p, repairs

        # --------------------------------------------------------------
        # Existing exception: 00 00 inserted before F0 10.
        # --------------------------------------------------------------
        if p[4:6] == NULL_PAIR and p[6:8] == b"\xf0\x10":
            p = p[:4] + p[6:]
            repairs.append("nulls-before-bitmap")
            return p, repairs

        # --------------------------------------------------------------
        # Determine the primary bitmap from its fixed 8-byte position.
        # A primary bitmap by itself does not tell us whether its contents
        # are corrupt; bit 1/bit 2 are used to establish what follows it.
        # --------------------------------------------------------------
        primary = p[4:12]
        has_secondary = bool(primary[0] & 0x80)
        has_de2 = bool(primary[0] & 0x40)

        # --------------------------------------------------------------
        # If there is a secondary bitmap and DE2 is present, first check
        # the normal 8-byte secondary boundary. If DE2 is valid there,
        # everything is already aligned and we must not touch any 00 00
        # inside either bitmap.
        # --------------------------------------------------------------
        if has_secondary and has_de2:
            normal_sec_end = 4 + 8 + 8
            if (
                normal_sec_end + 2 <= len(p)
                and Scanner._is_ebcdic_numeric(
                    p[normal_sec_end:normal_sec_end + 2]
                )
            ):
                return p, repairs

            # The primary itself may be corrupted. Try repairing it first.
            # A valid primary reconstruction must restore a valid DE2
            # boundary after the secondary bitmap.
            primary_candidates = []
            for candidate_primary, consumed, removed in (
                Scanner._generate_primary_candidates(p)
            ):
                if consumed == 8 and not removed:
                    continue

                valid, _, _ = Scanner._bitmap_candidate_valid(
                    p, candidate_primary, consumed
                )
                if valid:
                    primary_candidates.append(
                        (candidate_primary, consumed, removed)
                    )

            if len(primary_candidates) == 1:
                candidate_primary, consumed, removed = primary_candidates[0]
                remainder_start = 4 + consumed
                p = (
                    p[:4]
                    + candidate_primary
                    + p[remainder_start:]
                )
                positions = ",".join(str(x) for x in removed)
                repairs.append(
                    f"nulls-in-primary-bitmap-at:{positions}"
                )
                return p, repairs

            # ----------------------------------------------------------
            # Primary is not the problem (or no primary candidate was
            # uniquely valid). Now repair the SECONDARY bitmap. This is
            # the case where exactly 00 00 bytes were inserted inside the
            # secondary bitmap, pushing DE2 to the right.
            # ----------------------------------------------------------
            candidates = Scanner._generate_secondary_candidates(
                p,
                primary_consumed=8,
                max_removed_pairs=1,
            )

            # For these Mastercard 1240 records, DE94 (bit 94) is the
            # discriminator for the intended secondary bitmap.
            de94_candidates = [
                c for c in candidates
                if (c[0][3] & 0x04)
            ]
            if de94_candidates:
                candidates = de94_candidates

            # In these 1240 records, bit 71 is also set. Use it as a
            # tie-breaker for runs of 00 bytes where more than one removal
            # position can otherwise appear structurally valid.
            bit71_candidates = [
                c for c in candidates
                if (c[0][0] & 0x02)
            ]
            if bit71_candidates:
                candidates = bit71_candidates

            if len(candidates) == 1:
                candidate_secondary, consumed, removed = candidates[0]
                sec_start = 4 + 8
                remainder_start = sec_start + consumed
                p = (
                    p[:sec_start]
                    + candidate_secondary
                    + p[remainder_start:]
                )
                positions = ",".join(str(x) for x in removed)
                repairs.append(
                    f"nulls-in-secondary-bitmap-at:{positions}"
                )
            elif len(candidates) > 1:
                repairs.append("secondary-bitmap-repair-ambiguous")

            return p, repairs

        # --------------------------------------------------------------
        # No secondary bitmap.
        # If DE2 is present, validate its normal boundary. If it is not
        # numeric we can try the existing primary repair logic.
        # --------------------------------------------------------------
        if not has_secondary:
            if (
                not has_de2
                or (
                    12 + 2 <= len(p)
                    and Scanner._is_ebcdic_numeric(p[12:14])
                )
            ):
                return p, repairs

        # --------------------------------------------------------------
        # Primary bitmap repair for cases where the normal primary
        # interpretation is not structurally valid.
        # --------------------------------------------------------------
        candidates = []
        for candidate_primary, consumed, removed in (
            Scanner._generate_primary_candidates(p)
        ):
            if consumed == 8 and not removed:
                continue

            valid, _, _ = Scanner._bitmap_candidate_valid(
                p, candidate_primary, consumed
            )
            if valid:
                candidates.append(
                    (candidate_primary, consumed, removed)
                )

        if len(candidates) == 1:
            candidate_primary, consumed, removed = candidates[0]
            remainder_start = 4 + consumed
            p = (
                p[:4]
                + candidate_primary
                + p[remainder_start:]
            )
            positions = ",".join(str(x) for x in removed)
            repairs.append(
                f"nulls-in-primary-bitmap-at:{positions}"
            )
        elif len(candidates) > 1:
            repairs.append("bitmap-repair-ambiguous")

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
            recovered = self._recover_shifted_record(
                data,
                offset,
                length
            )
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
                mti = data[
                    payload_start:payload_start + 4
                ].decode("cp037")
            except Exception:
                continue

            if mti not in VALID_MTI:
                continue

            search_start = max(
                record_start + declared_length,
                payload_start + 20,
            )

            search_end = min(
                record_start + 5000,
                len(data)
            )

            for next_offset in range(
                search_start,
                search_end
            ):
                if not self.is_valid_header(
                    data,
                    next_offset
                ):
                    continue

                physical_length = (
                    next_offset - record_start
                )

                payload = data[
                    payload_start:next_offset
                ]

                if not (20 <= len(payload) <= 5000):
                    continue

                cleaned, repairs = self._repair_payload(
                    payload
                )

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

        # First try the obvious positions.
        for delta in (0, 2, -2, 1, -1, 3, -3, 4, -4):
            pos = expected + delta

            if pos < 0:
                continue

            if self.is_valid_header(data, pos):
                return pos

            if pos + 4 <= len(data):
                length = int.from_bytes(
                    data[pos:pos + 4],
                    "big"
                )

                if self._recover_shifted_record(
                    data,
                    pos,
                    length
                ) is not None:
                    return pos

        # Search ahead for candidates.
        end = min(
            expected + 4096,
            len(data)
        )

        candidates = [
            pos
            for pos in range(expected, end)
            if (
                self.is_valid_header(data, pos)
                or (
                    pos + 4 <= len(data)
                    and self._recover_shifted_record(
                        data,
                        pos,
                        int.from_bytes(
                            data[pos:pos + 4],
                            "big"
                        )
                    ) is not None
                )
            )
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
