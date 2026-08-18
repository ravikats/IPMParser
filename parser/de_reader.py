"""
de_reader.py

Generic byte reader for Mastercard IPM records.

Reads binary payloads and decodes EBCDIC only when requested.
"""


class DEReader:
    """Positional reader over a binary record payload."""

    MAX_LENGTH_SKIP = 8

    def __init__(self, payload: bytes):
        self.data = payload
        self.pos = 0

    # ------------------------------------------------------------------
    # Position helpers
    # ------------------------------------------------------------------

    def tell(self):
        return self.pos

    def seek(self, pos):
        self.pos = pos

    def eof(self):
        return self.pos >= len(self.data)

    def remaining(self):
        return len(self.data) - self.pos

    # ------------------------------------------------------------------
    # Raw reads
    # ------------------------------------------------------------------

    def read_bytes(self, length):
        value = self.data[self.pos:self.pos + length]
        self.pos += length
        return value

    def read_uint(self, length):
        return int.from_bytes(self.read_bytes(length), "big")

    def peek(self, length):
        return self.data[self.pos:self.pos + length]

    def skip(self, length):
        self.pos += length

    def read_bitmap(self):
        return self.read_bytes(8)

    # ------------------------------------------------------------------
    # EBCDIC reads
    # ------------------------------------------------------------------

    def read_ebcdic(self, length):
        """Read ``length`` EBCDIC chars, skipping embedded 0x00 padding.

        Embedded nulls are treated as padding and skipped so the decoded
        string contains exactly ``length`` characters.
        """
        collected = bytearray()
        while len(collected) < length:
            if self.pos >= len(self.data):
                break
            b = self.read_bytes(1)
            if b == b"\x00":
                continue
            collected.extend(b)
        return collected.decode("cp037", errors="ignore")

    def read_length(self, digits):
        """Read an EBCDIC numeric length of ``digits`` characters.

        Tolerates stray bytes that appear inside / in front of length
        fields in some records:
            - EBCDIC control bytes (0x00-0x3F) such as the 0x10/0x00
              bytes that end up embedded at length boundaries when the
              DE055 EMV TLV is truncated
            - the 0xAA byte seen in a handful of records

        All skipped bytes are consumed along with the digits.
        """
        start = self.pos
        collected = []
        junk = 0
        pos = start
        data = self.data
        n = len(data)

        while len(collected) < digits and pos < n:
            b = data[pos]
            if 0xF0 <= b <= 0xF9:
                collected.append(b)
            elif b < 0x40 or b == 0xAA:
                junk += 1
                if junk > self.MAX_LENGTH_SKIP:
                    break
            else:
                break
            pos += 1

        if len(collected) == digits:
            self.pos = pos
            return bytes(collected).decode("cp037")

        raise ValueError(
            f"invalid {digits}-digit length at offset {start}"
        )

    def read_llvar(self):
        return self.read_ebcdic(int(self.read_length(2)))

    def read_lllvar(self):
        return self.read_ebcdic(int(self.read_length(3)))

    def read_fixed(self, length):
        return self.read_ebcdic(length)
