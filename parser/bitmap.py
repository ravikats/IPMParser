"""
bitmap.py

ISO8583 / Mastercard IPM Bitmap Decoder

Supports:
    - Primary Bitmap (64 bits)
    - Secondary Bitmap (128 bits)
"""


class Bitmap:

    def __init__(self, primary: bytes, secondary: bytes = None):

        if len(primary) != 8:
            raise ValueError("Primary bitmap must be 8 bytes")

        self.primary = primary
        self.secondary = secondary

    # ------------------------------------------------------------------
    # Create from DEReader
    # ------------------------------------------------------------------

    @classmethod
    def from_reader(cls, reader):

        primary = reader.read_bytes(8)

        secondary = None

        #
        # Bit 1 indicates Secondary Bitmap
        #
        if primary[0] & 0x80:
            secondary = reader.read_bytes(8)

        return cls(primary, secondary)

    # ------------------------------------------------------------------

    def has_secondary(self):
        return self.secondary is not None

    def raw(self):
        if self.secondary:
            return self.primary + self.secondary
        return self.primary

    def hex(self):
        return self.raw().hex().upper()

    def primary_hex(self):
        return self.primary.hex().upper()

    def secondary_hex(self):
        if self.secondary:
            return self.secondary.hex().upper()
        return ""

    def binary(self):
        return "".join(format(b, "08b") for b in self.raw())

    def present_des(self):
        """Return the list of present data element numbers."""
        des = []
        bitno = 1
        for b in self.raw():
            for i in range(8):
                if b & (1 << (7 - i)):
                    des.append(bitno)
                bitno += 1
        return des

    def is_present(self, de):
        return de in self.present_des()
