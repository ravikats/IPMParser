class PayloadCleaner:

    def __init__(self, payload: bytes):
        self.data = bytearray(payload)

    def remove_nulls(self, start: int, length: int):
        """Remove 0x00 bytes from a region of the payload."""
        field = self.data[start:start + length]
        cleaned = bytearray(b for b in field if b != 0x00)
        removed = len(field) - len(cleaned)
        self.data[start:start + length] = cleaned
        return removed

    def payload(self):
        return bytes(self.data)
