"""
reader.py

Low-level IPM file reader.

Responsibilities:
    - Open binary IPM file
    - Read record boundaries
    - Return raw records
    - No field decoding
"""

from dataclasses import dataclass
from pathlib import Path
from typing import List


@dataclass
class RawRecord:
    offset: int
    length: int
    record_type: str
    data: bytes


class IPMReader:

    def __init__(self, filename: str):
        self.filename = filename

    def read(self) -> List[RawRecord]:

        with open(self.filename, "rb") as f:
            data = f.read()

        cursor = 0
        records = []

        while cursor + 6 <= len(data):

            start = cursor

            # First two bytes are record length (big-endian)
            length = int.from_bytes(
                data[cursor:cursor + 2],
                byteorder="big"
            )

            if length <= 0:
                break

            cursor += 2

            if cursor + length > len(data):
                break

            record = data[cursor:cursor + length]

            # Record type is first four EBCDIC characters
            try:
                record_type = record[:4].decode("cp037")
            except Exception:
                record_type = "????"

            records.append(
                RawRecord(
                    offset=start,
                    length=length,
                    record_type=record_type,
                    data=record,
                )
            )

            cursor += length

        return records