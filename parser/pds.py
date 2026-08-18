"""
pds.py

Generic Mastercard PDS Parser

Format

PPPP LLL DATA

PPPP = PDS ID (4)
LLL  = Length (3)
DATA = Variable
"""

from dataclasses import dataclass


@dataclass
class PDS:

    id: str
    length: int
    value: str


class PDSParser:

    def parse(self, text):
        pos = 0
        pds_list = []

        while pos < len(text):

            if pos + 7 > len(text):
                break

            pds_id = text[pos:pos + 4]

            try:
                length = int(text[pos + 4:pos + 7])
            except ValueError:
                break

            value = text[
                pos + 7:
                pos + 7 + length
            ]

            pds_list.append(
                PDS(
                    id=pds_id,
                    length=length,
                    value=value
                )
            )

            pos += 7 + length

        return pds_list
