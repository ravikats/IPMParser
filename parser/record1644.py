"""
record1644.py

Parser for 1644 Administrative Messages

Supports

697 File Header

695 File Trailer
"""

from parser.de_reader import DEReader
from parser.pds import PDSParser


class Record1644Parser:

    def __init__(self):

        self.pds = PDSParser()

    # --------------------------------------------------

    def parse(self, raw_record):

        reader = DEReader(raw_record.payload)

        rec = {}

        #
        # MTI
        #

        rec["mti"] = reader.read_ebcdic(4)

        #
        # Bitmap
        #

        rec["bitmap"] = reader.read_bitmap().hex().upper()

        #
        # Binary Header
        #

        rec["binary_header"] = reader.read_bytes(8).hex().upper()

        #
        # DE24
        #

        rec["de24"] = reader.read_ebcdic(3)

        #
        # DE48 Length
        #

        rec["de48_length"] = int(
            reader.read_ebcdic(3)
        )

        #
        # DE48
        #

        rec["de48"] = reader.read_ebcdic(
            rec["de48_length"]
        )

        #
        # Parse PDS
        #

        rec["pds"] = self.pds.parse(
            rec["de48"]
        )

        #
        # DE71
        #

        rec["de71"] = reader.read_ebcdic(8)

        return rec

    # --------------------------------------------------

    def dump(self, rec):

        print("=" * 80)

        print("1644 Administrative Message")

        print("=" * 80)

        print()

        print("MTI            :", rec["mti"])

        print("Bitmap         :", rec["bitmap"])

        print("Binary Header  :", rec["binary_header"])

        print("Function Code  :", rec["de24"])

        print("DE48 Length    :", rec["de48_length"])

        print("Message Number :", rec["de71"])

        print()

        print("DE48")

        print("-" * 80)

        print(rec["de48"])

        print()

        print("PDS")

        print("-" * 80)

        for p in rec["pds"]:

            print(
                f"{p.id}"
                f" ({p.length})"
            )

            print(p.value)

            print()