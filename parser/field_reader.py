"""
field_reader.py

Reads any DE based on its metadata.

Supported formats:
    FIXED
    LLVAR
    LLLVAR
    BINARY
"""

from parser.de_reader import DEReader


class FieldReader:

    @staticmethod
    def read(reader: DEReader, field):
        fmt = field["format"].upper()
        ftype = field.get("type", "").lower()

        #
        # DE055 - ICC System Related Data (EMV TLV):
        # 3-digit EBCDIC length followed by raw binary TLV bytes
        #
        if ftype == "b" and fmt == "LLLVAR":
            length = int(reader.read_length(3))
            return reader.read_bytes(length).hex().upper()

        #
        # FIXED
        #
        if fmt == "FIXED":
            length = field["length"]
            if field.get("encoding", "EBCDIC") == "BINARY":
                return reader.read_bytes(length).hex().upper()
            return reader.read_ebcdic(length)

        #
        # LLVAR
        #
        if fmt == "LLVAR":
            return reader.read_llvar()

        #
        # LLLVAR
        #
        if fmt == "LLLVAR":
            return reader.read_lllvar()

        #
        # BINARY
        #
        if fmt == "BINARY":
            return reader.read_bytes(field["length"]).hex().upper()

        raise ValueError(f"unsupported format {fmt}")
