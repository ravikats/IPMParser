"""
IPM validator.

Validates physical records, MTI/bitmap structure, DE metadata coverage,
field lengths, simple field content, and DE48 PDS structure.
"""

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any


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
    "1742",
    "1743",
}


@dataclass
class ValidationIssue:
    severity: str
    code: str
    message: str
    record_no: int | None = None
    record_offset: int | None = None
    payload_pos: int | None = None
    de: int | None = None
    pds: str | None = None


@dataclass
class FieldValidation:
    de: int
    name: str
    start: int
    end: int
    value: str


@dataclass
class RecordValidation:
    record_no: int
    offset: int
    length: int
    mti: str
    bitmap: str
    present_des: list[int]
    fields: list[FieldValidation] = field(default_factory=list)
    issues: list[ValidationIssue] = field(default_factory=list)


@dataclass
class ValidationResult:
    filename: str
    file_size: int
    records: list[RecordValidation] = field(default_factory=list)
    issues: list[ValidationIssue] = field(default_factory=list)

    @property
    def errors(self):
        return [issue for issue in self.all_issues() if issue.severity == "ERROR"]

    @property
    def warnings(self):
        return [issue for issue in self.all_issues() if issue.severity == "WARN"]

    def all_issues(self):
        issues = list(self.issues)
        for record in self.records:
            issues.extend(record.issues)
        return issues

    def ok(self):
        return not self.errors


class QuietReader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def tell(self):
        return self.pos

    def remaining(self):
        return len(self.data) - self.pos

    def read_bytes(self, length: int):
        if length < 0:
            raise ValueError("Negative read length")
        raw = self.data[self.pos:self.pos + length]
        self.pos += len(raw)
        return raw

    def read_ebcdic(self, length: int):
        collected = bytearray()

        while len(collected) < length:
            if self.remaining() <= 0:
                break

            b = self.read_bytes(1)
            if b == b"\x00":
                continue
            collected.extend(b)

        return bytes(collected).decode("cp037")


class IPMValidator:
    def __init__(self, de_metadata_path="metadata/de.json", pds_metadata_path="metadata/pds.json"):
        self.de_metadata = self._load_json(de_metadata_path)
        self.pds_metadata = self._load_json(pds_metadata_path)

    def validate_file(self, filename: str | Path):
        path = Path(filename)
        data = path.read_bytes()
        result = ValidationResult(str(path), len(data))

        offset = 0
        record_no = 1

        while offset < len(data):
            if self._is_padding(data[offset:]):
                break

            if offset + 8 > len(data):
                result.issues.append(
                    self._issue("ERROR", "TRAILING_BYTES", "Trailing bytes do not contain a full record header", record_offset=offset)
                )
                break

            length = int.from_bytes(data[offset:offset + 4], "big")
            header_issue = self._validate_record_header(data, offset, length)

            if header_issue:
                result.issues.append(header_issue)
                next_offset = self._find_next_header(data, offset + 1)
                if next_offset is None:
                    break
                offset = next_offset
                continue

            payload = data[offset + 4:offset + 4 + length]
            record = self._validate_payload(record_no, offset, length, payload)
            result.records.append(record)

            offset += 4 + length
            if (
                offset + 10 <= len(data)
                and self._validate_record_header(data, offset, int.from_bytes(data[offset:offset + 4], "big")) is not None
                and self._validate_record_header(data, offset + 2, int.from_bytes(data[offset + 2:offset + 6], "big")) is None
            ):
                offset += 2
            record_no += 1

        return result

    def _validate_payload(self, record_no: int, offset: int, length: int, payload: bytes):
        reader = QuietReader(payload)
        issues: list[ValidationIssue] = []

        try:
            mti = reader.read_ebcdic(4)
        except UnicodeError:
            mti = "????"
            issues.append(self._record_issue("ERROR", "BAD_MTI_ENCODING", "MTI is not valid EBCDIC", record_no, offset, 0))

        bitmap_start = reader.tell()
        primary = reader.read_bytes(8)
        secondary = b""

        if len(primary) != 8:
            issues.append(self._record_issue("ERROR", "MISSING_BITMAP", "Primary bitmap is incomplete", record_no, offset, bitmap_start))
            return RecordValidation(record_no, offset, length, mti, primary.hex().upper(), [], issues=issues)

        if primary[0] & 0x80 and mti != "1644":
            secondary = reader.read_bytes(8)
            if len(secondary) != 8:
                issues.append(self._record_issue("ERROR", "MISSING_SECONDARY_BITMAP", "Secondary bitmap is incomplete", record_no, offset, reader.tell()))

        bitmap = primary + secondary
        present_des = self._present_des(bitmap)

        if 1 in present_des and not secondary and mti != "1644":
            issues.append(self._record_issue("ERROR", "BITMAP_MISMATCH", "DE1 is present but secondary bitmap was not read", record_no, offset, bitmap_start))

        if mti == "1644":
            header_start = reader.tell()
            binary_header = reader.read_bytes(8)
            if len(binary_header) != 8:
                issues.append(self._record_issue("ERROR", "MISSING_BINARY_HEADER", "1644 binary header is incomplete", record_no, offset, header_start))
            return self._validate_1644(record_no, offset, length, mti, bitmap, present_des, reader, issues)

        fields: list[FieldValidation] = []

        for de in present_des:
            if de == 1:
                continue

            meta = self.de_metadata.get(str(de))
            if meta is None:
                issues.append(self._record_issue("ERROR", "MISSING_DE_METADATA", f"DE{de:03d} is present but metadata is missing", record_no, offset, reader.tell(), de=de))
                break

            start = reader.tell()
            value = self._read_field(reader, meta, issues, record_no, offset, de)
            end = reader.tell()
            fields.append(FieldValidation(de, meta.get("name", ""), start, end, value))

            if value is not None:
                self._validate_field_value(value, meta, issues, record_no, offset, start, de)
                if de == 48:
                    self._validate_pds(value, issues, record_no, offset, start)

        if reader.tell() < len(payload):
            issues.append(
                self._record_issue(
                    "WARN",
                    "UNCONSUMED_BYTES",
                    f"{len(payload) - reader.tell()} payload bytes were not consumed",
                    record_no,
                    offset,
                    reader.tell(),
                )
            )
        elif reader.tell() > len(payload):
            issues.append(
                self._record_issue("ERROR", "OVERREAD_PAYLOAD", "Parser read past the end of the payload", record_no, offset, reader.tell())
            )

        return RecordValidation(record_no, offset, length, mti, bitmap.hex().upper(), present_des, fields, issues)

    def _validate_1644(self, record_no, offset, length, mti, bitmap, present_des, reader, issues):
        fields: list[FieldValidation] = []

        for de in (24, 48, 71):
            meta = self.de_metadata.get(str(de))
            if meta is None:
                issues.append(self._record_issue("ERROR", "MISSING_DE_METADATA", f"DE{de:03d} is required for 1644 but metadata is missing", record_no, offset, reader.tell(), de=de))
                break

            start = reader.tell()
            value = self._read_field(reader, meta, issues, record_no, offset, de)
            end = reader.tell()
            fields.append(FieldValidation(de, meta.get("name", ""), start, end, value))

            if value is not None:
                self._validate_field_value(value, meta, issues, record_no, offset, start, de)
                if de == 48:
                    self._validate_pds(value, issues, record_no, offset, start)

        if reader.tell() < len(reader.data):
            issues.append(
                self._record_issue(
                    "WARN",
                    "UNCONSUMED_BYTES",
                    f"{len(reader.data) - reader.tell()} payload bytes were not consumed",
                    record_no,
                    offset,
                    reader.tell(),
                )
            )

        return RecordValidation(record_no, offset, length, mti, bitmap.hex().upper(), present_des, fields, issues)

    def _read_field(self, reader, meta, issues, record_no, offset, de):
        fmt = meta.get("format", "").upper()
        ftype = meta.get("type", "").lower()

        try:
            if fmt == "FIXED":
                length = int(meta["length"])
                return self._read_value(reader, length, ftype)

            if fmt == "LLVAR":
                return self._read_var(reader, 2, meta, issues, record_no, offset, de)

            if fmt == "LLLVAR":
                return self._read_var(reader, 3, meta, issues, record_no, offset, de)

            if fmt == "BINARY":
                return reader.read_bytes(int(meta["length"])).hex().upper()

            issues.append(self._record_issue("ERROR", "UNSUPPORTED_FORMAT", f"DE{de:03d} has unsupported format {fmt}", record_no, offset, reader.tell(), de=de))
            return None
        except (UnicodeError, ValueError, KeyError) as ex:
            issues.append(self._record_issue("ERROR", "FIELD_READ_FAILED", f"DE{de:03d} could not be read: {ex}", record_no, offset, reader.tell(), de=de))
            return None

    def _read_var(self, reader, prefix_len, meta, issues, record_no, offset, de):
        prefix_pos = reader.tell()
        prefix = reader.read_ebcdic(prefix_len)
        if not prefix.isdigit():
            issues.append(self._record_issue("ERROR", "BAD_LENGTH_PREFIX", f"DE{de:03d} length prefix is not numeric: {prefix!r}", record_no, offset, prefix_pos, de=de))
            return None

        length = int(prefix)
        max_length = int(meta.get("max_length", length))
        if length > max_length:
            issues.append(self._record_issue("ERROR", "FIELD_TOO_LONG", f"DE{de:03d} length {length} exceeds max {max_length}", record_no, offset, prefix_pos, de=de))

        return self._read_value(reader, length, meta.get("type", "").lower())

    def _read_value(self, reader, length, ftype):
        if ftype == "b":
            if reader.remaining() < length:
                raise ValueError(f"need {length} bytes, only {reader.remaining()} remain")
            raw = reader.read_bytes(length)
            return raw.hex().upper()

        return reader.read_ebcdic(length)

    def _validate_field_value(self, value, meta, issues, record_no, offset, payload_pos, de):
        ftype = meta.get("type", "").lower()
        if value is None or ftype == "b":
            return

        if ftype == "n" and not value.isdigit():
            issues.append(self._record_issue("ERROR", "INVALID_NUMERIC", f"DE{de:03d} should be numeric but contains {value!r}", record_no, offset, payload_pos, de=de))
        elif ftype in {"an", "ans"} and any(ord(ch) < 32 for ch in value):
            issues.append(self._record_issue("WARN", "CONTROL_CHARACTER", f"DE{de:03d} contains a control character", record_no, offset, payload_pos, de=de))

    def _validate_pds(self, value, issues, record_no, offset, de48_start):
        pos = 0
        while pos < len(value):
            pds_start = de48_start + pos
            if pos + 7 > len(value):
                issues.append(self._record_issue("ERROR", "PDS_TRUNCATED_HEADER", "DE48 ends inside a PDS header", record_no, offset, pds_start, de=48))
                return

            pds_id = value[pos:pos + 4]
            pds_len_text = value[pos + 4:pos + 7]

            if not pds_id.isdigit():
                issues.append(self._record_issue("ERROR", "BAD_PDS_ID", f"PDS id is not numeric: {pds_id!r}", record_no, offset, pds_start, de=48, pds=pds_id))

            if not pds_len_text.isdigit():
                issues.append(self._record_issue("ERROR", "BAD_PDS_LENGTH", f"PDS {pds_id} length is not numeric: {pds_len_text!r}", record_no, offset, pds_start + 4, de=48, pds=pds_id))
                return

            pds_length = int(pds_len_text)
            value_start = pos + 7
            value_end = value_start + pds_length

            if value_end > len(value):
                issues.append(self._record_issue("ERROR", "PDS_LENGTH_OVERFLOW", f"PDS {pds_id} length {pds_length} exceeds remaining DE48 data", record_no, offset, pds_start, de=48, pds=pds_id))
                return

            if pds_id not in self.pds_metadata:
                issues.append(self._record_issue("WARN", "UNKNOWN_PDS", f"PDS {pds_id} is not in metadata", record_no, offset, pds_start, de=48, pds=pds_id))

            pos = value_end

    def _validate_record_header(self, data, offset, length):
        if data[offset:offset + 2] == b"\xF4\xF0":
            return self._issue("WARN", "RECORD_SEPARATOR", "Record separator found", record_offset=offset)

        if length < 20:
            return self._issue("ERROR", "BAD_RECORD_LENGTH", f"Record length {length} is too small", record_offset=offset)
        if length > 5000:
            return self._issue("ERROR", "BAD_RECORD_LENGTH", f"Record length {length} is too large", record_offset=offset)
        if offset + 4 + length > len(data):
            return self._issue("ERROR", "RECORD_OVERRUN", f"Record length {length} runs past end of file", record_offset=offset)

        try:
            mti = data[offset + 4:offset + 8].decode("cp037")
        except UnicodeError:
            return self._issue("ERROR", "BAD_MTI_ENCODING", "Record MTI is not valid EBCDIC", record_offset=offset)

        if mti not in VALID_MTI:
            return self._issue("ERROR", "UNKNOWN_MTI", f"Unknown MTI {mti!r}", record_offset=offset)

        return None

    def _find_next_header(self, data, start):
        for pos in range(start, len(data) - 8):
            length = int.from_bytes(data[pos:pos + 4], "big")
            if self._validate_record_header(data, pos, length) is None:
                return pos
        return None

    def _present_des(self, bitmap):
        des = []
        bitno = 1
        for b in bitmap:
            for i in range(8):
                if b & (1 << (7 - i)):
                    des.append(bitno)
                bitno += 1
        return des

    def _is_padding(self, data):
        return bool(data) and all(b in (0x00, 0x40) for b in data)

    def _load_json(self, filename):
        with open(filename, encoding="utf8") as f:
            return json.load(f)

    def _issue(self, severity, code, message, record_no=None, record_offset=None, payload_pos=None, de=None, pds=None):
        return ValidationIssue(severity, code, message, record_no, record_offset, payload_pos, de, pds)

    def _record_issue(self, severity, code, message, record_no, record_offset, payload_pos=None, de=None, pds=None):
        return self._issue(severity, code, message, record_no, record_offset, payload_pos, de, pds)


def result_to_dict(result: ValidationResult) -> dict[str, Any]:
    def issue_to_dict(issue):
        return {
            "severity": issue.severity,
            "code": issue.code,
            "message": issue.message,
            "record_no": issue.record_no,
            "record_offset": issue.record_offset,
            "payload_pos": issue.payload_pos,
            "de": issue.de,
            "pds": issue.pds,
        }

    return {
        "filename": result.filename,
        "file_size": result.file_size,
        "ok": result.ok(),
        "record_count": len(result.records),
        "error_count": len(result.errors),
        "warning_count": len(result.warnings),
        "issues": [issue_to_dict(issue) for issue in result.all_issues()],
        "records": [
            {
                "record_no": record.record_no,
                "offset": record.offset,
                "length": record.length,
                "mti": record.mti,
                "bitmap": record.bitmap,
                "present_des": record.present_des,
                "issue_count": len(record.issues),
            }
            for record in result.records
        ],
    }
