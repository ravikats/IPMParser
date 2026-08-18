"""
test.py

Mastercard IPM file parser.

Reads an IPM file, parses every physical record, and writes one JSON
object per record to stdout (JSON Lines format), suitable for
downstream analysis.

Usage:
    python test.py <ipm-file> > records.jsonl
"""

import csv
import json
import sys

from parser.bitmap import Bitmap
from parser.cleanup import PayloadCleaner
from parser.compliance import RulesEngine
from parser.de_reader import DEReader
from parser.field_reader import FieldReader
from parser.pds import PDSParser
from parser.scanner import Scanner


def load_metadata(metadata_dir="metadata"):
    with open(f"{metadata_dir}/de.json", encoding="utf8") as f:
        de_metadata = json.load(f)
    with open(f"{metadata_dir}/pds.json", encoding="utf8") as f:
        pds_metadata = json.load(f)
    return de_metadata, pds_metadata


def pds_to_dict(pds_list, pds_metadata):
    """Convert parsed PDS objects to ``{id: {name, value}}`` dicts."""
    result = {}
    for p in pds_list:
        meta = pds_metadata.get(p.id)
        name = meta.get("name", "") if isinstance(meta, dict) else (meta or "")
        result[p.id] = {"name": name, "value": p.value}
    return result


def parse_1240(payload, de_metadata, pds_parser):
    reader = DEReader(PayloadCleaner(payload).payload())
    reader.read_ebcdic(4)
    bitmap = Bitmap.from_reader(reader)

    fields = {}
    errors = []

    for de in bitmap.present_des():
        if de == 1:
            continue
        field = de_metadata.get(str(de))
        if field is None:
            continue
        try:
            fields[str(de)] = FieldReader.read(reader, field)
        except Exception as ex:
            errors.append(f"DE{de:03d}: {ex}")
            break

    return {
        "bitmap": bitmap.present_des(),
        "fields": fields,
        "errors": errors,
        "consumed": reader.tell(),
        "payload_length": len(payload),
    }


def parse_1644(payload, pds_parser):
    reader = DEReader(PayloadCleaner(payload).payload())
    reader.read_ebcdic(4)
    reader.read_bitmap()
    reader.read_bytes(8)            # binary header
    function = reader.read_ebcdic(3)
    de48_len = int(reader.read_length(3))
    de48 = reader.read_ebcdic(de48_len)
    message_number = reader.read_ebcdic(8)

    return {
        "function": function,
        "message_number": message_number,
        "de48": de48,
    }


def process_file(filename, de_metadata, pds_metadata, pds_parser, compliance):
    """Parse every record in ``filename`` and evaluate compliance rules.

    Returns ``(results, file_violations)`` where ``results`` is a list of
    per-record dicts and ``file_violations`` the file-level compliance
    violations (as ComplianceViolation objects).
    """
    results = []

    for rec_no, rec in enumerate(Scanner(verbose=False).scan(filename), start=1):

        result = {
            "record": rec_no,
            "offset": rec.offset,
            "length": rec.length,
            "mti": rec.mti,
        }
        if rec.repairs:
            result["repaired"] = rec.repairs

        try:
            if rec.mti == "1644":
                parsed = parse_1644(rec.payload, pds_parser)
                result.update(parsed)
                result["pds"] = pds_to_dict(
                    pds_parser.parse(parsed["de48"]),
                    pds_metadata,
                )
            else:
                parsed = parse_1240(rec.payload, de_metadata, pds_parser)

                if rec.trailing:
                    extended = parse_1240(
                        rec.payload + rec.trailing,
                        de_metadata,
                        pds_parser,
                    )
                    if (
                        not extended["errors"]
                        and extended["consumed"] == len(rec.payload + rec.trailing)
                    ):
                        parsed = extended
                        result["repaired"] = [
                            *rec.repairs,
                            f"extended-by-{len(rec.trailing)}",
                        ]

                result.update(parsed)
                result["complete"] = (
                    parsed["consumed"] == parsed["payload_length"]
                )
                result["remaining"] = (
                    parsed["payload_length"] - parsed["consumed"]
                )
                if result["remaining"] > 0:
                    result["trailing_hex"] = (
                        rec.payload[parsed["consumed"]:
                                    parsed["consumed"] + 64].hex(" ")
                    )

                de48 = parsed["fields"].get("48")
                if de48:
                    result["de48_pds"] = pds_to_dict(
                        pds_parser.parse(de48),
                        pds_metadata,
                    )
        except Exception as ex:
            result["errors"] = [f"record-level: {ex}"]

        violations = compliance.evaluate_record(result)
        if violations:
            result["compliance"] = [
                {
                    "rule_id": v.rule_id,
                    "severity": v.severity,
                    "message": v.message,
                }
                for v in violations
            ]

        results.append(result)

    file_violations = compliance.evaluate_file(results)
    if file_violations:
        results[-1]["file_compliance"] = [
            {
                "rule_id": v.rule_id,
                "severity": v.severity,
                "message": v.message,
            }
            for v in file_violations
        ]

    return results, file_violations


def write_csv(csv_file, results, compliance, file_violations):
    """Write one row per record with key fields and compliance results."""
    rule_ids = compliance.all_rule_ids
    header = ["record", "mti", "complete", "remaining"]
    header += [f"de{de}" for de in ("2", "3", "4", "12", "22", "23", "24",
                                     "25", "26", "37", "38", "40", "41", "42",
                                     "43", "48", "49", "54", "55", "63", "71",
                                     "94")]
    header.append("de70_0170")
    header += [f"rule:{rid}" for rid in rule_ids]
    header.append("errors")
    header.append("compliance")

    writer = csv.DictWriter(csv_file, fieldnames=header, extrasaction="ignore")
    writer.writeheader()

    file_map = {v.rule_id: v for v in file_violations}

    for result in results:
        fields = result.get("fields", {})
        row = {
            "record": result.get("record"),
            "mti": result.get("mti"),
            "complete": result.get("complete", ""),
            "remaining": result.get("remaining", ""),
        }
        for de in ("2", "3", "4", "12", "22", "23", "24", "25", "26", "37",
                   "38", "40", "41", "42", "43", "48", "49", "54", "55", "63",
                   "71", "94"):
            row[f"de{de}"] = fields.get(de, "")

        row["de70_0170"] = (
            result.get("de48_pds", {})
            .get("0170", {})
            .get("value", "")
        )

        compliance_map = {
            v["rule_id"]: v for v in result.get("compliance", [])
        }
        for rid in rule_ids:
            if rid in compliance_map:
                row[f"rule:{rid}"] = "FAIL"
            elif rid in file_map:
                row[f"rule:{rid}"] = "FAIL"
            else:
                row[f"rule:{rid}"] = "PASS"
        row["compliance"] = "|".join(
            v["message"] for v in result.get("compliance", [])
        )
        row["errors"] = "|".join(result.get("errors", []))
        if file_map and result.get("mti") in ("1644",):
            row["compliance"] = "|".join(
                f"{v.rule_id}: {v.message}" for v in file_violations
            )
        writer.writerow(row)

    for violation in file_violations:
        writer.writerow({
            "record": "",
            "mti": "FILE",
            "complete": "",
            "remaining": "",
            "compliance": f"{violation.rule_id}: {violation.message}",
        })


def main():
    if len(sys.argv) not in (2, 3, 4):
        print("usage: python test.py <ipm-file> [output.jsonl] [output.csv]", file=sys.stderr)
        sys.exit(2)

    filename = sys.argv[1]

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    jsonl_path = sys.argv[2] if len(sys.argv) >= 3 else None
    csv_path = sys.argv[3] if len(sys.argv) == 4 else None
    jsonl_file = open(jsonl_path, "w", encoding="utf-8") if jsonl_path else sys.stdout
    csv_file = open(csv_path, "w", encoding="utf-8", newline="") if csv_path else None

    de_metadata, pds_metadata = load_metadata()
    pds_parser = PDSParser()
    compliance = RulesEngine()

    results, file_violations = process_file(filename, de_metadata, pds_metadata, pds_parser, compliance)

    for result in results:
        jsonl_file.write(
            json.dumps(result, ensure_ascii=False, separators=(",", ":"))
            + "\n"
        )

    if jsonl_path:
        jsonl_file.close()

    if csv_file:
        write_csv(csv_file, results, compliance, file_violations)
        csv_file.close()


if __name__ == "__main__":
    main()
