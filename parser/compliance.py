"""
Configurable compliance rule engine.

Rules are loaded from a JSON file and evaluated against parsed IPM
record dictionaries (as emitted by test.py).

Rule schema (see metadata/compliance_rules.json):

    {
      "rules": [
        {
          "id": "ACCEPTOR_CONTACT_REQUIRED",
          "description": "Human readable description",
          "severity": "ERROR" | "WARN",
          "type": "required" | "min_length" | "max_length"
                  | "subfield_min_length" | "subfield_max_length"
                  | "subelement_min_length" | "subelement_max_length",
          "path": "dotted.path.to.field",
          "mtis": ["1240"],        // optional: only evaluate for these MTIs
          "strip": true,           // optional: strip whitespace before checking
          "min": 6,                // required for min_length / subfield_min_length
          "max": 12,               // required for max_length / subfield_max_length
          "delimiter": "\\",       // required for subfield_*; split the value
          "subfield": 1            // required for subfield_*; 1-based index
        }
      ],
      "file_rules": [
        {
          "id": "FILE_TOTAL_COUNT",
          "description": "Human readable description",
          "severity": "ERROR" | "WARN",
          "type": "file_count",    // compares a footer value against a record count
          "footer_path": "pds.0306.value",
          "record_mti": "1240"     // optional: count only records with this MTI
        },
        {
          "id": "FILE_TOTAL_AMOUNT",
          "description": "Human readable description",
          "severity": "ERROR" | "WARN",
          "type": "file_amount",   // compares a footer value against a summed field
          "footer_path": "pds.0301.value",
          "field_path": "fields.4",
          "record_mti": "1240"     // optional: sum only records with this MTI
        }
      ]
    }
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any


@dataclass
class ComplianceViolation:
    rule_id: str
    severity: str
    message: str
    record_no: int
    mti: str


class RulesEngine:
    def __init__(self, rules_path="metadata/compliance_rules.json"):
        with open(rules_path, encoding="utf8") as f:
            config = json.load(f)
        self.rules = config.get("rules", [])
        self.file_rules = config.get("file_rules", [])

    @property
    def all_rule_ids(self):
        ids = [rule["id"] for rule in self.rules]
        ids += [rule["id"] for rule in self.file_rules]
        return ids

    def evaluate_record(self, record: dict[str, Any]) -> list[ComplianceViolation]:
        violations: list[ComplianceViolation] = []
        for rule in self.rules:
            mtis = rule.get("mtis")
            if mtis and record.get("mti") not in mtis:
                continue

            value = self._resolve(record, rule["path"])
            violation = self._check(rule, value)
            if violation is not None:
                violations.append(
                    ComplianceViolation(
                        rule_id=rule["id"],
                        severity=rule.get("severity", "ERROR"),
                        message=violation,
                        record_no=record.get("record"),
                        mti=record.get("mti"),
                    )
                )
        return violations

    def _resolve(self, record: dict, path: str) -> Any:
        node: Any = record
        for part in path.split("."):
            if not isinstance(node, dict) or part not in node:
                return None
            node = node[part]
        return node

    def _check(self, rule: dict, value: Any) -> str | None:
        rtype = rule["type"]

        if rtype == "required":
            if value is None or str(value).strip() == "":
                return f"{rule['description']} (field '{rule['path']}' is missing or empty)"
            return None

        if rtype == "min_length":
            if value is None:
                return None
            text = str(value).strip() if rule.get("strip") else str(value)
            min_len = int(rule["min"])
            if len(text) < min_len:
                return (
                    f"{rule['description']}: value {len(text)} characters "
                    f"is shorter than min length {min_len} (field '{rule['path']}')"
                )
            return None

        if rtype == "max_length":
            if value is None:
                return None
            text = str(value).strip() if rule.get("strip") else str(value)
            max_len = int(rule["max"])
            if len(text) > max_len:
                return (
                    f"{rule['description']}: value {len(text)} characters "
                    f"exceeds max length {max_len} (field '{rule['path']}')"
                )
            return None

        if rtype in ("subfield_min_length", "subfield_max_length"):
            if value is None:
                return None
            parts = str(value).split(rule.get("delimiter", "\\"))
            idx = int(rule["subfield"]) - 1
            if idx < 0 or idx >= len(parts):
                return None
            text = parts[idx].strip() if rule.get("strip") else parts[idx]
            length = int(rule["min"] if rtype == "subfield_min_length" else rule["max"])
            if rtype == "subfield_min_length" and len(text) < length:
                return (
                    f"{rule['description']}: subfield {rule['subfield']} "
                    f"is {len(text)} characters, shorter than min length {length} "
                    f"(field '{rule['path']}')"
                )
            if rtype == "subfield_max_length" and len(text) > length:
                return (
                    f"{rule['description']}: subfield {rule['subfield']} "
                    f"is {len(text)} characters, exceeds max length {length} "
                    f"(field '{rule['path']}')"
                )
            return None

        if rtype in ("subelement_min_length", "subelement_max_length"):
            if value is None:
                return None
            element = self._extract_subelement(value, rule["element"])
            if element is None:
                return (
                    f"{rule['description']}: subelement {rule['element']} "
                    f"is missing (field '{rule['path']}')"
                )
            text = element.strip() if rule.get("strip") else element
            length = int(rule["min"] if rtype == "subelement_min_length" else rule["max"])
            if rtype == "subelement_min_length" and len(text) < length:
                return (
                    f"{rule['description']}: subelement {rule['element']} "
                    f"is {len(text)} characters, shorter than min length {length} "
                    f"(field '{rule['path']}')"
                )
            if rtype == "subelement_max_length" and len(text) > length:
                return (
                    f"{rule['description']}: subelement {rule['element']} "
                    f"is {len(text)} characters, exceeds max length {length} "
                    f"(field '{rule['path']}')"
                )
            return None

        return None

    @staticmethod
    def _extract_subelement(value: Any, element_id: str) -> str | None:
        """Return the value of subelement ``element_id`` from a DE value
        encoded as concatenated ``<3-digit ID><3-digit length><value>`` chunks.

        Returns None if the element is absent or the encoding is malformed.
        """
        text = str(value)
        pos = 0
        n = len(text)
        while pos + 6 <= n:
            sid = text[pos:pos + 3]
            length_part = text[pos + 3:pos + 6]
            if not length_part.isdigit():
                return None
            vlen = int(length_part)
            start = pos + 6
            end = start + vlen
            if sid == element_id:
                return text[start:end] if end <= n else text[start:]
            if end > n:
                return None
            pos = end
        return None

    def evaluate_file(self, records: list[dict[str, Any]]) -> list[ComplianceViolation]:
        """Evaluate file-level rules (totals / counts) against all records.

        The footer record (last record in the list) supplies the declared
        value via ``footer_path``. Returns a list of ComplianceViolation.
        """
        violations: list[ComplianceViolation] = []
        if not records:
            return violations

        footer = records[-1]
        footer_no = footer.get("record")

        for rule in self.file_rules:
            declared_raw = self._resolve(footer, rule["footer_path"])
            declared = self._to_number(declared_raw)
            rtype = rule["type"]

            if rtype == "file_count":
                mtis = rule.get("record_mti")
                # File Message Counts (e.g. PDS 0306) declares the total
                # number of physical records in the file, including the
                # 1644 header and the trailer record itself -- so no
                # record is excluded here.
                actual = sum(
                    1 for r in records if (mtis is None or r.get("mti") == mtis)
                )
                label = f"count {actual}"

            elif rtype == "file_amount":
                mtis = rule.get("record_mti")
                actual = 0
                for r in records:
                    if mtis is not None and r.get("mti") != mtis:
                        continue
                    value = self._to_number(self._resolve(r, rule["field_path"]))
                    if value is not None:
                        actual += value
                label = f"total {actual}"

            else:
                continue

            if declared is None or declared != actual:
                message = (
                    f"{rule['description']}: declared {declared} "
                    f"({declared_raw!r}), expected {label}"
                )
                violations.append(
                    ComplianceViolation(
                        rule_id=rule["id"],
                        severity=rule.get("severity", "ERROR"),
                        message=message,
                        record_no=footer_no,
                        mti=footer.get("mti"),
                    )
                )

        return violations

    @staticmethod
    def _to_number(value: Any) -> int | None:
        if value is None:
            return None
        if isinstance(value, (int, float)):
            return int(value)
        text = str(value).strip()
        if not text:
            return None
        try:
            return int(text)
        except ValueError:
            return None
