"""
watch_ipm.py

File watcher for incoming Mastercard IPM files.

Polls a directory for new/modified files whose name starts with a given
prefix (default "TESTR", extension ignored). Each detected file is parsed
and validated with the same pipeline as test.py, producing a CSV (and
JSONL) in a fixed output directory.

Usage:
    python watch_ipm.py
    python watch_ipm.py --watch D:\\Vaultspay\\IPM --out D:\\mc\\IPM\\output
    python watch_ipm.py --prefix TESTR --interval 5 --once
    python watch_ipm.py --errors-only
    python watch_ipm.py --errors-only --no-jsonl
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

from parser.compliance import RulesEngine
from parser.pds import PDSParser

import ipm_parser as ipm

def make_pipeline(metadata_dir, rules_path):
    de_metadata, pds_metadata = ipm.load_metadata(metadata_dir)
    pds_parser = PDSParser()
    compliance = RulesEngine(rules_path)
    return de_metadata, pds_metadata, pds_parser, compliance


def process_one(filename, metadata_dir, rules_path):
    de_metadata, pds_metadata, pds_parser, compliance = make_pipeline(metadata_dir, rules_path)
    results, file_violations = ipm.process_file(
        filename, de_metadata, pds_metadata, pds_parser, compliance
    )
    return results, file_violations, compliance


def write_outputs(filename, out_dir, metadata_dir, rules_path, errors_only=False, skip_jsonl=False):
    """Process ``filename`` and write <name>.csv and <name>.jsonl in out_dir.

    ``errors_only`` is forwarded to ``ipm.write_csv`` unchanged: when False
    (default) the CSV is the full development-mode CSV; when True it is
    the compact production CSV containing only records with errors and/or
    compliance violations.

    ``skip_jsonl``, when True, skips writing the .jsonl file entirely
    (production mode doesn't need it). Default False keeps the existing
    behaviour of always writing the .jsonl file.
    """
    name = Path(filename).name
    stem = Path(filename).stem
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    csv_path = out_dir / f"{name}.csv"
    jsonl_path = out_dir / f"{name}.jsonl"

    results, file_violations, compliance = process_one(filename, metadata_dir, rules_path)

    if not skip_jsonl:
        with open(jsonl_path, "w", encoding="utf-8") as f:
            for result in results:
                f.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n")

    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        ipm.write_csv(f, results, compliance, file_violations, errors_only=errors_only)

    error_count = sum(1 for r in results if r.get("errors"))
    return csv_path, jsonl_path, len(results), error_count, file_violations


class Watcher:
    def __init__(self, watch_dir, out_dir, prefix, metadata_dir, rules_path, interval,
                 errors_only=False, skip_jsonl=False):
        self.watch_dir = Path(watch_dir)
        self.out_dir = Path(out_dir)
        self.prefix = prefix
        self.metadata_dir = metadata_dir
        self.rules_path = rules_path
        self.interval = interval
        self.errors_only = errors_only
        self.skip_jsonl = skip_jsonl
        self.seen = {}

    def _fingerprint(self, path):
        stat = path.stat()
        return stat.st_size, stat.st_mtime_ns

    def _candidates(self):
        if not self.watch_dir.is_dir():
            return []
        result = []
        for entry in os.scandir(self.watch_dir):
            if not entry.is_file():
                continue

            path = Path(entry.path)

            if not path.name.startswith(self.prefix):
                continue

            # Only process numeric extensions (.001, .002, ...)
            if not (path.suffix.startswith(".") and path.suffix[1:].isdigit()):
                continue

            result.append(path)

        return result

    def _stable(self, path):
        """Wait until the file size stops changing (i.e. fully written)."""
        try:
            size1, mtime1 = self._fingerprint(path)
        except FileNotFoundError:
            return False
        time.sleep(self.interval)
        try:
            size2, mtime2 = self._fingerprint(path)
        except FileNotFoundError:
            return False
        return size1 == size2 and mtime1 == mtime2

    def _handle(self, path):
        if not self._stable(path):
            print(f"SKIP (still changing): {path.name}")
            return
        try:
            print(f"PROCESS: {path.name}")
            csv_path, jsonl_path, n, errors, file_violations = write_outputs(
                path, self.out_dir, self.metadata_dir, self.rules_path,
                errors_only=self.errors_only,
                skip_jsonl=self.skip_jsonl,
            )
            self.seen[path] = self._fingerprint(path)
            status = "OK" if not errors and not file_violations else "ISSUES"
            print(
                f"  -> {csv_path.name} ({n} records, {errors} error(s), "
                f"{len(file_violations)} file violation(s)) [{status}]"
            )
        except Exception as ex:
            print(f"ERROR processing {path.name}: {ex}", file=sys.stderr)

    def run(self, once=False):
        print(f"Watching {self.watch_dir} for files starting with {self.prefix}*")
        print(f"Output  -> {self.out_dir}")
        print(f"Rules   -> {self.rules_path}")
        print(f"Interval-> {self.interval}s")
        print("=" * 70)

        while True:
            for path in self._candidates():
                if path not in self.seen:
                    self._handle(path)
                else:
                    fp = self._fingerprint(path)
                    if fp != self.seen[path]:
                        print(f"CHANGED: {path.name}")
                        self._handle(path)

            if once:
                break
            time.sleep(self.interval)


def main():
    script_dir = Path(__file__).resolve().parent

    parser = argparse.ArgumentParser(description="Watch for new IPM files")
    parser.add_argument("--watch", default=r"D:\Vaultspay\IPM", help="Directory to watch")
    parser.add_argument("--out", default=str(script_dir / "output"), help="Output directory")
    parser.add_argument("--prefix", default="TESTR", help="Filename prefix (extension ignored)")
    parser.add_argument("--metadata", default=str(script_dir / "metadata"), help="Metadata directory")
    parser.add_argument("--rules", default=str(script_dir / "metadata" / "compliance_rules.json"), help="Compliance rules JSON")
    parser.add_argument("--interval", type=float, default=5.0, help="Poll interval in seconds")
    parser.add_argument("--once", action="store_true", help="Process existing files once, then exit")
    parser.add_argument(
        "--errors-only",
        action="store_true",
        help="Write a compact production CSV (only records with errors/compliance violations)",
    )
    parser.add_argument(
        "--no-jsonl",
        dest="skip_jsonl",
        action="store_true",
        help="Skip writing the .jsonl output file (production mode)",
    )
    args = parser.parse_args()

    watcher = Watcher(
        args.watch,
        args.out,
        args.prefix,
        args.metadata,
        args.rules,
        args.interval,
        errors_only=args.errors_only,
        skip_jsonl=args.skip_jsonl,
    )
    watcher.run(once=args.once)


if __name__ == "__main__":
    main()
