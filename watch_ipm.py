"""
watch_ipm.py

File watcher for incoming Mastercard IPM files.

Polls a directory for new/modified files whose name starts with a given
prefix (default "TESTR") and carries a numeric extension (e.g. TESTR.001).
Each detected file is parsed and validated with the same pipeline as
test.py, producing a CSV (and JSONL) in a fixed output directory.

Usage:
    python watch_ipm.py
    python watch_ipm.py --watch D:\\Vaultspay\\IPM --out D:\\mc\\IPM\\output
    python watch_ipm.py --prefix TESTR --interval 5 --once
    python watch_ipm.py --errors-only
    python watch_ipm.py --errors-only --no-jsonl
    python watch_ipm.py --mail-config config.env
    python watch_ipm.py --notify-to compliance-team@credopay.com

Email notifications:
    When a processed file contains one or more compliance violations, a
    single summary email is sent listing each flagged record's RRN (DE 37)
    with the violation message(s) and severity, plus any file-level
    violations (which carry no RRN).

    Settings are read from a config.env file (KEY=VALUE per line, next to
    this script by default; override the path with --mail-config):

        TO_RECEIVER_MAIL_ID   comma-separated To recipients. If blank,
                               falls back to --notify-to
                               (default ravi.k@credopay.com).
        CC_RECEIVER_MAIL_ID   comma-separated Cc recipients (optional)
        SMTPHOST              SMTP server host (default smtp.office365.com)
        SMTPPORT              SMTP server port (default 587)
        SENDERMAILID          mailbox used to authenticate and send from
        MAILPASSWORD          mailbox password / app password

    Pass --notify-to "" (with TO_RECEIVER_MAIL_ID also blank) to disable
    notifications entirely.
"""

import argparse
import json
import os
import smtplib
import sys
import time
from email.mime.text import MIMEText
from email.utils import formatdate
from pathlib import Path

from parser.compliance import RulesEngine
from parser.pds import PDSParser

import ipm_parser as ipm

def make_pipeline(metadata_dir, rules_path):
    de_metadata, pds_metadata = ipm.load_metadata(metadata_dir)
    pds_parser = PDSParser()
    compliance = RulesEngine(rules_path)
    return de_metadata, pds_metadata, pds_parser, compliance


def process_one(filename, pipeline):
    de_metadata, pds_metadata, pds_parser, compliance = pipeline
    results, file_violations = ipm.process_file(
        filename, de_metadata, pds_metadata, pds_parser, compliance
    )
    return results, file_violations, compliance


def _collect_compliance_flags(results):
    """Return one entry per record that has a compliance violation.

    Each entry is ``(record_no, rrn, acceptor_id, messages)`` where ``rrn``
    is DE 37 (Retrieval Reference Number), ``acceptor_id`` is DE 42 (Card
    Acceptor ID Code), both pulled from the record's parsed fields, and
    ``messages`` is the list of ``[SEVERITY] message`` strings for that
    record. Records with no ``compliance`` entry are not included --
    parsing errors alone do not count (compliance-only trigger).
    """
    flagged = []
    for result in results:
        violations = result.get("compliance")
        if not violations:
            continue
        fields = result.get("fields", {})
        rrn = fields.get("37", "")
        acceptor_id = fields.get("42", "")
        messages = [f"[{v['severity']}] {v['message']}" for v in violations]
        flagged.append((result.get("record"), rrn, acceptor_id, messages))
    return flagged


def _split_mail_list(value):
    """Split a comma-separated address list, dropping blanks/whitespace."""
    return [addr.strip() for addr in value.split(",") if addr.strip()]


def load_mail_config(config_path):
    """Load SMTP / notification settings from a simple ``KEY=VALUE`` file.

    Recognised keys (matching config.env):
        TO_RECEIVER_MAIL_ID   comma-separated To recipients
        CC_RECEIVER_MAIL_ID   comma-separated Cc recipients
        SMTPHOST              SMTP server host (default smtp.office365.com)
        SMTPPORT              SMTP server port (default 587)
        SENDERMAILID          mailbox used to authenticate and send from
        MAILPASSWORD          mailbox password / app password

    Blank lines and lines starting with ``#`` are ignored. Values may
    optionally be wrapped in quotes. If the file doesn't exist, all
    values default to empty/blank -- callers decide what to do about
    missing required fields (e.g. skip sending).

    Returns a dict with keys: to (list), cc (list), host, port, sender,
    password.
    """
    raw = {}
    path = Path(config_path)
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            raw[key.strip()] = value.strip().strip('"').strip("'")

    try:
        port = int(raw.get("SMTPPORT") or "587")
    except (TypeError, ValueError):
        port = 587

    return {
        "to": _split_mail_list(raw.get("TO_RECEIVER_MAIL_ID", "")),
        "cc": _split_mail_list(raw.get("CC_RECEIVER_MAIL_ID", "")),
        "host": raw.get("SMTPHOST") or "smtp.office365.com",
        "port": port,
        "sender": raw.get("SENDERMAILID", ""),
        "password": raw.get("MAILPASSWORD", ""),
    }


def send_compliance_notification(source_name, csv_path, flagged, mail_config, fallback_to=None,
                                 file_violations=None):
    """Send a single summary email listing every record with a compliance
    violation for one processed file.

    ``flagged`` is the list of ``(record_no, rrn, acceptor_id, messages)``
    tuples produced by ``_collect_compliance_flags``. ``file_violations``, when
    given, is the list of file-level ComplianceViolation objects (they
    have no RRN and are listed in a separate section). ``mail_config`` is
    the dict returned by ``load_mail_config``. ``fallback_to`` (e.g.
    --notify-to) is used as the To recipient when config.env's
    TO_RECEIVER_MAIL_ID is blank.

    Returns True if the email was sent, False otherwise. Failures are
    logged to stderr but never raised -- a notification failure must
    never take down the watcher loop.
    """
    to_list = mail_config.get("to") or ([fallback_to] if fallback_to else [])
    cc_list = mail_config.get("cc") or []
    sender = mail_config.get("sender")
    password = mail_config.get("password")
    host = mail_config.get("host", "smtp.office365.com")
    port = mail_config.get("port", 587)

    if not to_list:
        print(
            "SKIP notification: no To recipient configured (set "
            "TO_RECEIVER_MAIL_ID in config.env or pass --notify-to)",
            file=sys.stderr,
        )
        return False
    if not sender or not password:
        print(
            "SKIP notification: set SENDERMAILID / MAILPASSWORD in "
            "config.env to enable compliance emails",
            file=sys.stderr,
        )
        return False

    lines = [
        f"Compliance issue(s) detected in {source_name} ({csv_path.name}):",
        "",
    ]
    for record_no, rrn, acceptor_id, messages in flagged:
        rrn_display = rrn or "(missing)"
        acceptor_display = acceptor_id or "(missing)"
        lines.append(
            f"Record {record_no} - RRN {rrn_display} - "
            f"Acceptor ID {acceptor_display}:"
        )
        for message in messages:
            lines.append(f"  - {message}")
        lines.append("")
    if file_violations:
        lines.append("File-level violation(s):")
        for v in file_violations:
            lines.append(f"  - [{v.severity}] {v.message}")
        lines.append("")
    lines.append(f"Full details: {csv_path}")
    body = "\n".join(lines)

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = (
        f"[IPM Compliance] {len(flagged) + len(file_violations or [])} "
        f"issue(s) in {source_name}"
    )
    msg["From"] = sender
    msg["To"] = ", ".join(to_list)
    if cc_list:
        msg["Cc"] = ", ".join(cc_list)
    msg["Date"] = formatdate(localtime=True)

    all_recipients = to_list + cc_list

    try:
        with smtplib.SMTP(host, port, timeout=30) as server:
            server.starttls()
            server.login(sender, password)
            server.sendmail(sender, all_recipients, msg.as_string())
        return True
    except Exception as ex:
        print(f"ERROR sending compliance notification: {ex}", file=sys.stderr)
        return False


def write_outputs(filename, out_dir, pipeline, errors_only=False, skip_jsonl=False):
    """Process ``filename`` and write <name>.csv and <name>.jsonl in out_dir.

    The output base name includes the input file's numeric extension (e.g.
    TESTR.001 -> TESTR.001.csv) so files that share a stem but differ only
    by extension don't overwrite each other's output.

    ``pipeline`` is the ``(de_metadata, pds_metadata, pds_parser,
    compliance)`` tuple built by ``make_pipeline``.

    ``errors_only`` is forwarded to ``ipm.write_csv`` unchanged: when False
    (default) the CSV is the full development-mode CSV; when True it is
    the compact production CSV containing only records with errors and/or
    compliance violations.

    ``skip_jsonl``, when True, skips writing the .jsonl file entirely
    (production mode doesn't need it). Default False keeps the existing
    behaviour of always writing the .jsonl file.
    """
    base = Path(filename).name
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    csv_path = out_dir / f"{base}.csv"
    jsonl_path = out_dir / f"{base}.jsonl"

    results, file_violations, compliance = process_one(filename, pipeline)

    if not skip_jsonl:
        with open(jsonl_path, "w", encoding="utf-8") as f:
            for result in results:
                f.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n")

    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        ipm.write_csv(f, results, compliance, file_violations, errors_only=errors_only)

    error_count = sum(1 for r in results if r.get("errors"))
    flagged = _collect_compliance_flags(results)
    return csv_path, jsonl_path, len(results), error_count, file_violations, flagged


class Watcher:
    def __init__(self, watch_dir, out_dir, prefix, metadata_dir, rules_path, interval,
                 errors_only=False, skip_jsonl=False, mail_config=None, notify_to=None):
        self.watch_dir = Path(watch_dir)
        self.out_dir = Path(out_dir)
        self.prefix = prefix
        self.metadata_dir = metadata_dir
        self.rules_path = rules_path
        self.interval = interval
        self.errors_only = errors_only
        self.skip_jsonl = skip_jsonl
        self.mail_config = mail_config or {"to": [], "cc": [], "sender": "", "password": "",
                                            "host": "smtp.office365.com", "port": 587}
        self.notify_to = notify_to or None  # fallback To when config.env's TO is blank
        self.pipeline = make_pipeline(metadata_dir, rules_path)
        self.stability_wait = min(interval, 2.0)
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
        except OSError:
            return False
        time.sleep(self.stability_wait)
        try:
            size2, mtime2 = self._fingerprint(path)
        except OSError:
            return False
        return size1 == size2 and mtime1 == mtime2

    def _handle(self, path):
        if not self._stable(path):
            print(f"SKIP (still changing): {path.name}")
            return
        try:
            print(f"PROCESS: {path.name}")
            csv_path, jsonl_path, n, errors, file_violations, flagged = write_outputs(
                path, self.out_dir, self.pipeline,
                errors_only=self.errors_only,
                skip_jsonl=self.skip_jsonl,
            )
            self.seen[path] = self._fingerprint(path)
            status = "OK" if not errors and not file_violations and not flagged else "ISSUES"
            print(
                f"  -> {csv_path.name} ({n} records, {errors} error(s), "
                f"{len(file_violations)} file violation(s), "
                f"{len(flagged)} compliance issue(s)) [{status}]"
            )

            if flagged or file_violations:
                sent = send_compliance_notification(
                    path.name, csv_path, flagged, self.mail_config,
                    fallback_to=self.notify_to, file_violations=file_violations,
                )
                if sent:
                    recipients = self.mail_config.get("to") or [self.notify_to]
                    print(f"  -> notification email sent to {', '.join(recipients)}")
        except Exception as ex:
            print(f"ERROR processing {path.name}: {ex}", file=sys.stderr)

    def run(self, once=False, future_only=False):
        print(f"Watching {self.watch_dir} for files starting with {self.prefix}*")
        print(f"Output  -> {self.out_dir}")
        print(f"Rules   -> {self.rules_path}")
        print(f"Interval-> {self.interval}s")
        if future_only:
            self.ignore = {p for p in self._candidates()}
            print(f"Ignoring {len(self.ignore)} existing file(s) at startup "
                  f"(only future files will be processed)")
        else:
            self.ignore = set()
        print("=" * 70)

        while True:
            candidates = self._candidates()
            for path in candidates:
                if path in self.ignore:
                    continue
                if path not in self.seen:
                    self._handle(path)
                else:
                    try:
                        fp = self._fingerprint(path)
                    except OSError:
                        continue
                    if fp != self.seen[path]:
                        print(f"CHANGED: {path.name}")
                        self._handle(path)

            candidate_set = {p for p in candidates}
            self.seen = {k: v for k, v in self.seen.items() if k in candidate_set}

            if once:
                break
            time.sleep(self.interval)


def main():
    if getattr(sys, "frozen", False):
        script_dir = Path(sys._MEIPASS)
    else:
        script_dir = Path(__file__).resolve().parent

    parser = argparse.ArgumentParser(description="Watch for new IPM files")
    parser.add_argument("--watch", default=r"D:\Vaultspay\IPM", help="Directory to watch")
    parser.add_argument("--out", default=str(script_dir / "output"), help="Output directory")
    parser.add_argument("--prefix", default="TESTR",
                        help="Filename prefix (file must also have a numeric extension, e.g. TESTR.001)")
    parser.add_argument("--metadata", default=str(script_dir / "metadata"), help="Metadata directory")
    parser.add_argument("--rules", default=str(script_dir / "metadata" / "compliance_rules.json"), help="Compliance rules JSON")
    parser.add_argument("--interval", type=float, default=5.0, help="Poll interval in seconds")
    parser.add_argument("--once", action="store_true", help="Process existing files once, then exit")
    parser.add_argument(
        "--future-only",
        action="store_true",
        help="Skip files already present when the watcher starts; "
             "only process files that arrive afterwards",
    )
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
    parser.add_argument(
        "--notify-to",
        default="ravi.k@credopay.com",
        help="Fallback To address for compliance emails, used only when "
             "TO_RECEIVER_MAIL_ID in config.env is blank (pass an empty "
             "string to disable when config.env has no TO either)",
    )
    parser.add_argument(
        "--mail-config",
        default=str(script_dir / "config.env"),
        help="Path to the config.env file with mail settings "
             "(TO_RECEIVER_MAIL_ID, CC_RECEIVER_MAIL_ID, SMTPHOST, "
             "SMTPPORT, SENDERMAILID, MAILPASSWORD)",
    )
    args = parser.parse_args()

    mail_config = load_mail_config(args.mail_config)

    watcher = Watcher(
        args.watch,
        args.out,
        args.prefix,
        args.metadata,
        args.rules,
        args.interval,
        errors_only=args.errors_only,
        skip_jsonl=args.skip_jsonl,
        mail_config=mail_config,
        notify_to=args.notify_to,
    )
    watcher.run(once=args.once, future_only=args.future_only)


if __name__ == "__main__":
    main()