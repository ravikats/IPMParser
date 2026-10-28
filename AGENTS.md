# IPMParser — Project Memory

Handoff notes so a fresh session can resume quickly without re-reading the
codebase. Ignore the historical errors; this is the current working state.

## Repo / status

- GitHub: `https://github.com/ravikats/IPMParser` (public), branch `main`
- Local working copy: `D:\mc\IPM\IPMParser` (committed; AGENTS.md itself is NOT committed — it holds the current commit id)
- Latest commit: **`9741528`** — "Include numeric extension in output CSV/JSONL base name"
- Push method: plain `git push` works (credentials cached in Windows Credential Manager). The fine-grained PAT
  (`D:\NSS\PAT.txt`) is **read-only** — do not rely on it for writes.
- Git exe (not on PATH): `C:\Program Files\Git\cmd\git.exe`

## What it is

Mastercard IPM file watcher + parser + compliance validator.

- `watch_ipm.py` — daemon: polls a directory for files matching `--prefix` (default `TESTR`)
  with a numeric extension (`.001`), parses each, writes CSV/JSONL, and emails a summary
  when compliance violations are found.
- `ipm_parser.py` — parse pipeline (`process_file`, `write_csv`, `load_metadata`).
- `parser/` — `compliance.py` (RulesEngine, rules + file_rules), `pds.py` (PDSParser),
  `scanner.py`, `de_reader.py`, `field_reader.py`, `bitmap.py`, `cleanup.py`.
  `compliance_bug.py` and `validator.py` are NOT in the runtime pipeline — ignore.
- `metadata/` — `de.json`, `pds.json`, `compliance_rules.json` (bundled into binary).
  `de.json` now defines DE 105 (Universal Cardholder Authentication Field Data, LLVAR).
- Top-level `compliance_rules.json` differs from `metadata/compliance_rules.json` — the
  defaults point at the `metadata/` one. DE 105 rules (required + subelement 001 min/max 22)
  were added to BOTH copies. `parser/compliance.py` has `subelement_min_length` /
  `subelement_max_length` rule types that parse IPM `<3-digit ID><3-digit length><value>`
  encoding (the old `subfield_*` backslash split is still used by DE 43 rules).

## Key runtime facts (do not re-derive)

- Email: DE 37 = RRN, DE 42 = Acceptor ID. Notification line format:
  `Record N - RRN <37> - Acceptor ID <42>:` then `- [SEVERITY] message`.
- Record-level violations only (`result["compliance"]`); file-level violations go in a
  separate email section. Severity prefixed in messages.
- `watch_ipm.py` builds the pipeline (metadata + `PDSParser` + `RulesEngine`) ONCE in
  `Watcher.__init__` (not per file). `make_pipeline()` returns a 4-tuple passed to
  `process_one(filename, pipeline)` / `write_outputs(filename, out_dir, pipeline, ...)`.
- `Watcher.run()` wraps `_fingerprint()` in `try/except OSError` and prunes `self.seen`
  each poll (only keeps current candidates). `_stable()` waits `min(interval, 2.0)`.
- `--future-only`: snapshots candidate files at startup into `self.ignore` and skips them
  (and any CHANGED reprocessing); only files that arrive after start are processed.
- Output CSV/JSONL base name includes the input's numeric extension (`TESTR.001` ->
  `TESTR.001.csv`), so same-stem files with different extensions don't overwrite each other.
- `load_mail_config` falls back to port 587 on bad `SMTPPORT`.

## Deployment (production)

- Server: RHEL 8 / Rocky 8 family → **glibc 2.28**. Ubuntu 24.04-built binaries fail
  (`GLIBC_2.38 not found`). MUST build inside a RHEL 8 UBI container.
- Binary is a PyInstaller onefile built from `watch_ipm.py`; `metadata/` bundled via
  `--add-data metadata:metadata`. `config.env` is gitignored / NEVER bundled (secret).
- Frozen-path handling: `watch_ipm.py main()` uses `sys._MEIPASS` when
  `getattr(sys, "frozen", False)` else `Path(__file__).resolve().parent`.
- systemd unit: `deploy/ipm-watch.service` — binary at `/opt/ipm-watch/ipm-watch`,
  WorkingDirectory `/opt/ipm-watch`, args:
  `--watch /vp-switch/OUTPUT --out /vp-switch/IPMOUT --prefix TESTR --no-jsonl
  --future-only --mail-config /Netset/Network_Settlement/config.env
  --rules /Netset/Network_Settlement/compliance_rules.json --interval 60`
- Metadata (`de.json`) is BUNDLED into the binary — server edits only the external
  `compliance_rules.json`. Rule changes need no rebuild; DE/field definition changes DO.
- `deploy/deploy.sh` (venv/source variant) references `test.py`/`requirements.txt`
  which do NOT exist — do not run it as-is.
- `config.env` keys: `TO_RECEIVER_MAIL_ID`, `CC_RECEIVER_MAIL_ID`, `SMTPHOST`,
  `SMTPPORT`, `SENDERMAILID`, `MAILPASSWORD`. Default host `smtp.office365.com:587`.

## CI/CD (`.github/workflows/build.yml`)

- Triggers: push to `main`, tags `v*`, manual `workflow_dispatch`.
- Build step runs Docker `registry.access.redhat.com/ubi8/python-311` with
  `pyinstaller --onefile --name ipm-watch --add-data metadata:metadata watch_ipm.py`.
- Artifact: `ipm-watch-linux` (~14 MB) under Actions → run → Artifacts. Tags attach the
  binary to a Release.
- YAML gotcha: multi-line `run:` MUST use `run: |` block scalar — trailing `\`
  line-continuation in a folded plain scalar broke PyInstaller (`Script file ' --add-data'
  does not exist`).

## Gotchas / decisions

- `config.env` and local test data (`TESTR*.01`, `*.csv`, `ipm-watch` binary, `build/`,
  `dist/`, `output/`, `INPUT/`) are gitignored.
- `watch_ipm.py` on Windows: default `--watch D:\Vaultspay\IPM`. Production overrides all paths.
- Changes must be committed AND pushed (`git push origin main`) to trigger builds;
  pushes have timed out before at 120s — use a larger timeout or retry.