# Universal PDF Password Recovery Utility

Offline, local-only password recovery for PDFs you own or are explicitly
authorized to access. Tests candidate passwords solely through the normal
PDF decryption path (`pypdf` `decrypt()`).

```bash
pdf-recovery recover --pdf "document.pdf"
```

## 1. What the application does

Given a PDF whose opening password you forgot, the tool:

1. Detects whether the PDF is encrypted and reports the encryption scheme
   (`/Filter /V /R`, key length) when the library exposes it.
2. Tries the empty password, then (optionally) your wordlist and your
   partially-remembered base words, then systematically enumerates candidates
   by increasing length.
3. Uses all CPU cores (bounded multiprocessing), checkpoints progress
   atomically, resumes after interruption, and stops immediately on success.
4. Tells you honestly when a search is too large to be feasible instead of
   hanging your machine.

It never modifies the original PDF (opened read-only), never uploads
anything, needs no network, and contains no password-bypass, hash-extraction,
or encryption-stripping code of any kind.

## 2. Authorization / privacy warning

> **Use this tool ONLY on PDFs you own or are explicitly authorized to
> access.** Unauthorized access to documents may be unlawful. The tool prints
> this warning on every run. Everything runs locally on your machine; no
> document, password, hash, or telemetry ever leaves it (see §19).

## 3. Installation

Requires Python 3.9+ and `pip`.

```bash
# From the project directory:
pip install .

# Then run either entry point (identical behavior):
pdf-recovery recover --pdf document.pdf
python -m pdf_recovery recover --pdf document.pdf

pdf-recovery --version
pdf-recovery --help
```

Dependencies (`requirements.txt`, also in `pyproject.toml`): `pypdf>=4.0.0`,
`tqdm>=4.64.0`. Developer tooling: `pip install -r requirements-dev.txt`.

## 4. Quick start

```bash
# Check a file (no search runs):
pdf-recovery recover --pdf document.pdf --check-only

# Beginner-friendly automatic recovery (sane defaults: lower/1-4):
pdf-recovery recover --pdf "document.pdf"

# With a wordlist you already have:
pdf-recovery recover --pdf document.pdf --wordlist passwords.txt

# Fully explicit automatic search:
pdf-recovery recover --pdf document.pdf --auto --force \
  --charset alphanumeric --min-length 1 --max-length 6 --workers 8
```

A run prints an aligned status panel, live progress on stderr, and ends with
`SUCCESS / Password recovered: '…'` (exit 0), `SEARCH EXHAUSTED` (exit 1),
or `INTERRUPTED` (exit 130). Usage errors exit 2; unexpected failures print a
one-line `Error:` (never a stack trace) and exit 1.

## 5. Automatic recovery

```bash
pdf-recovery recover --pdf document.pdf
pdf-recovery recover --pdf document.pdf --charset lower,digits \
  --min-length 1 --max-length 5 --workers 4
pdf-recovery --pdf document.pdf --auto   # legacy equivalent
```

Candidates enumerate deterministically by increasing length, lexicographic
within a length, lazily (never held in RAM). Before starting, the tool shows
`total = Σ(charset_size^length)`, tiered warnings (`>5M / >10M / >1B`), and —
unless `--force` — the prestart safety gate (§10).

## 6. Wordlist recovery

One password per line; blanks skipped; `#` lines are comments:

```bash
pdf-recovery recover --pdf document.pdf --wordlist passwords.txt --workers 4
pdf-recovery --pdf document.pdf --wordlist passwords.txt --workers 1 --no-progress
```

## 7. Custom character sets

Named sets (repeatable, comma-combinable): `lower`(26) `upper`(26)
`digits`(10) `letters`(52) `alphanumeric`(62) `symbols`(32) `printable`(94).

```bash
pdf-recovery recover --pdf document.pdf --charset alphanumeric \
  --min-length 1 --max-length 6
pdf-recovery recover --pdf document.pdf --charset lower --charset digits \
  --min-length 1 --max-length 5
pdf-recovery recover --pdf document.pdf --charset-custom "abc123!#" \
  --min-length 1 --max-length 4
```

## 8. Checkpoint / resume

Progress checkpoints atomically to `<pdf>.auto-checkpoint.json` (override with
`--checkpoint PATH`, or set a `checkpoint_dir` in the config file, §6 of the
feature set below). Only the contiguous tested prefix is stored — resume never
skips candidates; at most a bounded overlap is retested. Cleared on success or
full exhaustion; kept on interruption or `--limit`. A changed PDF invalidates
the checkpoint (size/mtime/content fingerprint); corrupted files are reported
with a `--reset` hint and never silently resumed.

```bash
pdf-recovery recover --pdf document.pdf --charset digits \
  --min-length 1 --max-length 6 --limit 200000   # stop any time with Ctrl+C
pdf-recovery recover --pdf document.pdf --charset digits \
  --min-length 1 --max-length 6                  # resumes automatically
pdf-recovery --pdf document.pdf --status
pdf-recovery --pdf document.pdf --reset
```

Optional per-user defaults (never mandatory) live in a JSON config file —
`--config PATH`, else auto-discovered (`~/.config/pdf-recovery/config.json`
on Linux, `~/Library/Application Support/pdf-recovery/config.json` on macOS,
`%APPDATA%\pdf-recovery\config.json` on Windows):

```json
{
  "workers": 8,
  "charset": "alphanumeric",
  "min_length": 1,
  "max_length": 6,
  "no_progress": false,
  "verbose": false,
  "checkpoint_dir": "/home/user/.cache/pdf-recovery"
}
```

CLI arguments always override the file. Credential-like keys are ignored with
a warning — **never store passwords in config files**.

Explicit result export (never the default):

```bash
pdf-recovery recover --pdf document.pdf --output-json result.json
pdf-recovery recover --pdf document.pdf --output-json result.json --include-password
```

Without `--include-password` the JSON holds metadata only. Verbose,
non-sensitive diagnostics: `--verbose`; append them to a file with
`--log-file log.txt` (passwords and candidates are never logged).

## 9. Benchmarking

```bash
pdf-recovery benchmark --pdf document.pdf
pdf-recovery --pdf document.pdf --benchmark   # compatible form
pdf-recovery benchmark --pdf document.pdf --charset alphanumeric \
  --min-length 1 --max-length 4 --bench-samples 30 --workers 4
```

Uses the actual PDF through normal `decrypt()` with guaranteed-wrong
synthetic passwords — it never attempts the real password and never modifies
the file. Only non-sensitive metadata (rate, samples, method) is cached.
Output clearly separates the **measured rate** from the **estimated
completion time** plus an honest feasibility verdict. CPU-only; no GPU is
claimed.

## 10. Large-search safety gate

`recover` never silently launches an impractical search. A quick cached probe
estimates the remaining time; past ~10M candidates or ~2 h estimated it STOPS:

```
AUTOMATIC SEARCH GATED
The automatic search space is extremely large (...) and is estimated to take
1276474y 132d at 153 attempts/sec (measured locally, CPU-only).
To explicitly start it, run:
  python -m pdf_recovery recover --pdf "document.pdf" --auto --force ...
```

## 11. `--force`

Explicit opt-in for large searches (also skips straight past the gate):

```bash
pdf-recovery recover --pdf document.pdf --auto --force \
  --charset printable --min-length 1 --max-length 8
```

A small `--limit` likewise bounds the work, so limit-capped runs start
without `--force` and stay resumable.

## 12. Windows installation

```powershell
py -m pip install .
pdf-recovery recover --pdf "C:\Users\you\Documents\file.pdf"
```

Paths with spaces/Unicode work as-is (quote them). Checkpoints land next to
the PDF unless `--checkpoint` or config `checkpoint_dir` says otherwise.
Standalone executable: install PyInstaller and run `pyinstaller
pdf-recovery.spec` → `dist\pdf-recovery\pdf-recovery.exe` (runs without
Python, multiprocessing included).

## 13. macOS installation

```bash
pip3 install .
pdf-recovery recover --pdf "document.pdf"
# Executable: pip install pyinstaller && pyinstaller pdf-recovery.spec
# -> dist/pdf-recovery/pdf-recovery
```

## 14. Linux installation

```bash
pip install .
pdf-recovery recover --pdf "document.pdf"
# Executable: pip install pyinstaller && pyinstaller pdf-recovery.spec
# -> dist/pdf-recovery/pdf-recovery
```

All three platforms also support `python -m pdf_recovery …` identically.

## 15. Troubleshooting

| Symptom | Meaning / fix |
|---|---|
| `Error: PDF not found` | Path typo; check quoting of spaces. |
| `… is a directory, not a PDF file` | Point `--pdf` at a single `.pdf` file. |
| `nothing to recover` | File is not encrypted; no password needed. |
| `unsupported encryption scheme` | Library can't process it; reported, never bypassed. Try updating `pypdf`. |
| `Malformed or unreadable PDF` | File is corrupt/truncated. |
| `cannot read checkpoint … (use --reset)` | Corrupt or half-written file; delete with `--reset` and rerun. |
| `checkpoint PDF differs (file changed …)` | PDF replaced/edited after checkpoint; `--reset` to restart. |
| `checkpoint … differs (use --reset)` | Charset/lengths changed; `--reset` to restart. |
| `AUTOMATIC SEARCH GATED` | Space too large; rerun the printed `--force` command or narrow scope. |
| `password not found within --limit` | Raise `--limit` or rerun to resume from checkpoint. |
| `usage: pdf-recovery … error:` | Exit 2: CLI usage error (e.g. missing `--pdf`). |

## 16. Performance expectations

Measured locally (example): ~110–160 attempts/sec single-core on RC4 PDFs.
expect roughly linear scaling with `--workers` until CPU saturation.
`lower/1-4` (475,254 candidates) takes minutes–tens of minutes;
`alphanumeric/1-6` (~57B) and beyond are not CPU-feasible — run
`benchmark` first and heed the gate.

## 17. PDF encryption limitations

PDF supports several encryption revisions (RC4-40, RC4-128, AES-128 via
crypt filters, AES-256). This tool only *verifies* passwords through the
installed `pypdf`; if `pypdf` lacks the algorithm (e.g. AES without the
`cryptography` package), recovery reports `unsupported encryption` instead of
attempting anything clever. Owner-password restrictions on an otherwise open
file need no recovery. Passwords are verified by trial decryption — there is
no shortcut, which is exactly why §18 holds.

## 18. Why strong random passwords may be computationally infeasible

Each extra character multiplies the search space by the charset size
(`62^8 ≈ 2.2×10¹⁵` for alphanumeric length 8 — millions of years at
hundreds of attempts/sec). Random 8+ character passwords over large charsets
cannot realistically be brute-forced on a CPU, by this tool or any
legitimate one. Prefer wordlists / variations of something partially
remembered, narrow the charset and lengths, and treat exhaustive search as a
last resort for short passwords. The safety gate and benchmark exist to make
this impossibility visible *before* you spend the electricity.

## 19. Security / privacy architecture

- No sockets, no telemetry, no external APIs, no subprocesses to remote
  services (audit: `grep -R "socket\|requests\|urllib\|subprocess" pdf_recovery/`
  shows only the benchmark's *local* `ProcessPoolExecutor`).
- Filenames/config values treated as untrusted (existence + directory checks,
  no shell interpolation — all `subprocess` use is absent; quoting helper is
  display-only for echoed rerun commands).
- Temp files: stdlib `tempfile` semantics; atomic checkpoint writes
  (tmp + rename); no predictable world-readable secret paths.
- Source PDFs opened read-only; no code path writes to them (verified by
  SHA-256 before/after in testing).
- No password/hash extraction, no downgrade/strip/patch paths exist.
- Logs/checkpoints/cache carry only counts, rates, resume indexes and
  redacted encryption metadata — never candidates, passwords, keys, or raw
  O/U hashes (asserted by tests).

## 20. Development / testing instructions

```bash
pip install -r requirements-dev.txt   # flake8, black, mypy, pyinstaller
python -m unittest discover -s tests -v
python -m flake8 pdf_recovery --max-line-length=120 --extend-ignore=E203,W503
python -m black --check pdf_recovery tests
python -m mypy pdf_recovery
python -m build 2>/dev/null || pip install .   # packaging check
```

Project layout: `pdf_recovery/` (`cli`, `engine`, `candidates`, `auto`,
`runner`, `benchmark`, `checkpoint`, `config`+`config_file`, `pdf_tester`,
`results`) and `tests/` (`test_candidates`, `test_pdf_tester`, `test_auto`,
`test_universal`, `test_safety`, `test_production`). See CONTRIBUTING.md.
