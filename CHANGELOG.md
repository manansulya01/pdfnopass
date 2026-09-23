# Changelog

All notable changes to this project are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.0.1] - 2026-09-23

### Fixed
- Privacy: `--output-json` metadata export no longer includes the recovered
  password inside nested per-stage entries unless `--include-password` is
  explicitly given (top level was already excluded). Added regression tests.
- Frozen executable: `__main__.py` now falls back to an absolute import and
  calls `multiprocessing.freeze_support()`, so the PyInstaller build runs
  (including multi-worker searches) without Python installed.
- Build: `pdf-recovery.spec` rewritten to the standard PyInstaller
  onedir layout and excludes unneeded heavy dependencies
  (numpy/PIL/matplotlib/pandas/scipy); bundle shrank from ~28 MB to ~12 MB.
- Removed dead imports and unused variables flagged by flake8 (`pdf_recovery`
  and `tests` are now flake8-clean apart from pre-existing continuation-indent
  style notes).

## [1.0.0] - 2026-09-21

Initial production release.

### Added
- Unified staged recovery engine: empty-password check → wordlist →
  variations → deterministic indexed automatic search (`recover`).
- Legacy modes preserved: `--wordlist`, `--bases`, `--brute`, `--auto`.
- Named charsets (`lower/upper/digits/letters/alphanumeric/symbols/printable`)
  plus `--charset-custom`; repeatable and comma-combinable.
- Bounded multiprocessing with early stop; sequential `--workers 1` mode.
- Atomic checkpoint/resume with PDF fingerprint invalidation (`--status`,
  `--reset`); benchmark metadata cache.
- Prestart safety gate with measured estimates and `--force` explicit opt-in.
- `benchmark` subcommand (compatible `--benchmark` flag form kept).
- Optional JSON/TOML user config file (CLI always overrides; credentials ignored).
- `RecoveryResult` object; optional `--output-json` export (password excluded
  unless `--include-password`); `--verbose` and `--log-file` diagnostics that
  never record candidates or passwords.
- `pyproject.toml` packaging with `pdf-recovery` console entry point;
  `pdf-recovery.spec` PyInstaller build; GitHub Actions CI matrix
  (Ubuntu/Windows/macOS × Python 3.11/3.12/3.13).
- Docs: professional README (20 sections), CONTRIBUTING, SECURITY, CHANGELOG.

### Security
- Local-only: no network, telemetry, subprocesses, or external APIs.
- Read-only PDFs (SHA-256 verified in tests); no hash extraction, bypass,
  downgrade, or stripping code paths.
- Checkpoints/logs/cache carry only non-sensitive metadata.
