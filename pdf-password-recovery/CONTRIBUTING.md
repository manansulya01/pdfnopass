# Contributing

## Ground rules

- This tool is for recovering passwords of PDFs you own or are explicitly
  authorized to access. Do not contribute bypass, hash-extraction,
  downgrade/strip, telemetry, networking, or stealth features — such
  contributions will be rejected.
- Everything must stay offline, local, and read-only toward source PDFs.

## Workflow

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
python -m flake8 pdf_recovery --max-line-length=120 --extend-ignore=E203,W503
python -m black --check pdf_recovery tests
python -m mypy pdf_recovery
```

- Tests use stdlib `unittest`, run offline, and generate their own tiny PDF
  fixtures in temporary directories. Never commit real-world PDFs, password
  lists, or checkpoints.
- Keep every existing test green; add tests for new behavior in
  `tests/test_<area>.py`.
- No stack traces for users: CLI errors must print `Error:` + exit code.
- Never log or persist candidate passwords; assert it in tests when touching
  logging, checkpoints, cache, or result export.

## Release checklist

1. `python -m unittest discover -s tests` green.
2. Lint/format/type checks pass.
3. `pip install .` in a clean venv; verify `pdf-recovery --version` and
   `python -m pdf_recovery --version`.
4. End-to-end recovery on a generated PDF; verify SHA-256 before/after.
5. Update CHANGELOG.md; tag `v<version>`.
