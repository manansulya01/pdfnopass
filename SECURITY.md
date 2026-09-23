# Security Policy

## Scope and authorized use

This application recovers forgotten passwords of PDFs the user owns or is
explicitly authorized to access, by trial verification through the PDF
library's normal decryption API. Using it against documents you are not
authorized to access may be unlawful.

## What this software does NOT do

- No network connections, telemetry, external APIs, or subprocesses.
- No password/hash extraction, encryption bypass, downgrade, or stripping.
- No persistence of passwords, candidates, keys, or raw O/U hashes in logs,
  checkpoints, caches, or exports (exports exclude the password unless the
  user passes explicit `--include-password`).
- Source PDFs are opened read-only and never modified.

## Reporting a vulnerability

If you find a security weakness (e.g. a network call, a secret written to
disk, a bypass path, unsafe temp-file handling), please report it with:

1. Affected version (`pdf-recovery --version`).
2. Minimal reproduction steps using a locally generated test PDF.
3. Expected vs. actual behavior.

Do not include real passwords or private documents in reports — reproduce
with generated fixtures only.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |
