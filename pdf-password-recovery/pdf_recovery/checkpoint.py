"""Checkpoint / resume support for --auto searches. Fully offline.

A checkpoint is a small JSON file (no PDF data, no passwords) recording the
contiguous tested prefix of the deterministic search space, so an
interrupted search can resume without skipping or resampling candidates.

Schema (v2; v1 files without a fingerprint are still accepted):
{
  "version": 2,
  "pdf": "<absolute pdf path>",
  "pdf_size": 12345,              # fingerprint: invalidate on file change
  "pdf_mtime_ns": 1234567890,     # fingerprint: invalidate on file change
  "pdf_head_sha256": "ab12...",   # sha256 of first 256 KiB (cheap, robust)
  "charset": "<resolved charset string>",
  "charset_spec": ["lower"],
  "charset_custom": null | "...",
  "min_length": 1,
  "max_length": 4,
  "total": 475254,
  "next_index": 1234,      # resume ordinal: first index NOT contiguously done
  "tested": 1200,          # contiguously completed count (= next_index - start)
  "updated": "2026-...Z",
  "workers": 4
}

Only the contiguous prefix is checkpointed: workers may finish out of order,
but the resume point advances only when ordinals [resume_start..N] are all
done. Buffered out-of-order completions beyond the prefix are retested on
resume (bounded duplicate work, never a skip).

Writes are atomic (temporary file + rename), so an interrupted write leaves
either the previous checkpoint or none at all — never a half-written file
under the real name. Corrupted files are reported (never silently resumed).
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
from typing import Any, Dict, Optional


CHECKPOINT_VERSION = 2

#: Bytes hashed from the start of the PDF for change detection.
_FINGERPRINT_HEAD_BYTES = 262144


def default_checkpoint_path(pdf_path: str) -> str:
    """Default checkpoint location: '<pdf>.auto-checkpoint.json'."""
    return f"{pdf_path}.auto-checkpoint.json"


def _utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def fingerprint_pdf(pdf_path: str) -> Dict[str, Any]:
    """Cheap, robust identity of a PDF file (size + mtime + head hash).

    Read-only. Raises OSError if the file cannot be read.
    """
    st = os.stat(pdf_path)
    digest = hashlib.sha256()
    with open(pdf_path, "rb") as fh:
        digest.update(fh.read(_FINGERPRINT_HEAD_BYTES))
    return {
        "pdf_size": st.st_size,
        "pdf_mtime_ns": st.st_mtime_ns,
        "pdf_head_sha256": digest.hexdigest(),
    }


def make_checkpoint(
    pdf_path: str,
    charset: str,
    charset_spec: list,
    charset_custom: Optional[str],
    min_length: int,
    max_length: int,
    total: int,
    next_index: int,
    tested_contiguous: int,
    workers: int,
    fingerprint: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    data = {
        "version": CHECKPOINT_VERSION,
        "pdf": os.path.abspath(pdf_path),
        "charset": charset,
        "charset_spec": list(charset_spec or []),
        "charset_custom": charset_custom,
        "min_length": min_length,
        "max_length": max_length,
        "total": total,
        "next_index": next_index,
        "tested": tested_contiguous,
        "updated": _utcnow(),
        "workers": workers,
    }
    if fingerprint:
        for key in ("pdf_size", "pdf_mtime_ns", "pdf_head_sha256"):
            if key in fingerprint:
                data[key] = fingerprint[key]
    return data


def save_checkpoint(path: str, data: Dict[str, Any]) -> None:
    """Atomically write checkpoint JSON (tmp file + rename)."""
    tmp = f"{path}.tmp"
    directory = os.path.dirname(os.path.abspath(path))
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)


def load_checkpoint(path: str) -> Dict[str, Any]:
    """Load and validate a checkpoint file.

    Raises FileNotFoundError, or ValueError describing the corruption
    (bad JSON, wrong shape, or bad field types). Callers add the
    "(use --reset)" hint. A torn write can never appear under the real
    name because saves are atomic (tmp file + rename).
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except ValueError as exc:
        raise ValueError(f"checkpoint is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("checkpoint is not a JSON object")
    for key in ("pdf", "charset", "min_length", "max_length", "total", "next_index"):
        if key not in data:
            raise ValueError(f"checkpoint missing key: {key}")
    for key in ("min_length", "max_length", "total", "next_index"):
        value = data.get(key)
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"checkpoint key {key!r} must be an integer")
    if data["next_index"] < 0 or data["total"] < 0:
        raise ValueError("checkpoint counters must be non-negative")
    if not isinstance(data.get("charset"), str):
        raise ValueError("checkpoint key 'charset' must be a string")
    return data


def checkpoint_exists(path: str) -> bool:
    return os.path.exists(path)


def reset_checkpoint(path: str) -> bool:
    """Delete checkpoint file. Returns True if something was removed."""
    try:
        os.unlink(path)
        return True
    except FileNotFoundError:
        return False


def describe_checkpoint(data: Dict[str, Any]) -> str:
    total = data.get("total", 0)
    nxt = data.get("next_index", 0)
    done = min(nxt, total) if total else nxt
    remaining = max(0, (total or 0) - done)
    pct = (100.0 * done / total) if total else 0.0
    charset = data.get("charset", "")
    lines = [
        f"PDF:          {data.get('pdf')}",
        f"Charset size: {len(charset)} chars",
        f"Lengths:      {data.get('min_length')}..{data.get('max_length')}",
        f"Total:        {total}",
        f"Completed:    {done} ({pct:.2f}%)",
        f"Remaining:    {remaining}",
        f"Resume index: {nxt}",
        f"Updated:      {data.get('updated')}",
    ]
    return "\n".join(lines)


def params_match(data: Dict[str, Any], pdf_path: str, charset: str,
                 min_length: int, max_length: int, total: int,
                 fingerprint: Optional[Dict[str, Any]] = None) -> tuple:
    """Check a checkpoint matches the requested search. Returns (ok, reason).

    Compares the PDF path, charset, length range and total (never resumes
    with incompatible parameters). When both the checkpoint and the caller
    carry a file fingerprint, a changed PDF invalidates the checkpoint
    instead of resuming against the wrong file. Checkpoints written before
    fingerprints existed (v1) skip the file check for backward
    compatibility. A worker-count difference is allowed (resume may use
    different --workers).
    """
    if os.path.abspath(pdf_path) != data.get("pdf"):
        return (False, f"checkpoint is for {data.get('pdf')}, not {os.path.abspath(pdf_path)}")
    if data.get("charset") != charset:
        return (False, "checkpoint charset differs (use --reset to restart)")
    if data.get("min_length") != min_length or data.get("max_length") != max_length:
        return (False, "checkpoint length range differs (use --reset to restart)")
    if data.get("total") != total:
        return (False, "checkpoint total differs (use --reset to restart)")
    if fingerprint is not None and any(k in data for k in
                                       ("pdf_size", "pdf_mtime_ns", "pdf_head_sha256")):
        for key in ("pdf_size", "pdf_mtime_ns", "pdf_head_sha256"):
            if key in data and data.get(key) != fingerprint.get(key):
                return (False, "checkpoint PDF differs (file changed since checkpoint; "
                               "use --reset to restart)")
    return (True, "")
