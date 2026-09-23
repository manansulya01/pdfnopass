"""Multiprocess recovery orchestration with progress + Ctrl+C handling.

Design:
- Each worker opens the PDF read-only and calls ``try_password`` (the
  normal pypdf decryption path). No hashes or file contents leave the
  machine; there is no networking anywhere in this package.
- The parent streams candidates lazily and keeps only a bounded number
  of in-flight futures so multi-million brute-force spaces do not blow
  up memory.
- On the first success all pending work is cancelled immediately.
- KeyboardInterrupt (Ctrl+C) is caught, workers are shut down, and an
  "interrupted" result is returned instead of a traceback.
"""
from __future__ import annotations

import concurrent.futures
import sys
import time
from typing import Dict, Iterable, Optional, Tuple


def _check_one(args: Tuple[str, str]) -> Tuple[str, str]:
    """Worker entry point (top-level so it pickles under spawn).

    Returns (password, outcome) where outcome is one of:
    "match" | "no" | "unsupported" | "malformed" | "missing".
    """
    pdf_path, password = args
    # Local import so workers don't pay import cost until needed.
    from .pdf_tester import (
        PdfMalformedError,
        PdfNotFoundError,
        PdfUnsupportedEncryptionError,
        try_password,
    )

    try:
        ok = try_password(pdf_path, password)
        return (password, "match" if ok else "no")
    except PdfUnsupportedEncryptionError:
        return (password, "unsupported")
    except PdfMalformedError:
        return (password, "malformed")
    except PdfNotFoundError:
        return (password, "missing")
    except Exception:
        return (password, "no")


def _make_progress(total: Optional[int], desc: str, enabled: bool):
    if not enabled:
        return None
    try:
        import shutil

        from tqdm import tqdm  # type: ignore

        # Bounded width for small terminals; stderr keeps stdout redirect-safe.
        width = shutil.get_terminal_size((80, 20)).columns
        return tqdm(total=total, desc=desc, unit="pw", dynamic_ncols=True,
                    ncols=max(60, min(88, width)), mininterval=0.3)
    except ImportError:
        return None


def run_recovery(
    pdf_path: str,
    candidates: Iterable[str],
    workers: int = 4,
    total: Optional[int] = None,
    limit: Optional[int] = None,
    show_progress: bool = True,
    desc: str = "Testing passwords",
    dedup: bool = True,
) -> Dict:
    """Test *candidates* against *pdf_path*.

    Returns dict: {"status", "password", "tried", "total", "elapsed",
    "truncated"}. status is one of "found" | "not_found" |
    "interrupted" | "error". "error" carries "error" message.
    """
    start = time.monotonic()
    tried = 0
    pbar = _make_progress(total if total != 0 else None, desc, show_progress)
    simple_every = 500
    seen = set() if dedup else None

    def note_progress(n: int = 1):
        if pbar is not None:
            pbar.update(n)
        elif show_progress and tried % simple_every == 0:
            msg = f"\r{tried} passwords tried..."
            if total:
                msg = f"\r{tried}/{total} passwords tried..."
            sys.stderr.write(msg)
            sys.stderr.flush()

    def finish(status: str, password=None, error=None, truncated=False):
        elapsed = time.monotonic() - start
        if pbar is not None:
            pbar.close()
        elif show_progress:
            sys.stderr.write("\n")
        return {
            "status": status,
            "password": password,
            "tried": tried,
            "total": total,
            "elapsed": elapsed,
            "truncated": truncated,
            "error": error,
        }

    # Filter + cap lazily so huge generators stay lazy.
    def stream():
        count = 0
        for cand in candidates:
            if dedup:
                assert seen is not None
                if cand in seen:
                    continue
                seen.add(cand)
            if limit is not None and count >= limit:
                break
            count += 1
            yield cand

    it = stream()

    try:
        if workers <= 1:
            for pw in it:
                outcome_pw, outcome = _check_one((pdf_path, pw))
                tried += 1
                note_progress()
                if outcome == "match":
                    return finish("found", password=outcome_pw)
                if outcome in ("unsupported", "malformed", "missing"):
                    kind = {
                        "unsupported": "Unsupported PDF encryption scheme.",
                        "malformed": "Malformed or unreadable PDF.",
                        "missing": "PDF file not found.",
                    }[outcome]
                    return finish("error", error=kind)
                if limit is not None and tried >= limit:
                    return finish("not_found", truncated=True)
            truncated = limit is not None and tried >= (limit or 0)
            return finish("not_found", truncated=truncated)

        # Multiprocess path with bounded in-flight futures.
        max_in_flight = max(workers * 4, 8)
        with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as ex:
            pending: Dict[concurrent.futures.Future, str] = {}

            def fill():
                while len(pending) < max_in_flight:
                    try:
                        pw = next(it)
                    except StopIteration:
                        break
                    fut = ex.submit(_check_one, (pdf_path, pw))
                    pending[fut] = pw

            fill()
            while pending:
                done, _ = concurrent.futures.wait(
                    list(pending.keys()),
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                for fut in done:
                    pw = pending.pop(fut)
                    try:
                        ret_pw, outcome = fut.result()
                    except Exception:  # pragma: no cover - defensive
                        tried += 1
                        note_progress()
                        continue
                    tried += 1
                    note_progress()
                    if outcome == "match":
                        for f in pending:
                            f.cancel()
                        ex.shutdown(wait=False, cancel_futures=True)
                        return finish("found", password=ret_pw)
                    if outcome in ("unsupported", "malformed", "missing"):
                        kind = {
                            "unsupported": "Unsupported PDF encryption scheme.",
                            "malformed": "Malformed or unreadable PDF.",
                            "missing": "PDF file not found.",
                        }[outcome]
                        for f in pending:
                            f.cancel()
                        ex.shutdown(wait=False, cancel_futures=True)
                        return finish("error", error=kind)
                    if limit is not None and tried >= limit:
                        for f in pending:
                            f.cancel()
                        ex.shutdown(wait=False, cancel_futures=True)
                        return finish("not_found", truncated=True)
                # Replenish, respecting limit.
                if limit is not None and tried + len(pending) >= limit:
                    pass
                else:
                    fill()
            truncated = limit is not None and tried >= (limit or 0)
            return finish("not_found", truncated=truncated)
    except KeyboardInterrupt:
        return finish("interrupted")
