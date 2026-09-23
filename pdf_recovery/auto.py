"""Automatic clue-free search: deterministic indexed enumeration + resume.

- Candidates enumerated by increasing length, lexicographic within a length
  following charset order (matches ``brute_force_candidates``). Lazy:
  each password is derived from its global ordinal in O(length); the space
  is never materialised.
- Multiprocess via ProcessPoolExecutor with bounded in-flight futures.
- Contiguous-prefix checkpointing: resume point advances only when all
  ordinals below it are done, so resume never skips (at most a bounded
  overlap is retested).
- Early stop: all workers cancelled immediately on first match.
- Progress shows current length, tested, rate, elapsed, remaining.
"""
from __future__ import annotations

import concurrent.futures
import sys
import time
from typing import Dict, Optional

from .candidates import index_to_password, length_for_index
from .checkpoint import (
    fingerprint_pdf,
    make_checkpoint,
    reset_checkpoint,
    save_checkpoint,
)


def _auto_progress(total: int, enabled: bool):
    if not enabled:
        return None
    try:
        import shutil

        from tqdm import tqdm  # type: ignore

        # Bounded width for small terminals; progress goes to stderr so
        # stdout stays clean when redirected. No per-candidate newlines.
        width = shutil.get_terminal_size((80, 20)).columns
        return tqdm(total=total, desc="Auto", unit="pw", dynamic_ncols=True,
                    ncols=max(60, min(88, width)), mininterval=0.3)
    except ImportError:
        return None


def run_auto(
    pdf_path: str,
    charset: str,
    min_length: int,
    max_length: int,
    total: int,
    start_index: int = 0,
    workers: int = 4,
    limit: Optional[int] = None,
    show_progress: bool = True,
    checkpoint_path: Optional[str] = None,
    checkpoint_meta: Optional[Dict] = None,
    checkpoint_every: int = 500,
    checkpoint_seconds: float = 5.0,
) -> Dict:
    """Run the automatic search from *start_index*.

    *limit* caps candidates tested in THIS invocation (from start_index).
    Returns dict with status found|not_found|interrupted|error plus
    password/tried/total/next_index/elapsed/truncated/checkpoint info.
    """
    from .runner import _check_one  # reuse normal pypdf decrypt path

    start_time = time.monotonic()
    k = len(charset)
    end_exclusive = min(total, start_index + limit) if limit is not None else total
    to_test = max(0, end_exclusive - start_index)

    pbar = _auto_progress(to_test, show_progress)

    completed_total = 0  # all finished (any order), for rate/remaining
    completed_contig = start_index  # contiguous prefix frontier (checkpoint)
    done_set = set()  # completed ordinals > contig (bounded by in-flight)
    submitted_next = start_index
    current_length = length_for_index(k, min_length, max_length, start_index) if to_test else min_length
    last_ckpt_time = start_time
    last_ckpt_contig = completed_contig
    last_ckpt_length = current_length
    _pdf_fingerprint = None  # computed lazily on first checkpoint save

    def _save_ckpt():
        nonlocal last_ckpt_time, last_ckpt_contig, last_ckpt_length, _pdf_fingerprint
        if not checkpoint_path:
            return
        meta = checkpoint_meta or {}
        if _pdf_fingerprint is None:
            try:
                _pdf_fingerprint = fingerprint_pdf(pdf_path)
            except OSError:
                _pdf_fingerprint = False  # don't retry every save
        data = make_checkpoint(
            pdf_path=pdf_path,
            charset=charset,
            charset_spec=meta.get("charset_spec", []),
            charset_custom=meta.get("charset_custom"),
            min_length=min_length,
            max_length=max_length,
            total=total,
            next_index=completed_contig,
            tested_contiguous=completed_contig - start_index,
            workers=workers,
            fingerprint=_pdf_fingerprint or None,
        )
        try:
            save_checkpoint(checkpoint_path, data)
        except OSError:
            pass
        last_ckpt_time = time.monotonic()
        last_ckpt_contig = completed_contig
        last_ckpt_length = current_length

    def _delete_ckpt():
        if checkpoint_path:
            try:
                reset_checkpoint(checkpoint_path)
            except OSError:
                pass

    def _maybe_ckpt(force: bool = False):
        if not checkpoint_path:
            return
        if force:
            _save_ckpt()
            return
        if completed_contig == last_ckpt_contig:
            return
        now = time.monotonic()
        length_changed = current_length != last_ckpt_length
        if length_changed or (completed_total % checkpoint_every == 0) or (now - last_ckpt_time >= checkpoint_seconds):
            _save_ckpt()

    def _update_display():
        if pbar is not None:
            try:
                remaining = max(0, to_test - completed_total)
                pbar.set_postfix({"len": current_length, "remaining": remaining})
            except Exception:
                pass
        elif show_progress and completed_total % 500 == 0:
            elapsed = time.monotonic() - start_time
            rate = (completed_total / elapsed) if elapsed > 0 else 0.0
            remaining = max(0, to_test - completed_total)
            sys.stderr.write(
                f"\rlen={current_length} tried={completed_total}/{to_test} "
                f"rate={rate:.0f}/s elapsed={elapsed:.0f}s remaining={remaining}   "
            )
            sys.stderr.flush()

    def _finish(status: str, password=None, error=None, truncated=False):
        elapsed = time.monotonic() - start_time
        if pbar is not None:
            pbar.close()
        elif show_progress:
            sys.stderr.write("\n")
        rate = (completed_total / elapsed) if elapsed > 0 else 0.0
        return {
            "status": status,
            "password": password,
            "tried": completed_total,
            "total": total,
            "start_index": start_index,
            "next_index": completed_contig,
            "current_length": current_length,
            "elapsed": elapsed,
            "rate": rate,
            "remaining": max(0, end_exclusive - start_index - completed_total),
            "truncated": truncated,
            "checkpoint": checkpoint_path,
            "error": error,
        }

    def _note_done(idx: int):
        nonlocal completed_total, completed_contig
        completed_total += 1
        done_set.add(idx)
        while completed_contig in done_set:
            done_set.discard(completed_contig)
            completed_contig += 1

    def _outcome_error(outcome: str) -> Optional[str]:
        return {
            "unsupported": "Unsupported PDF encryption scheme.",
            "malformed": "Malformed or unreadable PDF.",
            "missing": "PDF file not found.",
        }.get(outcome)

    try:
        if to_test == 0:
            return _finish("not_found", truncated=bool(limit))

        if workers <= 1:
            # Sequential: exact order, checkpoint is exact (no overlap).
            for idx in range(start_index, end_exclusive):
                pw, length = index_to_password(charset, min_length, max_length, idx)
                current_length = length
                _, outcome = _check_one((pdf_path, pw))
                _note_done(idx)
                if pbar is not None:
                    pbar.update(1)
                    _update_display()
                else:
                    _update_display()
                if outcome == "match":
                    _delete_ckpt()
                    return _finish("found", password=pw)
                err = _outcome_error(outcome)
                if err:
                    return _finish("error", error=err)
                # Checkpoint on length boundary or periodically.
                if idx + 1 == end_exclusive or (completed_total % checkpoint_every == 0):
                    _maybe_ckpt(force=(idx + 1 == end_exclusive))
                else:
                    _maybe_ckpt()
            truncated = bool(limit is not None and end_exclusive < total)
            if truncated:
                _save_ckpt()  # keep resume point for --limit runs
            else:
                _delete_ckpt()  # space exhausted: no stale checkpoint
            return _finish("not_found", truncated=truncated)

        max_in_flight = max(workers * 4, 8)
        with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as ex:
            pending: Dict[concurrent.futures.Future, int] = {}
            pending_len: Dict[int, int] = {}

            def fill():
                nonlocal submitted_next, current_length
                while len(pending) < max_in_flight and submitted_next < end_exclusive:
                    pw, length = index_to_password(charset, min_length, max_length, submitted_next)
                    fut = ex.submit(_check_one, (pdf_path, pw))
                    pending[fut] = submitted_next
                    pending_len[submitted_next] = length
                    current_length = length
                    submitted_next += 1

            fill()
            if pbar is not None:
                _update_display()
            while pending:
                done, _ = concurrent.futures.wait(
                    list(pending.keys()),
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                for fut in done:
                    idx = pending.pop(fut)
                    pending_len.pop(idx, None)
                    try:
                        ret_pw, outcome = fut.result()
                    except Exception:
                        _note_done(idx)
                        if pbar is not None:
                            pbar.update(1)
                        _update_display()
                        _maybe_ckpt()
                        continue
                    _note_done(idx)
                    if pbar is not None:
                        pbar.update(1)
                    _update_display()
                    _maybe_ckpt()
                    if outcome == "match":
                        for f in pending:
                            f.cancel()
                        ex.shutdown(wait=False, cancel_futures=True)
                        _delete_ckpt()
                        return _finish("found", password=ret_pw)
                    err = _outcome_error(outcome)
                    if err:
                        for f in pending:
                            f.cancel()
                        ex.shutdown(wait=False, cancel_futures=True)
                        return _finish("error", error=err)
                fill()
                if pbar is not None:
                    _update_display()
            truncated = bool(limit is not None and end_exclusive < total)
            if truncated:
                _save_ckpt()
            else:
                _delete_ckpt()
            return _finish("not_found", truncated=truncated)
    except KeyboardInterrupt:
        _save_ckpt()
        return _finish("interrupted")
