"""Unified recovery engine: staged automatic recovery.

Stages (in order), all offline through the normal ``pypdf`` decrypt path:

1. Empty-password check (fast path for PDFs secured with a blank password).
2. Wordlist recovery (only when the user supplies ``--wordlist``).
3. Variation recovery (only when the user supplies ``--bases``/``--bases-file``).
4. Automatic exhaustive search (indexed ``charset^length`` enumeration) when
   no clues are supplied — or always as the final stage of ``recover``.

This module orchestrates the existing, tested components
(``pdf_tester``, ``runner.run_recovery``, ``auto.run_auto``); it does not
reimplement verification, enumeration, or checkpointing.
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional


def run_unified_recovery(
    pdf_path: str,
    charset: str,
    min_length: int,
    max_length: int,
    total: int,
    workers: int = 4,
    limit: Optional[int] = None,
    show_progress: bool = True,
    checkpoint_path: Optional[str] = None,
    checkpoint_meta: Optional[Dict] = None,
    start_index: int = 0,
    wordlist_path: Optional[str] = None,
    wordlist_encoding: str = "utf-8",
    base_phrases: Optional[List[str]] = None,
    variation_kwargs: Optional[Dict] = None,
    skip_empty_check: bool = False,
    auto_gate: bool = True,
    force: bool = False,
    bench_samples: int = 12,
    bench_cache_path: Optional[str] = None,
) -> Dict:
    """Run staged recovery. Returns unified result dict.

    Result keys: status (found|not_found|interrupted|error|not_encrypted|
    gated), password, stage (empty|wordlist|variations|auto|None), tried
    (across stages), total (auto space), elapsed, truncated, error, gate
    (prestart decision details when the automatic stage was gated),
    stages (list of per-stage summaries). ``gated`` means the automatic
    stage was NOT started: rerun with ``force=True`` (``--force``) to allow
    it. The original PDF is only read, never modified.
    """
    from .auto import run_auto
    from .candidates import count_wordlist, generate_variations, load_wordlist
    from .pdf_tester import (
        PdfMalformedError,
        PdfNotFoundError,
        PdfUnsupportedEncryptionError,
        get_encryption_info,
        try_password,
    )
    from .runner import run_recovery

    t0 = time.monotonic()
    tried_total = 0
    stage_log: List[Dict] = []
    method: Optional[str] = None

    def _budget() -> Optional[int]:
        if limit is None:
            return None
        return max(0, limit - tried_total)

    # Pre-check encryption state (read-only).
    try:
        info = get_encryption_info(pdf_path)
    except PdfNotFoundError as e:
        return _done("error", None, None, tried_total, t0, total, False, str(e), stage_log)
    except PdfUnsupportedEncryptionError as e:
        return _done("error", None, None, tried_total, t0, total, False,
                      f"unsupported encryption: {e}", stage_log)
    except PdfMalformedError as e:
        return _done("error", None, None, tried_total, t0, total, False,
                      f"malformed PDF: {e}", stage_log)
    except Exception as e:
        return _done("error", None, None, tried_total, t0, total, False, str(e), stage_log)
    if not info.get("encrypted"):
        return _done("not_encrypted", None, None, tried_total, t0, total, False, None, stage_log)
    method = info.get("method")

    # Stage 1: empty-password fast path.
    if not skip_empty_check:
        try:
            if try_password(pdf_path, ""):
                tried_total += 1
                stage_log.append({"stage": "empty", "status": "found", "tried": 1})
                return _done("found", "", "empty", tried_total, t0, total, False, None, stage_log)
            tried_total += 1
            stage_log.append({"stage": "empty", "status": "not_found", "tried": 1})
        except (PdfUnsupportedEncryptionError,) as e:
            return _done("error", None, "empty", tried_total, t0, total, False,
                          f"unsupported encryption: {e}", stage_log)
        except (PdfMalformedError, PdfNotFoundError) as e:
            return _done("error", None, "empty", tried_total, t0, total, False, str(e), stage_log)
        if _budget() is not None and _budget() <= 0:
            return _done("not_found", None, None, tried_total, t0, total, True, None, stage_log)

    # Stage 2: wordlist (only with user-supplied list).
    if wordlist_path:
        budget = _budget()
        try:
            entries = count_wordlist(wordlist_path, encoding=wordlist_encoding)
            _ = entries  # FYI only; stream lazily below
        except (FileNotFoundError, UnicodeDecodeError, OSError) as e:
            return _done("error", None, "wordlist", tried_total, t0, total, False,
                          f"cannot read wordlist: {e}", stage_log)
        res = run_recovery(
            pdf_path,
            load_wordlist(wordlist_path, encoding=wordlist_encoding),
            workers=workers,
            total=None,
            limit=budget,
            show_progress=show_progress,
            desc="Wordlist",
            dedup=True,
        )
        tried_total += res["tried"]
        stage_log.append({"stage": "wordlist", **res})
        if res["status"] == "found":
            return _done("found", res["password"], "wordlist", tried_total, t0, total, False, None, stage_log)
        if res["status"] == "interrupted":
            return _done("interrupted", None, "wordlist", tried_total, t0, total, False, None, stage_log)
        if res["status"] == "error":
            return _done("error", None, "wordlist", tried_total, t0, total, False, res.get("error"), stage_log)
        if res.get("truncated"):
            return _done("not_found", None, "wordlist", tried_total, t0, total, True, None, stage_log)

    # Stage 3: variations (only with user-supplied bases).
    if base_phrases:
        budget = _budget()
        vkw = variation_kwargs or {}
        variations = generate_variations(
            base_phrases,
            capitalize=vkw.get("capitalize", True),
            separators=vkw.get("separators", ["", "-", "_", "."]),
            prefixes=vkw.get("prefixes", [""]),
            suffixes=vkw.get("suffixes", [""]),
            add_numbers=vkw.get("add_numbers", True),
            number_max=vkw.get("number_max", 100),
        )
        # Honour cross-stage budget without materialising a second copy.
        candidates: object = iter(variations)
        if budget is not None:
            import itertools as _it

            candidates = _it.islice(iter(variations), budget)
        res = run_recovery(
            pdf_path,
            candidates,  # type: ignore[arg-type]
            workers=workers,
            total=min(len(variations), budget) if budget is not None else len(variations),
            limit=None,  # already sliced
            show_progress=show_progress,
            desc="Variations",
            dedup=True,
        )
        tried_total += res["tried"]
        if budget is not None and res["tried"] >= budget and res["status"] != "found":
            stage_log.append({"stage": "variations", **res})
            return _done("not_found", None, "variations", tried_total, t0, total, True, None, stage_log)
        stage_log.append({"stage": "variations", **res})
        if res["status"] == "found":
            return _done("found", res["password"], "variations", tried_total, t0, total, False, None, stage_log)
        if res["status"] == "interrupted":
            return _done("interrupted", None, "variations", tried_total, t0, total, False, None, stage_log)
        if res["status"] == "error":
            return _done("error", None, "variations", tried_total, t0, total, False, res.get("error"), stage_log)

    # Stage 4: automatic exhaustive search (gated unless forced).
    if auto_gate and not force:
        from .benchmark import prestart_decision

        gate_remaining = max(0, total - start_index)
        if limit is not None:
            # A user-imposed cap bounds the actual work; gate on that.
            gate_remaining = min(gate_remaining, limit)
        decision = prestart_decision(
            pdf_path, method, len(set(charset)), gate_remaining,
            workers_probe=1, samples=bench_samples,
            cache_path=bench_cache_path, force=False,
        )
        if decision.get("error"):
            return _done("error", None, "auto", tried_total, t0, total, False,
                          decision["error"], stage_log, gate=decision)
        if not decision.get("proceed"):
            # Deliberately do NOT start (or checkpoint) the huge search.
            return _done("gated", None, "auto", tried_total, t0, total, False,
                          None, stage_log, gate=decision)
    budget = _budget()
    res = run_auto(
        pdf_path,
        charset,
        min_length,
        max_length,
        total,
        start_index=start_index,
        workers=workers,
        limit=budget,
        show_progress=show_progress,
        checkpoint_path=checkpoint_path,
        checkpoint_meta=checkpoint_meta,
    )
    tried_total += res["tried"]
    stage_log.append({"stage": "auto", **res})
    if res["status"] == "found":
        return _done("found", res["password"], "auto", tried_total, t0, total, False, None, stage_log)
    if res["status"] == "interrupted":
        return _done("interrupted", None, "auto", tried_total, t0, total, False, None, stage_log)
    if res["status"] == "error":
        return _done("error", None, "auto", tried_total, t0, total, False, res.get("error"), stage_log)
    return _done("not_found", None, "auto", tried_total, t0, total,
                 bool(res.get("truncated")), None, stage_log)


def _done(status, password, stage, tried, t0, total, truncated, error, stages,
          gate=None):
    return {
        "status": status,
        "password": password,
        "stage": stage,
        "tried": tried,
        "total": total,
        "elapsed": time.monotonic() - t0,
        "truncated": truncated,
        "error": error,
        "gate": gate,
        "stages": stages,
    }
