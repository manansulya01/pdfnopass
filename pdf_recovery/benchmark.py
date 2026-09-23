"""Offline throughput benchmark for PDF password verification.

Measures the *actual* local ``try_password`` rate (CPU-only; no GPU is
claimed or used) so users get honest duration estimates for a configured
search space instead of pretending every password is recoverable.

Everything is read-only and offline: candidate strings are synthetic
(``__bench_N__``) and the target PDF is only opened via the normal
``pypdf`` decrypt path. Small probe results can be cached per
PDF/encryption/workers so repeated safety checks stay instant.
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional


#: Safety-gate defaults: an automatic search over more candidates than this,
#: or estimated longer than this, requires explicit ``--force``.
AUTO_GATE_SIZE_LIMIT = 10_000_000
AUTO_GATE_TIME_LIMIT_SECONDS = 7200.0
#: Quick prestart probe size (sequential, ~a tenth of a second).
GATE_PROBE_SAMPLES = 12
BENCHMARK_CACHE_VERSION = 1


def format_duration(seconds: float) -> str:
    """Human duration, e.g. 90 -> '1m 30s', 90000 -> '1d 1h'."""
    if seconds != seconds or seconds < 0:  # NaN guard
        return "unknown"
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    m, s = divmod(s, 60)
    if m < 60:
        return f"{m}m {s}s"
    h, m = divmod(m, 60)
    if h < 48:
        return f"{h}h {m}m"
    d, h = divmod(h, 24)
    if d < 730:
        return f"{d}d {h}h"
    y, d = divmod(d, 365)
    return f"{y}y {d}d"


def estimate_seconds(total_candidates: int, rate_per_sec: float) -> float:
    """Estimated seconds to test total_candidates at rate_per_sec."""
    if rate_per_sec <= 0:
        return float("inf")
    return total_candidates / rate_per_sec


def feasibility_verdict(total_candidates: int, rate_per_sec: float) -> str:
    """Honest feasibility sentence for a space at a measured rate.

    Never promises recovery; strong random passwords are infeasible.
    """
    secs = estimate_seconds(total_candidates, rate_per_sec)
    if secs == float("inf"):
        return "cannot estimate (no measured throughput)"
    if secs > 365 * 86400:
        return (
            f"computationally INFEASIBLE by exhaustive search "
            f"(~{format_duration(secs)} at {rate_per_sec:.0f}/s; "
            f"strong random passwords of this size cannot realistically be recovered)"
        )
    if secs > 30 * 86400:
        return (
            f"likely infeasible (~{format_duration(secs)} at {rate_per_sec:.0f}/s); "
            f"narrow the charset/length range or supply clues"
        )
    if secs > 86400:
        return f"very long (~{format_duration(secs)} at {rate_per_sec:.0f}/s)"
    if secs > 3600:
        return f"long (~{format_duration(secs)} at {rate_per_sec:.0f}/s)"
    return f"~{format_duration(secs)} at {rate_per_sec:.0f}/s"


def measure_throughput(
    pdf_path: str,
    workers: int = 1,
    samples: int = 20,
    show_progress: bool = False,
) -> Dict:
    """Measure real verification throughput against *pdf_path*.

    Tests *samples* guaranteed-wrong synthetic passwords through the normal
    decrypt path. With workers>1 uses the same bounded multiprocess path as
    recovery; workers<=1 is sequential. Returns
    {"samples","elapsed","rate","workers"}.
    """
    from .pdf_tester import try_password

    if samples < 1:
        raise ValueError("samples must be >= 1")
    if workers < 1:
        raise ValueError("workers must be >= 1")
    candidates: List[str] = [f"__bench_{i:06d}__" for i in range(samples)]
    start = time.monotonic()
    if workers <= 1:
        for pw in candidates:
            try_password(pdf_path, pw)
    else:
        import concurrent.futures

        from .runner import _check_one

        max_in_flight = max(workers * 4, 8)
        with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as ex:
            pending = set()
            it = iter(candidates)

            def fill():
                while len(pending) < max_in_flight:
                    try:
                        pw = next(it)
                    except StopIteration:
                        break
                    pending.add(ex.submit(_check_one, (pdf_path, pw)))

            fill()
            while pending:
                done, _ = concurrent.futures.wait(
                    list(pending), return_when=concurrent.futures.FIRST_COMPLETED
                )
                for fut in done:
                    pending.discard(fut)
                    try:
                        fut.result()
                    except Exception:
                        pass
                fill()
    elapsed = time.monotonic() - start
    rate = (samples / elapsed) if elapsed > 0 else 0.0
    return {"samples": samples, "elapsed": elapsed, "rate": rate, "workers": workers}


def benchmark_report(
    pdf_path: str,
    total_candidates: Optional[int] = None,
    charset_size: Optional[int] = None,
    min_length: Optional[int] = None,
    max_length: Optional[int] = None,
    workers: int = 1,
    samples: int = 20,
) -> Dict:
    """Measure throughput and (optionally) project a configured space.

    Returns {"throughput": {...}, "total":..., "seconds":...,
    "duration":..., "verdict":...}. Pure computation + local verification.
    """
    throughput = measure_throughput(pdf_path, workers=workers, samples=samples)
    out: Dict = {"throughput": throughput, "total": total_candidates}
    if total_candidates is not None:
        secs = estimate_seconds(total_candidates, throughput["rate"])
        out["seconds"] = secs
        out["duration"] = format_duration(secs)
        out["verdict"] = feasibility_verdict(total_candidates, throughput["rate"])
    else:
        out["seconds"] = None
        out["duration"] = None
        out["verdict"] = None
    out.update(
        {"charset_size": charset_size, "min_length": min_length, "max_length": max_length}
    )
    return out


# ---------------------------------------------------------------------------
# Cached probes + prestart safety gate.
# ---------------------------------------------------------------------------

def default_benchmark_cache_path(checkpoint_path: str) -> str:
    """Cache location derived from the checkpoint path (same directory)."""
    return f"{checkpoint_path}.benchmark.json"


def _utcnow() -> str:
    import datetime

    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def load_benchmark_cache(path: str, pdf_path: str, method: Optional[str],
                         workers: int) -> Optional[float]:
    """Return cached probes/sec when the entry matches, else None.

    Match key: absolute PDF path + encryption method label + worker count.
    No TTL: encryption parameters of a file are immutable, and the stored
    rate is only used for conservative planning estimates.
    """
    import json
    import os

    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except (OSError, ValueError):
        return None
    try:
        if not isinstance(data, dict):
            return None
        if data.get("pdf") != os.path.abspath(pdf_path):
            return None
        if data.get("method") != (method or ""):
            return None
        if int(data.get("workers", -1)) != int(workers):
            return None
        rate = float(data.get("rate", 0))
        return rate if rate > 0 else None
    except (TypeError, ValueError):
        return None


def store_benchmark_cache(path: str, pdf_path: str, method: Optional[str],
                          workers: int, rate: float, samples: int,
                          elapsed: float) -> None:
    """Atomically store a probe result (best effort; never raises)."""
    import os

    try:
        from .checkpoint import save_checkpoint

        save_checkpoint(path, {
            "version": BENCHMARK_CACHE_VERSION,
            "pdf": os.path.abspath(pdf_path),
            "method": method or "",
            "workers": int(workers),
            "rate": float(rate),
            "samples": int(samples),
            "elapsed": float(elapsed),
            "updated": _utcnow(),
        })
    except OSError:
        pass
    except Exception:
        pass


def prestart_decision(
    pdf_path: str,
    method: Optional[str],
    charset_size: int,
    remaining: int,
    workers_probe: int = 1,
    samples: int = GATE_PROBE_SAMPLES,
    cache_path: Optional[str] = None,
    force: bool = False,
    size_limit: int = AUTO_GATE_SIZE_LIMIT,
    time_limit: float = AUTO_GATE_TIME_LIMIT_SECONDS,
) -> Dict:
    """Decide whether an automatic search may start without ``--force``.

    Measures (or reuses a cached) conservative single-worker probe rate,
    then estimates ``remaining / rate``. Returns dict with ``proceed`` bool
    plus ``rate/seconds/duration/verdict/cached/reason`` (and ``error`` when
    the PDF cannot even be probed). ``force=True`` short-circuits to proceed
    without measuring. Never raises for PDF problems (reports ``error``);
    never touches the network; never modifies the PDF.
    """
    if force:
        return {"proceed": True, "forced": True, "cached": False,
                "rate": None, "seconds": None, "duration": None,
                "verdict": None, "remaining": remaining,
                "reason": "explicit --force", "error": None}
    if remaining <= 0:
        return {"proceed": True, "forced": False, "cached": False,
                "rate": None, "seconds": 0.0, "duration": format_duration(0),
                "verdict": "nothing remaining", "remaining": remaining,
                "reason": "nothing remaining", "error": None}
    rate: Optional[float] = None
    cached = False
    if cache_path:
        rate = load_benchmark_cache(cache_path, pdf_path, method, workers_probe)
        cached = rate is not None
    if rate is None:
        try:
            measured = measure_throughput(pdf_path, workers=workers_probe,
                                          samples=samples)
        except KeyboardInterrupt:
            raise
        except Exception as exc:  # malformed/unsupported/gone since precheck
            return {"proceed": False, "forced": False, "cached": False,
                    "rate": None, "seconds": None, "duration": None,
                    "verdict": None, "remaining": remaining,
                    "reason": "probe failed", "error": str(exc)}
        rate = measured["rate"]
        if cache_path and rate > 0:
            store_benchmark_cache(cache_path, pdf_path, method, workers_probe,
                                  rate, measured["samples"], measured["elapsed"])
    if rate is None or rate <= 0:
        # No measurable rate: fall back to the size rule only.
        if remaining > size_limit:
            return {"proceed": False, "forced": False, "cached": cached,
                    "rate": rate, "seconds": None, "duration": None,
                    "verdict": None, "remaining": remaining,
                    "reason": f"{remaining:,} candidates exceeds {size_limit:,} "
                              f"with no measurable throughput", "error": None}
        return {"proceed": True, "forced": False, "cached": cached,
                "rate": rate, "seconds": None, "duration": None,
                "verdict": None, "remaining": remaining,
                "reason": "small space", "error": None}
    seconds = estimate_seconds(remaining, rate)
    verdict = feasibility_verdict(remaining, rate)
    if remaining > size_limit or seconds > time_limit:
        return {"proceed": False, "forced": False, "cached": cached,
                "rate": rate, "seconds": seconds,
                "duration": format_duration(seconds), "verdict": verdict,
                "remaining": remaining,
                "reason": f"~{format_duration(seconds)} at {rate:.0f}/s "
                          f"for {remaining:,} candidates", "error": None}
    return {"proceed": True, "forced": False, "cached": cached,
            "rate": rate, "seconds": seconds,
            "duration": format_duration(seconds), "verdict": verdict,
            "remaining": remaining, "reason": "within limits", "error": None}
