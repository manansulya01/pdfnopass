"""Clean internal recovery-result object (privacy-first).

``RecoveryResult`` carries every field the CLI needs to display without
ever persisting secrets by itself: :meth:`to_safe_dict` drops the
recovered password unless the caller explicitly passes
``include_password=True`` (used only for the explicit ``--output-json``
export, which itself defaults to excluding it).

The engine keeps returning plain dicts (stable, tested API); use
:func:`result_from_dict` at the CLI boundary.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class RecoveryResult:
    """Internal result of a recovery run. Never written to disk by itself."""

    status: str  # found|not_found|interrupted|error|not_encrypted|gated
    password: Optional[str] = None
    tested_count: int = 0
    elapsed_seconds: float = 0.0
    attempts_per_second: float = 0.0
    search_space: Optional[int] = None
    encryption_info: Optional[Dict[str, Any]] = None
    stage: Optional[str] = None
    checkpoint_path: Optional[str] = None
    truncated: bool = False
    error: Optional[str] = None
    gate: Optional[Dict[str, Any]] = None
    stages: List[Dict[str, Any]] = field(default_factory=list)

    def to_safe_dict(self, include_password: bool = False) -> Dict[str, Any]:
        """Serializable view. The password is included ONLY on explicit request."""
        data = asdict(self)
        if not include_password:
            data.pop("password", None)
            # Per-stage engine dicts also carry a "password" on success;
            # strip those too so metadata-only exports never leak the secret.
            stages = data.get("stages")
            if isinstance(stages, list):
                for entry in stages:
                    if isinstance(entry, dict):
                        entry.pop("password", None)
        if data.get("encryption_info") is not None:
            # Belt-and-braces: pdf_tester already redacts O/U hashes, but a
            # result export must never carry raw hash material either.
            redacted = dict(data["encryption_info"])
            details = redacted.get("details")
            if isinstance(details, dict):
                redacted["details"] = {
                    k: ("<present>" if k in ("/O", "/U", "/OE", "/UE", "/Perms") else v)
                    for k, v in details.items()
                }
            data["encryption_info"] = redacted
        return data


def result_from_dict(data: Dict[str, Any],
                     encryption_info: Optional[Dict[str, Any]] = None,
                     checkpoint_path: Optional[str] = None,
                     stage: Optional[str] = None) -> RecoveryResult:
    """Convert an engine/runner result dict into a RecoveryResult.

    ``stage`` optionally overrides the stage label (engine dicts already
    carry one; ``run_auto`` dicts do not, so callers pass ``"auto"``).
    """
    tried = int(data.get("tried", 0) or 0)
    elapsed = float(data.get("elapsed", 0.0) or 0.0)
    rate = data.get("rate")
    if rate is None:
        rate = (tried / elapsed) if elapsed > 0 else 0.0
    resolved_stage = stage if stage is not None else data.get("stage")
    return RecoveryResult(
        status=str(data.get("status", "error")),
        password=data.get("password"),
        tested_count=tried,
        elapsed_seconds=elapsed,
        attempts_per_second=float(rate or 0.0),
        search_space=data.get("total"),
        encryption_info=encryption_info,
        stage=resolved_stage,
        checkpoint_path=checkpoint_path if checkpoint_path is not None else data.get("checkpoint"),
        truncated=bool(data.get("truncated", False)),
        error=data.get("error"),
        gate=data.get("gate"),
        stages=list(data.get("stages", []) or []),
    )
