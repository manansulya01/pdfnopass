"""Configuration container for recovery runs.

All recovery parameters are explicit and user-controlled. Nothing is
fetched from the network; everything runs locally.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class RecoveryConfig:
    """User-controlled parameters for a recovery run."""

    pdf_path: str
    # Candidate sources. Any combination may be set; at least one is
    # required unless check_only is True.
    wordlist_path: Optional[str] = None
    wordlist_encoding: str = "utf-8"
    base_phrases: List[str] = field(default_factory=list)
    bases_file: Optional[str] = None
    # Variation options (mode 1).
    capitalize: bool = True
    separators: List[str] = field(default_factory=lambda: ["", "-", "_", "."])
    prefixes: List[str] = field(default_factory=lambda: [""])
    suffixes: List[str] = field(default_factory=lambda: [""])
    add_numbers: bool = True
    number_max: int = 100  # adds "0" .. "99" as extra suffixes when add_numbers
    # Brute-force options (narrowly scoped, explicit).
    brute: bool = False
    charset: str = ""  # resolved charset string (deduped, order-preserved)
    min_length: int = 1
    max_length: int = 0
    # Automatic clue-free mode (--auto).
    auto: bool = False
    charset_specs: List[str] = field(default_factory=list)  # raw --charset values
    charset_custom: Optional[str] = None  # --charset-custom value
    checkpoint_path: Optional[str] = None
    status_only: bool = False
    reset_checkpoint: bool = False
    # Execution options.
    workers: int = 4
    limit: Optional[int] = None  # max candidates to test (safety cap)
    show_progress: bool = True

    def validate(self) -> List[str]:
        """Return a list of validation error strings (empty == valid)."""
        errors: List[str] = []
        if not self.pdf_path:
            errors.append("--pdf is required.")
        if self.workers < 1:
            errors.append("--workers must be >= 1.")
        if self.min_length < 1:
            errors.append("--min-length must be >= 1.")
        if self.brute:
            if not self.charset:
                errors.append("--brute requires --charset to be set explicitly.")
            if self.max_length < self.min_length:
                errors.append("--max-length must be >= --min-length.")
            if len(set(self.charset)) == 0:
                errors.append("--charset must contain at least one character.")
        if self.auto:
            if not self.charset:
                errors.append("--auto requires a non-empty charset (use --charset or --charset-custom).")
            if self.max_length < self.min_length:
                errors.append("--auto requires --max-length >= --min-length.")
            if len(set(self.charset)) == 0:
                errors.append("--auto charset must contain at least one character.")
        if self.number_max < 0 or self.number_max > 100000:
            errors.append("--number-max must be in range 0..100000.")
        if self.limit is not None and self.limit < 1:
            errors.append("--limit must be >= 1.")
        return errors
