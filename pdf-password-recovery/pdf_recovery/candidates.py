"""Candidate-password generation.

Sources, all local and explicit:

1. ``generate_variations`` — known-password variations from base phrases.
2. ``load_wordlist`` — passwords streamed from a local text file.
3. ``brute_force_candidates`` — narrowly scoped charset/length search.
4. Automatic (clue-free) enumeration — deterministic indexed search over
   named charsets (see ``CHARSET_PRESETS`` / ``resolve_charset`` /
   ``iter_indexed``). Used by ``--auto``; lazy and resumable.

All generators are lazy iterators except ``generate_variations`` which
returns a deduplicated list (variation spaces are expected to be small).
"""
from __future__ import annotations

import itertools
import string
from typing import Dict, Iterable, Iterator, List, Sequence, Tuple


# Small set of common numeric passwords appended when add_numbers=True.
# Kept separate from the 0..number_max-1 range so behaviour is explicit.
COMMON_NUMBERS: List[str] = ["123", "1234", "12345", "007", "000", "111", "999"]


# ---------------------------------------------------------------------------
# Named character sets for --auto / --brute.
# ---------------------------------------------------------------------------
CHARSET_PRESETS: Dict[str, str] = {
    "lower": string.ascii_lowercase,  # 26
    "upper": string.ascii_uppercase,  # 26
    "digits": string.digits,  # 10
    "letters": string.ascii_letters,  # 52
    "alphanumeric": string.ascii_letters + string.digits,  # 62
    "symbols": string.punctuation,  # 32  ("common printable symbols")
    # 94 printable ASCII chars without space (letters + digits + symbols).
    "printable": string.ascii_letters + string.digits + string.punctuation,
}

#: Default named set used by bare ``--auto`` (kept narrow on purpose).
DEFAULT_AUTO_CHARSET_NAME = "lower"


def _dedup_preserve_order(s: str) -> str:
    return "".join(dict.fromkeys(s))


def resolve_charset(
    specs: Sequence[str] | None = None,
    custom: str | None = None,
    default: str | None = None,
) -> str:
    """Resolve a charset from named specs and/or a custom string.

    Rules (backward compatible with the old ``--charset "abc123"`` literal):
    - If *custom* is non-empty, it wins and is returned deduped
      (order preserved).
    - Otherwise each entry of *specs* may be a single preset name or a
      comma-separated list of preset names (e.g. ``"lower"``,
      ``"lower,digits"``, ``"alphanumeric"``). A token matching a preset
      name (case-insensitive) expands to that preset; any other token is
      treated as literal characters. Results are concatenated and deduped.
    - If neither yields anything and *default* names a preset, that preset
      is returned. Otherwise ``""`` is returned (caller validates).
    """
    if custom:
        return _dedup_preserve_order(custom)
    combined = ""
    if specs:
        tokens: List[str] = []
        for spec in specs:
            if spec is None:
                continue
            for tok in str(spec).split(","):
                tok = tok.strip()
                if tok == "":
                    continue
                tokens.append(tok)
        for tok in tokens:
            key = tok.lower()
            if key in CHARSET_PRESETS:
                combined += CHARSET_PRESETS[key]
            else:
                # Backward compat: treat unknown token as literal chars
                # (supports old `--charset "abc123"` usage).
                combined += tok
    if combined:
        return _dedup_preserve_order(combined)
    if default and default.lower() in CHARSET_PRESETS:
        return CHARSET_PRESETS[default.lower()]
    return ""


def capitalization_variants(word: str) -> List[str]:
    """Return deterministic capitalization variants of *word*, deduped.

    Order: original, lower, upper, capitalized, title-cased.
    """
    variants = [
        word,
        word.lower(),
        word.upper(),
        word.capitalize(),
        word.title(),
    ]
    seen: List[str] = []
    for v in variants:
        if v not in seen:
            seen.append(v)
    return seen


def _with_numbers(suffixes: Sequence[str], add_numbers: bool, number_max: int) -> List[str]:
    base = list(suffixes) if suffixes else [""]
    if not add_numbers:
        return base
    extras: List[str] = []
    for i in range(max(0, number_max)):
        extras.append(str(i))
    extras.extend(COMMON_NUMBERS)
    merged = list(base)
    for e in extras:
        if e not in merged:
            merged.append(e)
    return merged


def estimate_variation_count(
    base_phrases: Sequence[str],
    capitalize: bool = True,
    separators: Sequence[str] = ("", "-", "_", "."),
    prefixes: Sequence[str] = ("",),
    suffixes: Sequence[str] = ("",),
    add_numbers: bool = True,
    number_max: int = 100,
) -> int:
    """Exact deduped total without generating (accounts for the ("", "")
    affix pair, which yields the bare core once regardless of separator)."""
    non_empty = [b for b in base_phrases if b != ""]
    if not non_empty:
        return 0
    seps = list(separators) if separators else [""]
    pres = list(prefixes) if prefixes else [""]
    sufs = _with_numbers(list(suffixes) if suffixes else [""], add_numbers, number_max)
    pairs = len(pres) * len(sufs)
    if "" in pres and "" in sufs:
        per_core = (pairs - 1) * len(seps) + 1
    else:
        per_core = pairs * len(seps)
    total = 0
    for base in non_empty:
        n_core = len(capitalization_variants(base)) if capitalize else 1
        total += n_core * per_core
    return total


def generate_variations(
    base_phrases: Iterable[str],
    capitalize: bool = True,
    separators: Sequence[str] = ("", "-", "_", "."),
    prefixes: Sequence[str] = ("",),
    suffixes: Sequence[str] = ("",),
    add_numbers: bool = True,
    number_max: int = 100,
) -> List[str]:
    """Generate known-password variations.

    Candidate shape for separator ``sep``::

        prefix + (sep if prefix) + CORE + (sep if suffix) + suffix

    where CORE ranges over capitalization variants of each base phrase.
    For example with prefix ``"my"``, core ``"dog"``, suffix ``"123"``
    and separator ``"-"`` the candidate is ``"my-dog-123"``; with
    separator ``""`` it is ``"mydog123"``.

    Returns a deduplicated list preserving generation order.
    """
    bases = [b for b in base_phrases if b != ""]
    if not bases:
        return []
    seps = list(separators) if separators else [""]
    pres = list(prefixes) if prefixes else [""]
    sufs = _with_numbers(list(suffixes) if suffixes else [""], add_numbers, number_max)

    out: List[str] = []
    seen = set()
    for base in bases:
        cores = capitalization_variants(base) if capitalize else [base]
        for core in cores:
            for pre in pres:
                for suf in sufs:
                    for sep in seps:
                        left = f"{pre}{sep}{core}" if pre else core
                        # Avoid doubling the separator logic: the same sep
                        # joins both sides, which covers the common cases
                        # ("mydog123", "my-dog-123", "my_dog_123", ...).
                        cand = f"{left}{sep}{suf}" if suf else left
                        if cand not in seen:
                            seen.add(cand)
                            out.append(cand)
    return out


def load_wordlist(path: str, encoding: str = "utf-8") -> Iterator[str]:
    """Lazily yield passwords from a local text file.

    Blank lines are skipped. Leading/trailing whitespace (including the
    trailing newline) is stripped. Lines starting with ``#`` are treated
    as comments and skipped so users can annotate local lists.
    Raises FileNotFoundError if the path does not exist.
    """
    with open(path, "r", encoding=encoding, errors="strict") as fh:
        for line in fh:
            pw = line.strip()
            if not pw:
                continue
            if pw.startswith("#"):
                continue
            yield pw


def count_wordlist(path: str, encoding: str = "utf-8") -> int:
    """Count testable candidates in a wordlist file (for progress totals)."""
    n = 0
    with open(path, "r", encoding=encoding, errors="strict") as fh:
        for line in fh:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            n += 1
    return n


def estimate_bruteforce_total(charset: str, min_length: int, max_length: int) -> int:
    """Return sum(len(charset)**n) for n in [min_length, max_length]."""
    k = len(set(charset))
    return sum(k**n for n in range(min_length, max_length + 1))


def brute_force_candidates(
    charset: str, min_length: int, max_length: int
) -> Iterator[str]:
    """Yield every string over *charset* with lengths min..max.

    Lexicographic order per length, shortest first. Raises ValueError on
    invalid parameters. Callers should keep this narrowly scoped: the
    search space grows as ``len(charset) ** length``.
    """
    if not charset:
        raise ValueError("charset must be non-empty")
    if min_length < 1:
        raise ValueError("min_length must be >= 1")
    if max_length < min_length:
        raise ValueError("max_length must be >= min_length")
    chars = list(charset)
    for length in range(min_length, max_length + 1):
        for tup in itertools.product(chars, repeat=length):
            yield "".join(tup)


# ---------------------------------------------------------------------------
# Deterministic indexed enumeration for --auto (resumable, lazy).
# ---------------------------------------------------------------------------

def auto_space_total(charset: str, min_length: int, max_length: int) -> int:
    """Theoretical search-space size: sum(k**n for n in min..max).

    Raises ValueError on invalid parameters.
    """
    if not charset:
        raise ValueError("charset must be non-empty")
    if min_length < 1:
        raise ValueError("min_length must be >= 1")
    if max_length < min_length:
        raise ValueError("max_length must be >= min_length")
    k = len(set(charset))
    return sum(k**n for n in range(min_length, max_length + 1))


def length_for_index(charset_size: int, min_length: int, max_length: int, index: int) -> int:
    """Return the password length owning global ordinal *index*.

    Ordinals are 0-based over lengths min..max in increasing order.
    Raises IndexError if out of range.
    """
    if index < 0:
        raise IndexError("index must be >= 0")
    remaining = index
    for length in range(min_length, max_length + 1):
        count = charset_size**length
        if remaining < count:
            return length
        remaining -= count
    raise IndexError("index out of range for search space")


def index_to_password(charset: str, min_length: int, max_length: int, index: int) -> Tuple[str, int]:
    """Convert global ordinal *index* to (password, length), deterministically.

    Order matches ``brute_force_candidates`` exactly: increasing length,
    lexicographic within a length following *charset* order. O(length).
    Raises IndexError if out of range, ValueError on bad params.
    """
    if not charset:
        raise ValueError("charset must be non-empty")
    k = len(charset)
    length = length_for_index(k, min_length, max_length, index)
    # Offset of index within its length block.
    base = sum(k**n for n in range(min_length, length))
    offset = index - base
    # Base-k conversion, most-significant char first.
    chars = [""] * length
    for pos in range(length - 1, -1, -1):
        chars[pos] = charset[offset % k]
        offset //= k
    return ("".join(chars), length)


def password_to_index(charset: str, min_length: int, max_length: int, password: str) -> int:
    """Inverse of ``index_to_password`` (for tests / checkpoint validation)."""
    if not charset:
        raise ValueError("charset must be non-empty")
    k = len(charset)
    length = len(password)
    if length < min_length or length > max_length:
        raise ValueError("password length outside search range")
    pos_of = {c: i for i, c in enumerate(charset)}
    offset = 0
    for ch in password:
        if ch not in pos_of:
            raise ValueError(f"character {ch!r} not in charset")
        offset = offset * k + pos_of[ch]
    base = sum(k**n for n in range(min_length, length))
    return base + offset


def iter_indexed(
    charset: str,
    min_length: int,
    max_length: int,
    start: int = 0,
) -> Iterator[Tuple[int, str, int]]:
    """Lazily yield (global_index, password, length) from *start* to end.

    Never materialises the space; each item costs O(length). Deterministic:
    the same (charset, lengths, index) always yields the same password, so
    interrupted searches resume without skipping or resampling.
    """
    total = auto_space_total(charset, min_length, max_length)
    if start < 0 or start > total:
        raise ValueError("start index out of range")
    for idx in range(start, total):
        pw, length = index_to_password(charset, min_length, max_length, idx)
        yield (idx, pw, length)


def load_bases_file(path: str, encoding: str = "utf-8") -> List[str]:
    """Load base phrases from a local text file (one per line)."""
    bases: List[str] = []
    with open(path, "r", encoding=encoding, errors="strict") as fh:
        for line in fh:
            s = line.strip()
            if s and not s.startswith("#"):
                bases.append(s)
    return bases
