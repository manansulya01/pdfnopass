"""Command-line interface for the offline PDF password-recovery utility."""
from __future__ import annotations

import argparse
import itertools
import os
import sys
from typing import List, Optional

from . import OWNERSHIP_WARNING
from .candidates import (
    CHARSET_PRESETS,
    DEFAULT_AUTO_CHARSET_NAME,
    auto_space_total,
    brute_force_candidates,
    count_wordlist,
    estimate_bruteforce_total,
    generate_variations,
    load_bases_file,
    load_wordlist,
    resolve_charset,
)
from .config import RecoveryConfig
from .pdf_tester import (
    PdfMalformedError,
    PdfNotFoundError,
    PdfRecoveryError,
    PdfUnsupportedEncryptionError,
    get_encryption_info,
)
from .runner import run_recovery


def _parse_csv(value: str) -> List[str]:
    if value is None or value == "":
        return []
    return [p for p in (part for part in value.split(","))]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdf-recovery",
        description=(
            "Universal local, offline PDF password-recovery for PDFs you own or are "
            "explicitly authorized to access. Usage: "
            "'python -m pdf_recovery recover --pdf document.pdf' (automatic), or "
            "legacy flags ('--pdf document.pdf --auto'). Tests candidate passwords via "
            "normal PDF decryption only. Never uploads anything; "
            "works fully offline."
        ),
        epilog=OWNERSHIP_WARNING,
    )
    p.add_argument("--pdf", default=None,
                   help="Path to the PDF file (read-only, never modified). Required "
                        "except with --version/--help.")
    p.add_argument("--check-only", action="store_true",
                   help="Only report whether the PDF is encrypted, then exit.")
    p.add_argument("--wordlist", default=None,
                   help="Path to a local text file with one password per line.")
    p.add_argument("--wordlist-encoding", default="utf-8")
    p.add_argument("--bases", default=None,
                   help='Comma-separated base phrases, e.g. --bases "mydog,sunshine,1998"')
    p.add_argument("--bases-file", default=None,
                   help="Local text file with one base phrase per line.")
    p.add_argument("--no-capitalization", action="store_true",
                   help="Disable capitalization variants (default: enabled).")
    p.add_argument("--separators", default="-,_,.",
                   help='Comma-separated separators. "" (empty entry) means no separator. '
                        'Default: "-,_,." plus implicit no-separator. '
                        'NOTE: value starts with "-", so use the = form: '
                        '--separators="-,_,."')
    p.add_argument("--prefixes", default="",
                   help='Comma-separated prefixes, e.g. --prefixes "my,the". Default: none.')
    p.add_argument("--suffixes", default="",
                   help='Comma-separated suffixes, e.g. --suffixes "123,!,2024". Default: none.')
    p.add_argument("--no-add-numbers", action="store_true",
                   help="Do not auto-add numeric suffixes 0..number-max-1 + common numbers.")
    p.add_argument("--number-max", type=int, default=100,
                   help="Upper bound (exclusive) for auto numeric suffixes. Default 100.")
    p.add_argument("--brute", action="store_true",
                   help="Enable narrowly scoped brute-force search (requires --charset + --max-length).")
    p.add_argument("--charset", action="append", default=None,
                   help=('Named charset(s) for --brute/--auto: lower, upper, digits, '
                         'letters, alphanumeric, symbols, printable. Repeatable and '
                         'comma-combinable, e.g. --charset alphanumeric or '
                         '--charset lower,digits or --charset lower --charset digits. '
                         'Unknown values are treated as literal characters for '
                         'backward compatibility (e.g. --charset "abc123"). '
                         'See also --charset-custom.'))
    p.add_argument("--charset-custom", default=None,
                   help='Custom charset string, e.g. --charset-custom "abc123". '
                        'Overrides --charset when both are given.')
    p.add_argument("--auto", action="store_true",
                   help="Fully automatic clue-free search by increasing length. "
                        "Defaults: --charset lower --min-length 1 --max-length 4. "
                        "Checkpoints to '<pdf>.auto-checkpoint.json' for resume.")
    p.add_argument("--checkpoint", default=None,
                   help="Custom checkpoint file path for --auto "
                        "(default: '<pdf>.auto-checkpoint.json').")
    p.add_argument("--status", action="store_true",
                   help="Inspect the existing --auto checkpoint for --pdf and exit.")
    p.add_argument("--reset", action="store_true",
                   help="Discard the --auto checkpoint and restart fresh "
                        "(with --auto) or just discard (without --auto).")
    p.add_argument("--min-length", type=int, default=1)
    p.add_argument("--max-length", type=int, default=0,
                   help="Maximum length (required with --brute; defaults to 4 with --auto). Keep small!")
    p.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 4) - 0),
                   help="Worker process count. Default: CPU count. Use 1 for sequential.")
    p.add_argument("--limit", type=int, default=None,
                   help="Safety cap: maximum candidates to test.")
    p.add_argument("--force", action="store_true",
                   help="Explicitly allow a large automatic search stopped by the "
                        "prestart safety check. Without --force, an extremely large "
                        "search prints its estimated duration and the exact command "
                        "to rerun with --force, instead of starting silently.")
    p.add_argument("--benchmark", action="store_true",
                   help="Measure actual local verification throughput (CPU-only, no GPU) "
                        "and estimate the configured search duration, then exit without searching.")
    p.add_argument("--bench-samples", type=int, default=30,
                   help="Benchmark sample count (default 30). Small values are faster but noisier.")
    p.add_argument("--config", default=None,
                   help="Optional JSON/TOML config file with defaults (workers, charset, "
                        "min/max length, progress, checkpoint dir). CLI arguments override it. "
                        "Falls back to the platform config location when present.")
    p.add_argument("--output-json", default=None, metavar="PATH",
                   help="Write the recovery result metadata to PATH (atomic JSON). The "
                        "recovered password is EXCLUDED unless --include-password is given.")
    p.add_argument("--include-password", action="store_true",
                   help="Include the recovered password in --output-json. Only use with "
                        "explicit user request; never the default.")
    p.add_argument("--verbose", action="store_true",
                   help="Print extra non-sensitive diagnostics (encryption details, "
                        "resolved settings). Candidate passwords are never logged.")
    p.add_argument("--log-file", default=None, metavar="PATH",
                   help="Append non-sensitive diagnostics to PATH. Passwords and "
                        "candidates are never written to the log.")
    p.add_argument("--no-progress", action="store_true", help="Disable progress bar.")
    p.add_argument("--version", action="store_true", help="Print version and exit.")
    return p


def _parse_separators(raw: str) -> List[str]:
    # Raw is comma-separated; an empty entry means "". Always include "".
    parts = raw.split(",") if raw is not None else []
    seps: List[str] = []
    for part in parts:
        if part not in seps:
            seps.append(part)
    if "" not in seps:
        seps.insert(0, "")
    return seps


def _fmt_int(n) -> str:
    """Thousands-separated integer for displays (1,240,531)."""
    try:
        return f"{int(n):,}"
    except (TypeError, ValueError):
        return str(n)


def _fmt_elapsed(seconds: float) -> str:
    """Compact elapsed time: 00:42, 01:02:03."""
    try:
        total = max(0, int(seconds))
    except (TypeError, ValueError):
        return str(seconds)
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def _apply_config_file(args, parser) -> None:
    """Load optional config file; CLI arguments always win.

    Prints warnings for ignored keys; returns exit code 1 via SystemExit-free
    error printing is handled by the caller pattern: raises ValueError with a
    ready message on fatal config errors.
    """
    from .config_file import (
        coerce_config_types,
        default_config_path,
        load_config_file,
        split_config,
    )

    source = getattr(args, "config", None)
    data = None
    if source:
        try:
            data = load_config_file(source)
        except (FileNotFoundError, ValueError) as exc:
            print(f"Error: invalid configuration: {exc}", file=sys.stderr)
            raise _ConfigError() from exc
    else:
        default = default_config_path()
        if os.path.exists(default):
            try:
                data = load_config_file(default)
            except ValueError as exc:
                print(f"Warning: ignoring unreadable config {default}: {exc}",
                      file=sys.stderr)
                return
            source = default
    if data is None:
        return
    usable, warnings = split_config(data)
    for warning in warnings:
        print(f"Warning: config {source}: {warning}", file=sys.stderr)
    clean, errors = coerce_config_types(usable, source)
    if errors:
        for err in errors:
            print(f"Error: {err}", file=sys.stderr)
        raise _ConfigError()
    # Apply only where the CLI left parser defaults in place.
    if clean.get("workers") is not None and args.workers == parser.get_default("workers"):
        args.workers = clean["workers"]
    if clean.get("min_length") is not None and args.min_length == parser.get_default("min_length"):
        args.min_length = clean["min_length"]
    if clean.get("max_length") is not None and args.max_length == parser.get_default("max_length"):
        args.max_length = clean["max_length"]
    if clean.get("no_progress") and not args.no_progress:
        args.no_progress = True
    if clean.get("verbose") and not args.verbose:
        args.verbose = True
    if clean.get("charset") and not args.charset and not args.charset_custom:
        args.charset = [clean["charset"]]
    if clean.get("charset_custom") and not args.charset_custom:
        args.charset_custom = clean["charset_custom"]
    if clean.get("checkpoint_dir") and not args.checkpoint:
        args.checkpoint_dir = clean["checkpoint_dir"]
    if getattr(args, "verbose", False):
        _diag(args, f"Config: using defaults from {source} "
                     f"({', '.join(sorted(clean)) or 'no overrides'})")


class _ConfigError(Exception):
    """Fatal configuration error (message already printed; exit 1)."""


def _print_header(rows) -> None:
    """Print the recovery header (stdout, human readable, padded labels)."""
    rows = list(rows)
    width = max([len(str(k)) for k, _ in rows] + [10])
    for key, value in rows:
        print(f"{str(key):<{width}}  {value}")


def _diag(args, msg: str) -> None:
    """Non-sensitive diagnostics: stderr always, log file when requested.

    Candidate passwords and the recovered password NEVER flow through here;
    they are printed directly to stdout only on success.
    """
    print(msg, file=sys.stderr)
    path = getattr(args, "log_file", None)
    if path:
        try:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(msg + "\n")
        except OSError as exc:
            print(f"Warning: cannot write log file {path}: {exc}", file=sys.stderr)


def _pdf_fingerprint(pdf_path: str):
    """File fingerprint for checkpoint validation (None when unreadable)."""
    try:
        from .checkpoint import fingerprint_pdf

        return fingerprint_pdf(pdf_path)
    except OSError:
        return None


def _resolve_checkpoint(args) -> str:
    """Checkpoint path: --checkpoint, config checkpoint_dir, or PDF default."""
    from .checkpoint import default_checkpoint_path

    if getattr(args, "checkpoint", None):
        return args.checkpoint
    cdir = getattr(args, "checkpoint_dir", None)
    if cdir:
        return os.path.join(cdir, os.path.basename(args.pdf) + ".auto-checkpoint.json")
    return default_checkpoint_path(args.pdf)


def _maybe_write_output(args, result_obj) -> None:
    """Explicit result export. Password excluded unless --include-password."""
    if not getattr(args, "output_json", None):
        return
    payload = result_obj.to_safe_dict(
        include_password=bool(getattr(args, "include_password", False)))
    try:
        from .checkpoint import save_checkpoint

        save_checkpoint(args.output_json, payload)  # atomic tmp+rename
    except OSError as exc:
        print(f"Warning: cannot write output file {args.output_json}: {exc}",
              file=sys.stderr)
        return
    print(f"Result written to: {args.output_json}", file=sys.stderr)


def _quote_arg(s: str) -> str:
    """Minimal shell quoting for echoed commands."""
    s = str(s)
    if not s or any(c in s for c in ' \t\n"\'$`\\'):
        return '"' + s.replace('"', '\\"') + '"'
    return s


def _exact_auto_command(args, specs: List[str], custom: Optional[str],
                        min_len: int, max_len: int) -> str:
    parts = ["python", "-m", "pdf_recovery", "--pdf", _quote_arg(args.pdf),
             "--auto", "--force"]
    if custom:
        parts += ["--charset-custom", _quote_arg(custom)]
    elif specs:
        joined = ",".join(s for chunk in specs for s in str(chunk).split(",") if s.strip())
        parts += ["--charset", joined or ",".join(specs)]
    parts += ["--min-length", str(min_len), "--max-length", str(max_len),
              "--workers", str(args.workers)]
    if args.limit is not None:
        parts += ["--limit", str(args.limit)]
    if args.checkpoint:
        parts += ["--checkpoint", _quote_arg(args.checkpoint)]
    return " ".join(parts)


def _exact_recover_command(args, specs: List[str], custom: Optional[str],
                           min_len: int, max_len: int) -> str:
    parts = ["python", "-m", "pdf_recovery", "recover", "--pdf", _quote_arg(args.pdf),
             "--auto", "--force"]
    if args.wordlist:
        parts += ["--wordlist", _quote_arg(args.wordlist)]
    if args.bases:
        parts += ["--bases", _quote_arg(args.bases)]
    if args.bases_file:
        parts += ["--bases-file", _quote_arg(args.bases_file)]
    if custom:
        parts += ["--charset-custom", _quote_arg(custom)]
    elif specs:
        joined = ",".join(s for chunk in specs for s in str(chunk).split(",") if s.strip())
        parts += ["--charset", joined or ",".join(specs)]
    parts += ["--min-length", str(min_len), "--max-length", str(max_len),
              "--workers", str(args.workers)]
    if args.limit is not None:
        parts += ["--limit", str(args.limit)]
    if args.checkpoint:
        parts += ["--checkpoint", _quote_arg(args.checkpoint)]
    return " ".join(parts)


def _print_gated(cmd: str, total: int, remaining: int, decision) -> None:
    """STOP block for gated searches: duration + exact rerun command."""
    print("AUTOMATIC SEARCH GATED")
    print(f"The automatic search space is extremely large ({remaining:,} of {total:,} "
          f"candidates remaining) and is estimated to take "
          f"{decision.get('duration')} at {decision.get('rate', 0):.0f} attempts/sec "
          f"(measured locally, CPU-only).")
    print("It was NOT started, to avoid silently consuming this machine.")
    print("Strong random passwords of this size cannot realistically be recovered.")
    print("To explicitly start it, run:")
    print(f"  {cmd}")
    print("Result: GATED (use --force to start; checkpoint untouched).", file=sys.stderr)


def main(argv=None) -> int:
    parser = build_parser()
    # Subcommand-compatible: accept an optional leading `recover` or
    # `benchmark` token (e.g. `pdf-recovery recover --pdf doc.pdf`,
    # `pdf-recovery benchmark --pdf doc.pdf`) while keeping every legacy
    # flag invocation working unchanged.
    raw = list(argv) if argv is not None else list(__import__("sys").argv[1:])
    recover_mode = bool(raw and raw[0] == "recover")
    if recover_mode:
        raw = raw[1:]
    benchmark_prefix = bool(raw and raw[0] == "benchmark")
    if benchmark_prefix:
        raw = raw[1:]
    args = parser.parse_args(raw)  # SystemExit (usage errors) passes through
    args.recover = recover_mode
    if benchmark_prefix:
        args.benchmark = True
    try:
        return _main_impl(args, parser)
    except KeyboardInterrupt:
        print("Result: INTERRUPTED by user (Ctrl+C).", file=sys.stderr)
        return 130
    except BrokenPipeError:
        return 1
    except _ConfigError:
        return 1  # message already printed
    except Exception as exc:  # never expose a traceback during normal CLI use
        print(f"Error: unexpected failure: {exc}", file=sys.stderr)
        return 1


def _main_impl(args, parser) -> int:
    from . import __version__

    if args.version:
        print(f"pdf-recovery {__version__}")
        return 0

    if not args.pdf:
        parser.error("--pdf is required (provide the path to a .pdf file)")
    assert args.pdf is not None  # for type checkers; guaranteed above

    print(OWNERSHIP_WARNING, file=sys.stderr)

    _apply_config_file(args, parser)

    if not os.path.exists(args.pdf):
        print(f"Error: PDF not found: {args.pdf}", file=sys.stderr)
        return 1
    if os.path.isdir(args.pdf):
        print(f"Error: {args.pdf} is a directory, not a PDF file. "
              f"Provide the path to a single .pdf file.", file=sys.stderr)
        return 1

    # --- Encryption check (always done first) ---
    try:
        info = get_encryption_info(args.pdf)
    except PdfNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except PdfUnsupportedEncryptionError as e:
        print(f"Error: {e}", file=sys.stderr)
        print("Result: FAILED (unsupported encryption scheme).", file=sys.stderr)
        return 1
    except PdfMalformedError as e:
        print(f"Error: {e}", file=sys.stderr)
        print("Result: FAILED (malformed PDF).", file=sys.stderr)
        return 1
    except PdfRecoveryError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    from .pdf_tester import describe_encryption

    if not info["encrypted"]:
        print(f"PDF is NOT encrypted: {args.pdf}")
        print("Result: nothing to recover (file opens without a password).")
        return 0

    print(f"PDF is encrypted: {args.pdf}")
    if args.check_only:
        print(f"Encryption: {describe_encryption(info)}")
        print("Result: check complete (encrypted). Use 'recover --pdf ...' or provide "
              "--wordlist, --bases, --brute, or --auto to recover.")
        return 0

    # --- Checkpoint helpers for --auto ---
    from .checkpoint import (
        checkpoint_exists,
        describe_checkpoint,
        load_checkpoint,
        reset_checkpoint,
    )

    def _ckpt_path() -> str:
        return _resolve_checkpoint(args)

    # --status: inspect checkpoint and exit (no search).
    if args.status:
        path = _ckpt_path()
        if not checkpoint_exists(path):
            print(f"No checkpoint found at: {path}", file=sys.stderr)
            return 1
        try:
            data = load_checkpoint(path)
        except (OSError, ValueError) as e:
            print(f"Error: cannot read checkpoint: {e}", file=sys.stderr)
            return 1
        print(describe_checkpoint(data))
        return 0

    # --reset: discard checkpoint. With --auto, continue to fresh search;
    # without --auto (and without other modes), just discard and exit.
    if args.reset:
        path = _ckpt_path()
        removed = reset_checkpoint(path)
        if removed:
            print(f"Checkpoint removed: {path}", file=sys.stderr)
        else:
            print(f"No checkpoint to remove at: {path}", file=sys.stderr)
        has_other = bool(args.auto or args.wordlist or args.bases or args.bases_file or args.brute)
        if not has_other:
            return 0
        # else fall through to (fresh) search below

    # --benchmark: measure throughput + estimate, then exit (no search).
    if args.benchmark:
        return _run_benchmark(args, parser, info)

    # Universal `recover` mode: staged engine (empty → wordlist → variations → auto).
    if getattr(args, "recover", False):
        return _run_recover(args, parser, info)

    # --auto is exclusive: it runs alone without wordlist/bases/brute clues.
    if args.auto:
        if args.wordlist or args.bases or args.bases_file or args.brute:
            print("Error: --auto cannot be combined with --wordlist, --bases/--bases-file, or --brute. "
                  "Run them separately.", file=sys.stderr)
            parser.print_usage(sys.stderr)
            return 1
        return _run_auto(args, parser, info)

    # --- Legacy modes: Build config ---
    bases: List[str] = []
    if args.bases:
        bases.extend([b.strip() for b in args.bases.split(",") if b.strip() != ""])
    if args.bases_file:
        try:
            bases.extend(load_bases_file(args.bases_file, encoding=args.wordlist_encoding))
        except FileNotFoundError:
            print(f"Error: bases file not found: {args.bases_file}", file=sys.stderr)
            return 1
        except (UnicodeDecodeError, OSError) as e:
            print(f"Error: cannot read bases file: {e}", file=sys.stderr)
            return 1

    prefixes = _parse_csv(args.prefixes) if args.prefixes else []
    suffixes = _parse_csv(args.suffixes) if args.suffixes else []
    # Internal representation always includes "" (no affix).
    prefixes = [""] + [x for x in prefixes if x != ""]
    suffixes = [""] + [x for x in suffixes if x != ""]
    separators = _parse_separators(args.separators)

    # Resolve --charset (named sets, repeatable/comma-combined, with literal
    # fallback for backward compatibility) + --charset-custom override.
    if args.charset_custom and args.charset:
        print("WARNING: both --charset and --charset-custom given; using --charset-custom.",
              file=sys.stderr)
    resolved_charset = resolve_charset(specs=args.charset, custom=args.charset_custom)

    cfg = RecoveryConfig(
        pdf_path=args.pdf,
        wordlist_path=args.wordlist,
        wordlist_encoding=args.wordlist_encoding,
        base_phrases=bases,
        bases_file=args.bases_file,
        capitalize=not args.no_capitalization,
        separators=separators,
        prefixes=prefixes,
        suffixes=suffixes,
        add_numbers=not args.no_add_numbers,
        number_max=args.number_max,
        brute=args.brute,
        charset=resolved_charset,
        charset_specs=list(args.charset or []),
        charset_custom=args.charset_custom,
        min_length=args.min_length,
        max_length=args.max_length,
        workers=args.workers,
        limit=args.limit,
        show_progress=not args.no_progress,
    )
    errors = cfg.validate()
    if errors:
        for e in errors:
            print(f"Error: {e}", file=sys.stderr)
        parser.print_usage(sys.stderr)
        return 1

    has_wordlist = bool(cfg.wordlist_path)
    has_bases = bool(cfg.base_phrases)
    has_brute = bool(cfg.brute)
    if not (has_wordlist or has_bases or has_brute):
        print("Error: nothing to try. Provide --wordlist, --bases/--bases-file, --brute, or --auto.",
              file=sys.stderr)
        parser.print_usage(sys.stderr)
        return 1

    if has_wordlist and not os.path.exists(cfg.wordlist_path):  # type: ignore[arg-type]
        print(f"Error: wordlist not found: {cfg.wordlist_path}", file=sys.stderr)
        return 1

    # --- Assemble lazy candidate stream + totals for progress ---
    total: Optional[int] = 0
    streams = []

    if has_bases:
        variations = generate_variations(
            cfg.base_phrases,
            capitalize=cfg.capitalize,
            separators=cfg.separators,
            prefixes=cfg.prefixes,
            suffixes=cfg.suffixes,
            add_numbers=cfg.add_numbers,
            number_max=cfg.number_max,
        )
        print(f"Variation candidates: {len(variations)} "
              f"({len(cfg.base_phrases)} base phrase(s)).", file=sys.stderr)
        streams.append(iter(variations))
        total = (total or 0) + len(variations)

    if has_wordlist:
        assert cfg.wordlist_path is not None
        try:
            n = count_wordlist(cfg.wordlist_path, encoding=cfg.wordlist_encoding)
        except FileNotFoundError:
            print(f"Error: wordlist not found: {cfg.wordlist_path}", file=sys.stderr)
            return 1
        except (UnicodeDecodeError, OSError) as e:
            print(f"Error: cannot read wordlist: {e}", file=sys.stderr)
            return 1
        print(f"Wordlist candidates: ~{n} ({cfg.wordlist_path}).", file=sys.stderr)
        streams.append(load_wordlist(cfg.wordlist_path, encoding=cfg.wordlist_encoding))
        total = (total or 0) + n

    if has_brute:
        bt = estimate_bruteforce_total(cfg.charset, cfg.min_length, cfg.max_length)
        print(f"Brute-force candidates: {bt} "
              f"(charset={len(set(cfg.charset))} chars, "
              f"lengths {cfg.min_length}..{cfg.max_length}).", file=sys.stderr)
        if bt > 5_000_000:
            print("WARNING: brute-force space exceeds 5,000,000 candidates. "
                  "This may take a very long time. Keep it narrowly scoped "
                  "or use --limit to cap attempts.", file=sys.stderr)
        streams.append(brute_force_candidates(cfg.charset, cfg.min_length, cfg.max_length))
        total = (total or 0) + bt

    if cfg.limit is not None and total is not None and total > cfg.limit:
        total = cfg.limit

    candidates = itertools.chain(*streams)
    print(f"Workers: {cfg.workers} | Total (estimated): {total} | "
          f"Limit: {cfg.limit or 'none'}", file=sys.stderr)
    print("Press Ctrl+C to stop. The original PDF is never modified.", file=sys.stderr)

    # --- Run (Ctrl+C handled inside run_recovery) ---
    result = run_recovery(
        cfg.pdf_path,
        candidates,
        workers=cfg.workers,
        total=total,
        limit=cfg.limit,
        show_progress=cfg.show_progress,
        desc="Recovering",
        dedup=True,
    )

    status = result["status"]
    tried = result["tried"]
    elapsed = result.get("elapsed", 0.0)
    rate = (tried / elapsed) if elapsed > 0 else 0.0
    print(f"Tried {tried} candidate(s) in {elapsed:.1f}s ({rate:.0f}/s).", file=sys.stderr)

    if status == "found":
        print(f"SUCCESS: password found: {result['password']!r}")
        print("Result: SUCCESS.", file=sys.stderr)
        return 0
    if status == "interrupted":
        print("Result: INTERRUPTED by user (Ctrl+C).", file=sys.stderr)
        return 130
    if status == "error":
        print(f"Result: FAILED ({result.get('error', 'error')}).", file=sys.stderr)
        return 1
    # not_found
    if result.get("truncated"):
        print("Result: FAILED (password not found within --limit).", file=sys.stderr)
    else:
        print("Result: FAILED (password not found in the given candidate space).", file=sys.stderr)
    return 1


def _run_auto(args, parser, info=None) -> int:
    """Execute fully automatic clue-free search with checkpoint/resume."""
    from .auto import run_auto
    from .benchmark import default_benchmark_cache_path, prestart_decision
    from .checkpoint import (
        checkpoint_exists,
        load_checkpoint,
        params_match,
    )

    # Resolve charset: --charset-custom wins; else named specs; else default.
    specs: List[str] = list(args.charset or [])
    custom: Optional[str] = args.charset_custom
    if custom and specs:
        print("WARNING: both --charset and --charset-custom given; using --charset-custom.",
              file=sys.stderr)
    if not specs and not custom:
        specs = [DEFAULT_AUTO_CHARSET_NAME]
    charset = resolve_charset(specs=specs, custom=custom)
    if not charset:
        print("Error: --auto requires a non-empty charset.", file=sys.stderr)
        return 1

    min_len = args.min_length
    max_len = args.max_length if args.max_length != 0 else 4  # --auto default
    if min_len < 1 or max_len < min_len:
        print("Error: --auto requires 1 <= --min-length <= --max-length.", file=sys.stderr)
        return 1
    if args.workers < 1:
        print("Error: --workers must be >= 1.", file=sys.stderr)
        return 1
    if args.limit is not None and args.limit < 1:
        print("Error: --limit must be >= 1.", file=sys.stderr)
        return 1

    try:
        total = auto_space_total(charset, min_len, max_len)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Theoretical search-space size (requirement 12) + warnings (req 13).
    print(f"Auto search: charset={len(set(charset))} chars, lengths {min_len}..{max_len}, "
          f"workers={args.workers}", file=sys.stderr)
    print(f"Theoretical search-space size: total = {total} "
          f"(sum({len(set(charset))}**n for n in {min_len}..{max_len}))", file=sys.stderr)
    if total > 1_000_000_000:
        print(f"WARNING: search space is EXTREMELY large ({total:,} candidates). "
              f"At 500 pw/s this would take ~{total/500/86400:.1f} days. "
              f"Restrict --charset / --max-length or use --limit.", file=sys.stderr)
    elif total > 10_000_000:
        print(f"WARNING: search space is very large ({total:,} candidates). "
              f"This may take a very long time. Consider a narrower --charset, "
              f"smaller --max-length, or --limit with checkpoint/resume.", file=sys.stderr)
    elif total > 5_000_000:
        print(f"WARNING: search space exceeds 5,000,000 candidates ({total:,}).",
              file=sys.stderr)

    ckpt_path = _resolve_checkpoint(args)
    start_index = 0
    if checkpoint_exists(ckpt_path):
        try:
            data = load_checkpoint(ckpt_path)
        except (OSError, ValueError) as e:
            print(f"Error: cannot read checkpoint {ckpt_path}: {e} (use --reset)", file=sys.stderr)
            return 1
        ok, reason = params_match(data, args.pdf, charset, min_len, max_len, total,
                                   _pdf_fingerprint(args.pdf))
        if not ok:
            print(f"Error: existing checkpoint does not match: {reason}", file=sys.stderr)
            print(f"Checkpoint: {ckpt_path} (use --reset to discard)", file=sys.stderr)
            return 1
        start_index = int(data.get("next_index", 0))
        if start_index >= total:
            print(f"Checkpoint shows search already exhausted ({start_index}/{total}). "
                  f"Use --reset to restart.", file=sys.stderr)
            return 1
        if start_index > 0:
            print(f"Resuming from checkpoint: {ckpt_path} "
                  f"(completed {start_index}/{total}, remaining {total - start_index})",
                  file=sys.stderr)
    else:
        print(f"Checkpoint: {ckpt_path} (new search)", file=sys.stderr)

    print(f"Workers: {args.workers} | Limit: {args.limit or 'none'} | "
          f"Starting at index {start_index}/{total}", file=sys.stderr)
    print("Press Ctrl+C to stop (progress is checkpointed for resume). "
          "The original PDF is never modified.", file=sys.stderr)

    # Prestart safety gate: never silently launch an impractical search.
    # A user-imposed --limit bounds the actual work, so gate on that.
    method = info.get("method") if isinstance(info, dict) else None
    bench_cache = default_benchmark_cache_path(ckpt_path)
    gate_remaining = max(0, total - start_index)
    if args.limit is not None:
        gate_remaining = min(gate_remaining, args.limit)
    decision = prestart_decision(
        args.pdf, method, len(set(charset)), gate_remaining,
        workers_probe=1, samples=12, cache_path=bench_cache, force=args.force,
    )
    if decision.get("error"):
        print(f"Result: FAILED ({decision['error']}).", file=sys.stderr)
        return 1
    if not decision.get("proceed"):
        _print_gated(_exact_auto_command(args, specs, custom, min_len, max_len),
                      total, gate_remaining, decision)
        return 1
    if decision.get("cached"):
        print(f"Benchmark: cached probe {decision['rate']:.0f}/s; "
              f"estimated ~{decision['duration']} for remaining "
              f"{max(0, total - start_index):,} candidates.", file=sys.stderr)

    result = run_auto(
        pdf_path=args.pdf,
        charset=charset,
        min_length=min_len,
        max_length=max_len,
        total=total,
        start_index=start_index,
        workers=args.workers,
        limit=args.limit,
        show_progress=not args.no_progress,
        checkpoint_path=ckpt_path,
        checkpoint_meta={"charset_spec": specs, "charset_custom": custom},
    )

    status = result["status"]
    tried = result["tried"]
    elapsed = result.get("elapsed", 0.0)
    rate = result.get("rate", (tried / elapsed) if elapsed > 0 else 0.0)
    from .results import result_from_dict

    _maybe_write_output(args, result_from_dict(
        result, encryption_info=info if isinstance(info, dict) else None,
        checkpoint_path=ckpt_path, stage="auto"))
    print(f"Length {result.get('current_length')} | "
          f"Tried {_fmt_int(tried)} candidate(s) in {_fmt_elapsed(elapsed)} ({rate:.0f}/s) | "
          f"Remaining ~{_fmt_int(result.get('remaining', 0))} of {_fmt_int(total)}.", file=sys.stderr)
    if status == "found":
        print(f"SUCCESS: password found: {result['password']!r}")
        print("Result: SUCCESS. (checkpoint cleared)", file=sys.stderr)
        return 0
    if status == "interrupted":
        print(f"Result: INTERRUPTED. Resume with the same --auto command "
              f"(checkpoint: {ckpt_path}).", file=sys.stderr)
        return 130
    if status == "error":
        print(f"Result: FAILED ({result.get('error', 'error')}).", file=sys.stderr)
        return 1
    if result.get("truncated"):
        print(f"Result: FAILED (password not found within --limit; "
              f"resume from checkpoint: {ckpt_path}).", file=sys.stderr)
    else:
        print("SEARCH EXHAUSTED")
        print("Password was not found within the configured search space.")
        print("Result: FAILED (password not found in the automatic search space; "
              "checkpoint cleared).", file=sys.stderr)
    return 1


def _charset_label(specs: List[str], custom: Optional[str], charset: str) -> str:
    """Short header label, e.g. 'alphanumeric (62)' or 'custom (6)'."""
    if custom:
        return f"custom ({len(set(charset))})"
    cleaned = [s.strip().lower() for s in (specs or []) if s and s.strip()]
    if len(cleaned) == 1 and cleaned[0] in CHARSET_PRESETS:
        return f"{cleaned[0]} ({len(set(charset))})"
    if cleaned:
        return f"{'+'.join(cleaned)} ({len(set(charset))})"
    return f"custom ({len(set(charset))})"


def _warn_large_space(total: int, charset_size: int, min_len: int, max_len: int) -> None:
    """Tiered honesty warnings; never pretends huge spaces are feasible."""
    print(f"Theoretical search-space size: total = {total} "
          f"(sum({charset_size}**n for n in {min_len}..{max_len}))", file=sys.stderr)
    if total > 1_000_000_000:
        print(f"WARNING: search space is EXTREMELY large ({total:,} candidates). "
              f"Exhaustive recovery may be computationally INFEASIBLE; strong random "
              f"passwords of this size cannot realistically be recovered. Restrict "
              f"--charset / --max-length, supply clues, or use --limit. "
              f"Run --benchmark for a measured duration estimate.", file=sys.stderr)
    elif total > 10_000_000:
        print(f"WARNING: search space is very large ({total:,} candidates). "
              f"This may take a very long time. Consider a narrower --charset, "
              f"smaller --max-length, --limit with checkpoint/resume, or --benchmark "
              f"for a measured estimate.", file=sys.stderr)
    elif total > 5_000_000:
        print(f"WARNING: search space exceeds 5,000,000 candidates ({total:,}).",
              file=sys.stderr)


def _run_benchmark(args, parser, info) -> int:
    """Measure real local throughput and project the configured space."""
    from .benchmark import benchmark_report
    from .pdf_tester import describe_encryption

    specs: List[str] = list(args.charset or [])
    custom: Optional[str] = args.charset_custom
    if not specs and not custom:
        specs = [DEFAULT_AUTO_CHARSET_NAME]
    charset = resolve_charset(specs=specs, custom=custom)
    if not charset:
        print("Error: --benchmark requires a non-empty charset.", file=sys.stderr)
        return 1
    min_len = args.min_length
    max_len = args.max_length if args.max_length != 0 else 4
    if min_len < 1 or max_len < min_len:
        print("Error: benchmark requires 1 <= --min-length <= --max-length.", file=sys.stderr)
        return 1
    if args.bench_samples is not None and args.bench_samples < 1:
        print("Error: --bench-samples must be >= 1.", file=sys.stderr)
        return 1
    try:
        total = auto_space_total(charset, min_len, max_len)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    _print_header([
        ("PDF", args.pdf),
        ("Encrypted", "YES"),
        ("Encryption", describe_encryption(info)),
        ("Mode", "Benchmark"),
        ("Charset", _charset_label(specs, custom, charset)),
        ("Length range", f"{min_len}-{max_len}"),
        ("Search space", _fmt_int(total)),
        ("Workers", f"{args.workers}"),
        ("Benchmark samples", f"{args.bench_samples}"),
    ])
    if getattr(args, "verbose", False):
        _diag(args, f"Encryption details: {info.get('details')}")
    print("Benchmark: measuring actual local verification throughput "
          "(CPU-only; no GPU)...", file=sys.stderr)
    try:
        report = benchmark_report(
            args.pdf, total_candidates=total, charset_size=len(set(charset)),
            min_length=min_len, max_length=max_len,
            workers=args.workers, samples=args.bench_samples,
        )
    except (PdfMalformedError, PdfUnsupportedEncryptionError, PdfRecoveryError) as e:
        print(f"Result: FAILED ({e}).", file=sys.stderr)
        return 1
    th = report["throughput"]
    print(f"Rate: {th['rate']:.0f} attempts/sec "
          f"({th['samples']} samples in {th['elapsed']:.1f}s, workers={th['workers']}, CPU-only)")
    print(f"Tested: {_fmt_int(th['samples'])} (benchmark only; no search ran)")
    print(f"Elapsed: {_fmt_elapsed(th['elapsed'])}")
    print(f"Remaining: {_fmt_int(total)} (full configured space)")
    print(f"Estimated duration: {report['duration']}")
    print(f"Feasibility: {report['verdict']}")
    # Warm the prestart-gate cache so a following recover run reuses it.
    try:
        from .benchmark import default_benchmark_cache_path, store_benchmark_cache
        from .checkpoint import default_checkpoint_path

        store_benchmark_cache(
            default_benchmark_cache_path(
                args.checkpoint or default_checkpoint_path(args.pdf)),
            args.pdf, info.get("method") if isinstance(info, dict) else None,
            args.workers, th["rate"], th["samples"], th["elapsed"])
    except Exception:
        pass
    print("Result: benchmark complete (no checkpoint modified).", file=sys.stderr)
    return 0


def _run_recover(args, parser, info) -> int:
    """Universal staged recovery: empty → wordlist → variations → auto."""
    from .checkpoint import (
        checkpoint_exists,
        load_checkpoint,
        params_match,
    )
    from .engine import run_unified_recovery
    from .pdf_tester import describe_encryption

    # Optional clue stages (same parsing as legacy, but optional here).
    bases: List[str] = []
    if args.bases:
        bases.extend([b.strip() for b in args.bases.split(",") if b.strip() != ""])
    if args.bases_file:
        try:
            bases.extend(load_bases_file(args.bases_file, encoding=args.wordlist_encoding))
        except FileNotFoundError:
            print(f"Error: bases file not found: {args.bases_file}", file=sys.stderr)
            return 1
        except (UnicodeDecodeError, OSError) as e:
            print(f"Error: cannot read bases file: {e}", file=sys.stderr)
            return 1
    if args.wordlist and not os.path.exists(args.wordlist):
        print(f"Error: wordlist not found: {args.wordlist}", file=sys.stderr)
        return 1

    prefixes = _parse_csv(args.prefixes) if args.prefixes else []
    suffixes = _parse_csv(args.suffixes) if args.suffixes else []
    prefixes = [""] + [x for x in prefixes if x != ""]
    suffixes = [""] + [x for x in suffixes if x != ""]
    separators = _parse_separators(args.separators)

    if args.charset_custom and args.charset:
        print("WARNING: both --charset and --charset-custom given; using --charset-custom.",
              file=sys.stderr)
    specs: List[str] = list(args.charset or [])
    custom: Optional[str] = args.charset_custom
    if not specs and not custom:
        specs = [DEFAULT_AUTO_CHARSET_NAME]
    charset = resolve_charset(specs=specs, custom=custom)
    if not charset:
        print("Error: recovery requires a non-empty charset.", file=sys.stderr)
        return 1
    min_len = args.min_length
    max_len = args.max_length if args.max_length != 0 else 4
    if min_len < 1 or max_len < min_len:
        print("Error: recovery requires 1 <= --min-length <= --max-length.", file=sys.stderr)
        return 1
    if args.workers < 1:
        print("Error: --workers must be >= 1.", file=sys.stderr)
        return 1
    if args.limit is not None and args.limit < 1:
        print("Error: --limit must be >= 1.", file=sys.stderr)
        return 1
    try:
        total = auto_space_total(charset, min_len, max_len)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    stages = ["empty-password check"]
    if args.wordlist:
        stages.append(f"wordlist ({args.wordlist})")
    if bases:
        stages.append(f"variations ({len(bases)} base phrase(s))")
    stages.append(f"automatic (charset={_charset_label(specs, custom, charset)}, "
                  f"lengths {min_len}-{max_len})")

    _print_header([
        ("PDF", args.pdf),
        ("Encrypted", "YES"),
        ("Encryption", describe_encryption(info)),
        ("Mode", "Automatic"),
        ("Strategy", " → ".join(stages)),
        ("Charset", _charset_label(specs, custom, charset)),
        ("Length range", f"{min_len}-{max_len}"),
        ("Search space", _fmt_int(total)),
        ("Workers", f"{args.workers}"),
    ])
    if getattr(args, "verbose", False):
        _diag(args, f"Encryption details: {info.get('details')}")
    _warn_large_space(total, len(set(charset)), min_len, max_len)

    ckpt_path = _resolve_checkpoint(args)
    start_index = 0
    if checkpoint_exists(ckpt_path):
        try:
            data = load_checkpoint(ckpt_path)
        except (OSError, ValueError) as e:
            print(f"Error: cannot read checkpoint {ckpt_path}: {e} (use --reset)", file=sys.stderr)
            return 1
        ok, reason = params_match(data, args.pdf, charset, min_len, max_len, total,
                                   _pdf_fingerprint(args.pdf))
        if not ok:
            print(f"Error: existing checkpoint does not match: {reason}", file=sys.stderr)
            print(f"Checkpoint: {ckpt_path} (use --reset to discard)", file=sys.stderr)
            return 1
        start_index = int(data.get("next_index", 0))
        if start_index >= total:
            print(f"Checkpoint shows search already exhausted ({start_index}/{total}). "
                  f"Use --reset to restart.", file=sys.stderr)
            return 1
        if start_index > 0:
            print(f"Resuming automatic stage from checkpoint: {ckpt_path} "
                  f"(completed {start_index}/{total}, remaining {total - start_index})",
                  file=sys.stderr)
    else:
        print(f"Checkpoint: {ckpt_path} (new search)", file=sys.stderr)
    print(f"Limit: {args.limit or 'none'} | Force: {'yes' if args.force else 'no'} | "
          f"Starting staged recovery (automatic stage at index "
          f"{start_index}/{total})", file=sys.stderr)
    print("Huge automatic searches require --force (see safety gate below). "
          "Press Ctrl+C to stop (progress is checkpointed for resume). "
          "The original PDF is never modified.", file=sys.stderr)

    from .benchmark import default_benchmark_cache_path

    result = run_unified_recovery(
        pdf_path=args.pdf,
        charset=charset,
        min_length=min_len,
        max_length=max_len,
        total=total,
        workers=args.workers,
        limit=args.limit,
        show_progress=not args.no_progress,
        checkpoint_path=ckpt_path,
        checkpoint_meta={"charset_spec": specs, "charset_custom": custom},
        start_index=start_index,
        wordlist_path=args.wordlist,
        wordlist_encoding=args.wordlist_encoding,
        base_phrases=bases or None,
        variation_kwargs={
            "capitalize": not args.no_capitalization,
            "separators": separators,
            "prefixes": prefixes,
            "suffixes": suffixes,
            "add_numbers": not args.no_add_numbers,
            "number_max": args.number_max,
        },
        auto_gate=True,
        force=args.force,
        bench_samples=12,
        bench_cache_path=default_benchmark_cache_path(ckpt_path),
    )

    status = result["status"]
    if status == "gated":
        gate = result.get("gate") or {}
        _print_gated(_exact_recover_command(args, specs, custom, min_len, max_len),
                      total, gate.get("remaining", max(0, total - start_index)), gate)
        return 1
    from .results import result_from_dict

    result_obj = result_from_dict(result, encryption_info=info,
                                  checkpoint_path=ckpt_path,
                                  stage=result.get("stage"))
    _maybe_write_output(args, result_obj)
    tried = result["tried"]
    elapsed = result.get("elapsed", 0.0)
    rate = (tried / elapsed) if elapsed > 0 else 0.0
    print(f"Rate: {rate:.0f} attempts/sec")
    print(f"Tested: {_fmt_int(tried)}")
    print(f"Elapsed: {_fmt_elapsed(elapsed)}")
    auto_remaining = max(0, total - start_index - max(0, tried - _clue_tried(result)))
    print(f"Remaining: ~{_fmt_int(auto_remaining)} of {_fmt_int(total)} (automatic stage)")
    print(f"Tried {tried} candidate(s) across stages {result.get('stage')} "
          f"in {elapsed:.1f}s ({rate:.0f}/s).", file=sys.stderr)

    if status == "found":
        print("SUCCESS")
        print(f"Password recovered: {result['password']!r}")
        print(f"SUCCESS: password found: {result['password']!r}")
        print(f"Result: SUCCESS via {result.get('stage')} stage. (checkpoint cleared)",
              file=sys.stderr)
        return 0
    if status == "not_encrypted":
        print("Result: nothing to recover (file opens without a password).")
        return 0
    if status == "interrupted":
        print("INTERRUPTED")
        print(f"Result: INTERRUPTED. Resume with the same recover command "
              f"(checkpoint: {ckpt_path}).", file=sys.stderr)
        return 130
    if status == "error":
        print(f"Result: FAILED ({result.get('error', 'error')}).", file=sys.stderr)
        return 1
    if result.get("truncated"):
        print(f"Result: FAILED (password not found within --limit; "
              f"resume from checkpoint: {ckpt_path}).", file=sys.stderr)
    else:
        print("SEARCH EXHAUSTED")
        print("Password was not found within the configured search space.")
        print("Result: FAILED (password not found; checkpoint cleared).", file=sys.stderr)
    return 1


def _clue_tried(result) -> int:
    """Candidates tried before the automatic stage (for Remaining display)."""
    n = 0
    for s in result.get("stages", []) or []:
        if s.get("stage") in ("empty", "wordlist", "variations"):
            try:
                n += int(s.get("tried", 0) or 0)
            except (TypeError, ValueError):
                continue
    return n
