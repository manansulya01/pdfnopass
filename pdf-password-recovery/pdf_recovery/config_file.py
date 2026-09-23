"""Optional user configuration file (never mandatory, never secret).

Resolution order for each setting (highest wins):
1. Explicit CLI arguments.
2. ``--config PATH`` file, or the platform default config file if present.
3. Built-in defaults.

Supported keys (all optional): ``workers``, ``charset``, ``charset_custom``,
``min_length``, ``max_length``, ``no_progress``, ``verbose``,
``checkpoint_dir``. CLI arguments always override file values.

Privacy: keys that look like credentials (``password``, ``passwd``,
``secret``, ``api_key``, ``token``) are NEVER honoured; they are ignored
with a warning printed to stderr. Passwords must never live in config
files, and this tool never writes them anywhere.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

SUPPORTED_KEYS = (
    "workers",
    "charset",
    "charset_custom",
    "min_length",
    "max_length",
    "no_progress",
    "verbose",
    "checkpoint_dir",
)

_SENSITIVE_SUBSTRINGS = ("password", "passwd", "secret", "api_key", "apikey", "token")


def default_config_path() -> str:
    """Platform-appropriate default config location (may not exist)."""
    if os.name == "nt":
        base = os.environ.get("APPDATA") or str(Path.home())
        return str(Path(base) / "pdf-recovery" / "config.json")
    if __import__("sys").platform == "darwin":
        return str(Path.home() / "Library" / "Application Support"
                   / "pdf-recovery" / "config.json")
    xdg = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return str(Path(xdg) / "pdf-recovery" / "config.json")


def load_config_file(path: str) -> Dict[str, Any]:
    """Load and minimally validate a JSON (or TOML, if available) config file.

    Raises FileNotFoundError / ValueError with human-readable messages.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"config file not found: {path}")
    suffix = os.path.splitext(path)[1].lower()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise ValueError(f"cannot read config file {path}: {exc}") from exc
    if suffix == ".toml":
        try:
            import tomllib  # Python 3.11+
        except ImportError:
            try:
                import tomli as tomllib  # type: ignore[no-redef]
            except ImportError as exc:
                raise ValueError(
                    f"config file {path} is TOML but no TOML parser is available "
                    f"(Python 3.11+ required, or install 'tomli'); use JSON instead."
                ) from exc
        try:
            data = tomllib.loads(text)
        except Exception as exc:
            raise ValueError(f"invalid TOML in config file {path}: {exc}") from exc
    else:
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise ValueError(f"invalid JSON in config file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"config file {path} must contain a JSON object")
    return data


def split_config(data: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """Split raw config into (usable settings, warnings).

    Unknown keys produce warnings (ignored). Sensitive-looking keys are
    dropped with a warning and never honoured.
    """
    usable: Dict[str, Any] = {}
    warnings: List[str] = []
    for key, value in data.items():
        lowered = str(key).lower()
        if any(s in lowered for s in _SENSITIVE_SUBSTRINGS):
            warnings.append(
                f"config key {key!r} looks like a credential and was ignored "
                f"(never store passwords in config files)")
            continue
        if key not in SUPPORTED_KEYS:
            warnings.append(f"config key {key!r} is not supported and was ignored")
            continue
        usable[key] = value
    return usable, warnings


def coerce_config_types(usable: Dict[str, Any], source: str) -> Tuple[Dict[str, Any], List[str]]:
    """Validate value types; returns (clean, errors). Errors are fatal."""
    clean: Dict[str, Any] = {}
    errors: List[str] = []
    for key, value in usable.items():
        if key in ("workers", "min_length", "max_length"):
            try:
                clean[key] = int(value)
            except (TypeError, ValueError):
                errors.append(f"config {source}: {key!r} must be an integer")
        elif key in ("no_progress", "verbose"):
            if isinstance(value, bool):
                clean[key] = value
            else:
                errors.append(f"config {source}: {key!r} must be true/false")
        elif key in ("charset", "charset_custom", "checkpoint_dir"):
            if isinstance(value, str):
                clean[key] = value
            else:
                errors.append(f"config {source}: {key!r} must be a string")
    return clean, errors
