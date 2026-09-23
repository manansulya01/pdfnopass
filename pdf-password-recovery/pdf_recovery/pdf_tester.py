"""PDF password testing through the normal decryption path.

Only ``pypdf.PdfReader.decrypt`` is used — the tool never bypasses,
downgrades, strips, or rewrites PDF encryption. Files are opened
read-only; the original PDF is never modified or overwritten.
"""
from __future__ import annotations

import os
from typing import Any, Dict


class PdfRecoveryError(Exception):
    """Base class for PDF handling errors."""


class PdfNotFoundError(PdfRecoveryError):
    pass


class PdfMalformedError(PdfRecoveryError):
    pass


class PdfUnsupportedEncryptionError(PdfRecoveryError):
    pass


def _import_reader():
    try:
        from pypdf import PdfReader  # type: ignore
        return PdfReader
    except ImportError as exc:
        raise PdfRecoveryError(
            "The 'pypdf' package is required. Install with: pip install -r requirements.txt"
        ) from exc


def _read_encrypt_dict(reader) -> dict:
    """Best-effort read of the /Encrypt dictionary without decrypting.

    Returns {} when unavailable (e.g. file not encrypted, or the library
    refuses access before decryption). Never raises: callers treat missing
    details as 'unknown'. Read-only; never modifies the file.
    """
    try:
        trailer = getattr(reader, "trailer", None)
        if trailer is None:
            return {}
        enc = trailer.get("/Encrypt")
        if enc is None:
            return {}
        if hasattr(enc, "get_object"):
            try:
                enc = enc.get_object()
            except Exception:
                return {}
        if enc is None or not hasattr(enc, "keys"):
            return {}
        out: Dict[str, Any] = {}
        for key in ("/Filter", "/V", "/R", "/Length", "/CF", "/StmF", "/StrF",
                    "/EncryptMetadata", "/O", "/U", "/OE", "/UE", "/Perms"):
            try:
                if key in enc:
                    val = enc.get(key)
                    # Unwrap indirect references one level for readability.
                    if hasattr(val, "get_object"):
                        try:
                            val = val.get_object()
                        except Exception:
                            pass
                    # Keep only small printable scalars; never dump O/U hashes.
                    if key in ("/O", "/U", "/OE", "/UE", "/Perms"):
                        out[key] = "<present>" if val is not None else None
                    elif isinstance(val, (str, int, float, bool)) or val is None:
                        out[key] = val
                    else:
                        try:
                            out[key] = str(val)
                        except Exception:
                            out[key] = "<present>"
            except Exception:
                continue
        return out
    except Exception:
        return {}


def _algorithm_label(details: Dict[str, Any]) -> str:
    """Human label for the detected scheme, e.g. 'Standard V=2 R=3 (RC4 128-bit)'."""
    if not details:
        return "unknown (details unavailable)"
    filt = details.get("/Filter", "/Standard")
    v = details.get("/V")
    r = details.get("/R")
    length = details.get("/Length", 40 if v == 1 else 128 if v in (2, 4) else None)
    base = f"{filt} V={v} R={r}" if v is not None else str(filt)
    # Common mappings (informational only; no bypass involved).
    if v == 1:
        return f"{base} (RC4 40-bit)"
    if v == 2:
        return f"{base} (RC4 up to 128-bit; Length={length})"
    if v == 3:
        return f"{base} (unpublished algorithm)"
    if v == 4:
        cf = details.get("/CF")
        return f"{base} (crypt filters; Length={length}; CF={cf})"
    if v == 5:
        return f"{base} (AES-256)"
    if v is None and r is None:
        return f"{filt} (version details unavailable)"
    return base


def get_encryption_info(pdf_path: str) -> Dict[str, Any]:
    """Return encryption metadata without attempting recovery.

    Keys (backward compatible): ``exists``, ``encrypted``.
    Added when available: ``filter``, ``v``, ``r``, ``key_length``,
    ``method`` (human label), ``details`` (small /Encrypt summary; hash
    material like /O /U is redacted to '<present>').
    Raises PdfNotFoundError / PdfMalformedError /
    PdfUnsupportedEncryptionError on problem files.
    """
    if not os.path.exists(pdf_path):
        raise PdfNotFoundError(f"PDF not found: {pdf_path}")
    PdfReader = _import_reader()
    try:
        from pypdf.errors import PdfReadError  # type: ignore
    except ImportError:  # pragma: no cover - very old pypdf
        PdfReadError = Exception  # type: ignore

    try:
        reader = PdfReader(pdf_path)
        encrypted = bool(reader.is_encrypted)
        info: Dict[str, Any] = {"exists": True, "encrypted": encrypted}
        if encrypted:
            details = _read_encrypt_dict(reader)
            info["details"] = details
            info["filter"] = details.get("/Filter")
            info["v"] = details.get("/V")
            info["r"] = details.get("/R")
            info["key_length"] = details.get("/Length")
            info["method"] = _algorithm_label(details)
        else:
            info["details"] = {}
            info["filter"] = None
            info["v"] = None
            info["r"] = None
            info["key_length"] = None
            info["method"] = "not encrypted"
        return info
    except FileNotFoundError as exc:
        raise PdfNotFoundError(str(exc)) from exc
    except NotImplementedError as exc:
        # pypdf raises this for unsupported crypt filters / algorithms.
        raise PdfUnsupportedEncryptionError(f"Unsupported encryption scheme: {exc}") from exc
    except Exception as exc:
        name = type(exc).__name__
        if "PdfReadError" in name or "StreamTruncated" in name or "EmptyFile" in name:
            raise PdfMalformedError(f"Malformed or unreadable PDF: {exc}") from exc
        if isinstance(exc, PdfReadError):
            raise PdfMalformedError(f"Malformed or unreadable PDF: {exc}") from exc
        raise PdfMalformedError(f"Malformed or unreadable PDF ({name}): {exc}") from exc


def is_encrypted(pdf_path: str) -> bool:
    """Return True if the PDF requires a password to open."""
    return bool(get_encryption_info(pdf_path)["encrypted"])


def describe_encryption(info: Dict[str, Any]) -> str:
    """One-line human summary of encryption info (never includes secrets)."""
    if not info.get("encrypted"):
        return "not encrypted"
    method = info.get("method") or "encrypted (details unavailable)"
    return str(method)


def try_password(pdf_path: str, password: str) -> bool:
    """Test a single candidate password via normal PDF decryption.

    Opens the file fresh on every call (multiprocessing-safe, read-only).
    Returns True if *password* decrypts the document, False if it does not.

    Raises:
        PdfNotFoundError: file disappeared.
        PdfUnsupportedEncryptionError: pypdf cannot handle the crypt filter.
        PdfMalformedError: file is corrupt/unreadable.
    """
    PdfReader = _import_reader()

    try:
        reader = PdfReader(pdf_path)
    except FileNotFoundError as exc:
        raise PdfNotFoundError(str(exc)) from exc
    except NotImplementedError as exc:
        raise PdfUnsupportedEncryptionError(f"Unsupported encryption scheme: {exc}") from exc
    except Exception as exc:
        raise PdfMalformedError(f"Malformed or unreadable PDF: {exc}") from exc

    try:
        if not reader.is_encrypted:
            return True
    except NotImplementedError as exc:
        raise PdfUnsupportedEncryptionError(f"Unsupported encryption scheme: {exc}") from exc
    except Exception as exc:
        raise PdfMalformedError(f"Could not inspect PDF encryption: {exc}") from exc

    try:
        result = reader.decrypt(password)
    except NotImplementedError as exc:
        raise PdfUnsupportedEncryptionError(f"Unsupported encryption scheme: {exc}") from exc
    except Exception as exc:
        # Decryption itself failing unexpectedly -> treat as malformed only
        # if the error looks structural; otherwise a failed candidate.
        name = type(exc).__name__
        if "PdfReadError" in name:
            raise PdfMalformedError(f"Malformed PDF during decrypt: {exc}") from exc
        return False

    # pypdf returns 0 / PasswordType.NOT_DECRYPTED on failure,
    # 1 (user) or 2 (owner) on success depending on version.
    try:
        result_int = int(result)
    except (TypeError, ValueError):
        result_int = 1 if result else 0
    if result_int == 0:
        return False

    # Verify the decrypted document is actually readable.
    try:
        _ = len(reader.pages)
        return True
    except NotImplementedError as exc:
        raise PdfUnsupportedEncryptionError(f"Unsupported encryption scheme: {exc}") from exc
    except Exception:
        return False
