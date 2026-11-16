"""Filesystem path containment, sensitive file blacklisting, and SSRF validation.

Enforces zero-trust invariants.
"""

import fnmatch
import ipaddress
import os
import stat
from pathlib import Path
from urllib.parse import urlparse

from app.errors import (
    PathTraversalError,
    PayloadTooLargeError,
    SecurityViolationError,
    SensitiveFileError,
    SSRFBlockedError,
)

# Sensitive path and credential blacklist patterns
SENSITIVE_PATTERNS: frozenset[str] = frozenset(
    {
        ".env*",
        "id_rsa*",
        "id_ed25519*",
        "id_ecdsa*",
        "*.pem",
        "*.key",
        "*.p12",
        "*.pfx",
        "*.jks",
        "*.keystore",
        ".git*",
        "credentials*",
        "passwd*",
        "shadow*",
        "*.token*",
        "*_token.json",
        ".tokens*",
        "token_store*",
        ".aws*",
        "known_hosts*",
        ".npmrc",
        ".pypirc",
        ".netrc",
        "*.kdbx",
        ".docker/config.json",
    }
)

# Hostnames unconditionally blocked from outbound HTTP fetch
BLOCKED_HOSTNAMES: frozenset[str] = frozenset(
    {
        "169.254.169.254",
        "metadata.google.internal",
        "metadata.azure.internal",
        "localhost",
        "127.0.0.1",
        "0.0.0.0",  # noqa: S104 — Denylist literal for SSRF blocking, not a socket bind
        "::1",
    }
)


def is_sensitive_file(file_path: Path | str) -> bool:
    """Check if any segment or filename matches the sensitive file blacklist.

    Ref: agent-security.md §6.
    """
    path_obj = Path(file_path)
    segments = [*path_obj.parts, path_obj.name]
    for segment in segments:
        segment_lower = segment.lower()
        for pattern in SENSITIVE_PATTERNS:
            if fnmatch.fnmatch(segment_lower, pattern.lower()):
                return True
    return False


def resolve_safe_path(
    user_path: str,
    sandbox_root: Path,
    *,
    max_agent_file_bytes: int = 1048576,
) -> Path:
    """Resolve and validate a user-supplied relative path against a sandbox root.

    Guarantees:
    1. Rejects null bytes in path string.
    2. Enforces containment within sandbox_root (rejects traversal attempts).
    3. Rejects sensitive blacklisted files and directories.
    4. Confirms the target path exists.

    Raises:
        PathTraversalError: If path escapes sandbox boundary or contains null bytes.
        SensitiveFileError: If path matches sensitive blacklist.
        FileNotFoundError: If the target does not exist.
    """
    if "\0" in user_path:
        raise PathTraversalError("Null byte detected in file path")

    root = sandbox_root.resolve(strict=True)
    candidate = (root / user_path).resolve()

    if not candidate.is_relative_to(root):
        raise PathTraversalError(
            f"Path '{user_path}' escapes sandbox boundary '{root}'"
        )

    rel_path = candidate.relative_to(root)
    if is_sensitive_file(rel_path):
        raise SensitiveFileError(
            f"Access to sensitive file '{candidate.name}' is strictly denied"
        )

    if not candidate.exists():
        raise FileNotFoundError(f"File '{user_path}' does not exist")

    return candidate


def read_safe_file(
    user_path: str,
    sandbox_root: Path,
    *,
    max_agent_file_bytes: int = 1048576,
) -> bytes:
    """Perform a TOCTOU-safe read with O_NOFOLLOW and size clamping.


    Raises:
        PathTraversalError: If path is a symlink or escapes sandbox.
        SensitiveFileError: If path is blacklisted.
        PayloadTooLargeError: If file size exceeds max_agent_file_bytes.
        IsADirectoryError: If the path targets a directory.
        FileNotFoundError: If the path does not exist.
    """
    safe_path = resolve_safe_path(
        user_path, sandbox_root, max_agent_file_bytes=max_agent_file_bytes
    )

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):  # ATTR-SNIFF-WAIVER: stdlib-os-platform-check
        flags |= os.O_NOFOLLOW

    try:
        fd = os.open(str(safe_path), flags)
    except OSError as err:
        msg = f"Failed to open '{user_path}' (symlink or permission error): {err}"
        raise PathTraversalError(msg) from err

    try:
        stat_info = os.fstat(fd)
        if stat.S_ISDIR(stat_info.st_mode):
            raise IsADirectoryError(f"Path '{user_path}' is a directory, not a file")

        if stat_info.st_size > max_agent_file_bytes:
            raise PayloadTooLargeError(
                f"File size ({stat_info.st_size} bytes) exceeds maximum ceiling "
                f"({max_agent_file_bytes} bytes)"
            )

        return os.read(fd, stat_info.st_size)
    finally:
        os.close(fd)


def validate_url(url: str) -> str:
    """Validate outbound HTTP fetch URLs against SSRF and cloud metadata targets.


    Raises:
        SecurityViolationError: If scheme is unsupported or hostname is missing.
        SSRFBlockedError: If URL targets private IP, loopback, or cloud metadata.
    """
    if not url or not url.strip():
        raise SecurityViolationError("URL cannot be empty")

    parsed = urlparse(url.strip())
    if parsed.scheme.lower() not in ("http", "https"):
        scheme = parsed.scheme
        raise SecurityViolationError(
            f"Unsupported URL scheme '{scheme}'. Only 'http' and 'https' are allowed."
        )

    hostname = parsed.hostname
    if not hostname:
        raise SecurityViolationError("URL does not contain a valid hostname")

    hostname_lower = hostname.lower()

    if hostname_lower in BLOCKED_HOSTNAMES or hostname_lower.endswith(
        (".internal", ".local")
    ):
        raise SSRFBlockedError(
            f"Outbound request to blocked host '{hostname}' is denied (SSRF guard)"
        )

    try:
        ip = ipaddress.ip_address(hostname_lower)
        if (
            ip.is_loopback
            or ip.is_link_local
            or ip.is_private
            or str(ip) == "169.254.169.254"
        ):
            raise SSRFBlockedError(
                f"Outbound request to IP '{ip}' is denied (SSRF guard)"
            )
    except ValueError:
        pass

    return url
