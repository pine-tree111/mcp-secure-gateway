"""Unit tests for path containment, sensitive file blacklist, and SSRF validation."""

from pathlib import Path

import pytest

from app.errors import (
    PathTraversalError,
    PayloadTooLargeError,
    SecurityViolationError,
    SensitiveFileError,
    SSRFBlockedError,
)
from app.security import (
    is_sensitive_file,
    read_safe_file,
    resolve_safe_path,
    validate_url,
)


def test_is_sensitive_file_detection() -> None:
    """Verify blacklist catches common credential and sensitive file patterns."""
    assert is_sensitive_file(".env")
    assert is_sensitive_file(".env.production")
    assert is_sensitive_file("id_rsa")
    assert is_sensitive_file("id_ed25519")
    assert is_sensitive_file("server.key")
    assert is_sensitive_file("cert.pem")
    assert is_sensitive_file(".git/config")
    assert is_sensitive_file(".aws/credentials")
    assert is_sensitive_file("app.token")

    # Benign filenames must not trigger false positives
    assert not is_sensitive_file("README.md")
    assert not is_sensitive_file("data.csv")
    assert not is_sensitive_file("notes.txt")


def test_resolve_safe_path_valid(tmp_path: Path) -> None:
    """Verify safe relative path resolution within sandbox."""
    doc = tmp_path / "report.txt"
    doc.write_text("hello", encoding="utf-8")

    resolved = resolve_safe_path("report.txt", tmp_path)
    assert resolved == doc


def test_resolve_safe_path_subfolder(tmp_path: Path) -> None:
    """Verify safe nested path resolution."""
    sub = tmp_path / "sub"
    sub.mkdir()
    doc = sub / "doc.md"
    doc.write_text("nested", encoding="utf-8")

    resolved = resolve_safe_path("sub/doc.md", tmp_path)
    assert resolved == doc


def test_resolve_safe_path_traversal_blocked(tmp_path: Path) -> None:
    """Verify directory traversal attempts raise PathTraversalError."""
    with pytest.raises(PathTraversalError, match="escapes sandbox boundary"):
        resolve_safe_path("../outside.txt", tmp_path)

    with pytest.raises(PathTraversalError, match="escapes sandbox boundary"):
        resolve_safe_path("sub/../../outside.txt", tmp_path)


def test_resolve_safe_path_null_byte_blocked(tmp_path: Path) -> None:
    """Verify null bytes in path raise PathTraversalError."""
    with pytest.raises(PathTraversalError, match="Null byte detected"):
        resolve_safe_path("doc.txt\0evil.txt", tmp_path)


def test_resolve_safe_path_blacklist_blocked(tmp_path: Path) -> None:
    """Verify blacklisted file access raises SensitiveFileError."""
    env_file = tmp_path / ".env"
    env_file.write_text("SECRET=123", encoding="utf-8")

    with pytest.raises(SensitiveFileError, match="strictly denied"):
        resolve_safe_path(".env", tmp_path)


def test_resolve_safe_path_nonexistent_raises(tmp_path: Path) -> None:
    """Verify nonexistent file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        resolve_safe_path("missing.txt", tmp_path)


def test_read_safe_file_success(tmp_path: Path) -> None:
    """Verify reading a safe file returns exact bytes."""
    target = tmp_path / "sample.txt"
    target.write_bytes(b"content 12345")

    content = read_safe_file("sample.txt", tmp_path)
    assert content == b"content 12345"


def test_read_safe_file_payload_too_large(tmp_path: Path) -> None:
    """Verify file exceeding size ceiling raises PayloadTooLargeError."""
    target = tmp_path / "large.bin"
    target.write_bytes(b"A" * 1024)

    with pytest.raises(PayloadTooLargeError, match="exceeds maximum ceiling"):
        read_safe_file("large.bin", tmp_path, max_agent_file_bytes=512)


def test_read_safe_file_directory_rejected(tmp_path: Path) -> None:
    """Verify attempting to read a directory raises IsADirectoryError."""
    sub = tmp_path / "folder"
    sub.mkdir()

    with pytest.raises(IsADirectoryError):
        read_safe_file("folder", tmp_path)


def test_validate_url_valid() -> None:
    """Verify benign public URLs pass validation."""
    assert (
        validate_url("https://example.com/api/data") == "https://example.com/api/data"
    )
    assert (
        validate_url("http://api.github.com/events") == "http://api.github.com/events"
    )


def test_validate_url_cloud_metadata_blocked() -> None:
    """Verify AWS and GCP cloud metadata endpoints are rejected."""
    with pytest.raises(SSRFBlockedError, match="SSRF guard"):
        validate_url("http://169.254.169.254/latest/meta-data/")

    with pytest.raises(SSRFBlockedError, match="SSRF guard"):
        validate_url("http://metadata.google.internal/computeMetadata/v1/")


def test_validate_url_loopback_blocked() -> None:
    """Verify local loopback targets are rejected."""
    with pytest.raises(SSRFBlockedError, match="SSRF guard"):
        validate_url("http://127.0.0.1:8000/mcp")

    with pytest.raises(SSRFBlockedError, match="SSRF guard"):
        validate_url("http://localhost:3000")


def test_validate_url_invalid_schemes() -> None:
    """Verify non-HTTP schemes are rejected."""
    with pytest.raises(SecurityViolationError, match="Unsupported URL scheme"):
        validate_url("file:///etc/passwd")

    with pytest.raises(SecurityViolationError, match="Unsupported URL scheme"):
        validate_url("ftp://example.com/file")
