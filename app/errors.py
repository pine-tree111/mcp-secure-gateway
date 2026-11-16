"""Domain exception hierarchy for mcp-secure-gateway.

All domain exceptions inherit from MCPGuardError.
"""


class MCPGuardError(Exception):
    """Base exception for all mcp-secure-gateway errors."""


class SecurityViolationError(MCPGuardError):
    """AST mutation, dangerous function, path traversal, blacklist, or SSRF attempt."""


class QueryTimeoutError(MCPGuardError):
    """Query exceeded opcode evaluation or execution time threshold."""


class PathTraversalError(SecurityViolationError):
    """Database or file path escapes the authorized project root."""


class SensitiveFileError(SecurityViolationError):
    """File matches the sensitive file blacklist."""


class SSRFBlockedError(SecurityViolationError):
    """URL targets a blocked endpoint (cloud metadata, loopback)."""


class PayloadTooLargeError(MCPGuardError):
    """Serialized result exceeds max_payload_bytes or max_agent_file_bytes."""
