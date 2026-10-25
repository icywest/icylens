from enum import Enum
from urllib.parse import unquote


class AnalysisStatus(str, Enum):
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class ThreatVerdict(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    HIGHLY_SUSPICIOUS = "highly_suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class AnalysisEngine(str, Enum):
    STATIC = "static"
    MACHINE_LEARNING = "machine_learning"
    VULNERABILITY = "vulnerability"
    BEHAVIORAL = "behavioral"
    CORRELATION = "correlation"


def validate_filename(value: str) -> str:
    """Validate an untrusted client filename as metadata, never as a path."""
    if not value:
        raise ValueError("filename is required")
    # Defensively decode percent-encoding to catch encoded control characters
    try:
        decoded = unquote(value)
    except Exception:
        decoded = value
    for candidate in (decoded, value):
        if any(ord(character) < 32 or ord(character) == 127 for character in candidate):
            raise ValueError("filename must not contain control characters")
        if any(not character.isprintable() for character in candidate):
            raise ValueError("filename must not contain control characters")
    if len(value) > 255:
        raise ValueError("filename must contain at most 255 characters")
    if "/" in value or "\\" in value:
        raise ValueError("filename must not contain path separators")
    if value in {".", ".."}:
        raise ValueError("filename must be a file name, not a path component")
    return value
