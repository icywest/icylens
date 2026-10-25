from enum import Enum


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
