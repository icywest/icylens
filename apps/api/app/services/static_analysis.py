from datetime import UTC, datetime
from uuid import uuid4

from fastapi import UploadFile

from app.engines.static.fingerprint import compare_format, extract_extension
from app.schemas.static_analysis import (
    AnalysisLimitation,
    StaticAnalysisContent,
    StaticAnalysisFingerprint,
    StaticAnalysisResponse,
)
from app.services.content_inspection import inspect_content

ANALYSIS_LIMITATIONS = (
    AnalysisLimitation(
        code="static_only",
        description="Analysis is limited to static inspection.",
    ),
    AnalysisLimitation(
        code="no_execution",
        description="Uploaded content was not executed.",
    ),
    AnalysisLimitation(
        code="no_malware_verdict",
        description="Findings are descriptive and are not a malware verdict.",
    ),
    AnalysisLimitation(
        code="format_not_validity",
        description="Format identification does not prove structural validity.",
    ),
    AnalysisLimitation(
        code="entropy_not_maliciousness",
        description="Entropy does not establish maliciousness.",
    ),
    AnalysisLimitation(
        code="text_indicators_may_be_benign",
        description="Textual indicators can occur in benign files.",
    ),
    AnalysisLimitation(
        code="configured_bounds_apply",
        description=(
            "Inspection is limited by configured upload, extraction, and pattern "
            "bounds."
        ),
    ),
)


async def analyze_static_upload(
    upload: UploadFile,
    max_bytes: int,
    minimum_string_length: int,
    maximum_strings: int,
    maximum_string_length: int,
    maximum_indicators: int,
) -> StaticAnalysisResponse:
    """Adapt the existing single-pass inspection into one unified report."""
    analysis_id = uuid4()
    created_at = datetime.now(UTC)
    inspection = await inspect_content(
        upload,
        max_bytes=max_bytes,
        minimum_string_length=minimum_string_length,
        maximum_strings=maximum_strings,
        maximum_string_length=maximum_string_length,
        maximum_indicators=maximum_indicators,
    )
    completed_at = datetime.now(UTC)
    if completed_at < created_at:
        completed_at = created_at
    extension = extract_extension(inspection.filename)

    return StaticAnalysisResponse(
        analysis_id=analysis_id,
        analysis_type="static",
        status="completed",
        filename=inspection.filename,
        created_at=created_at,
        completed_at=completed_at,
        fingerprint=StaticAnalysisFingerprint(
            sha256=inspection.sha256,
            size_bytes=inspection.size_bytes,
            detected_format=inspection.detected_format,
            format_consistency=compare_format(
                extension,
                inspection.detected_format,
            ),
        ),
        content=StaticAnalysisContent(
            entropy=inspection.entropy,
            strings=inspection.strings,
        ),
        indicators=inspection.indicators,
        indicators_truncated=inspection.indicators_truncated,
        analysis_limitations=list(ANALYSIS_LIMITATIONS),
    )
