from fastapi import UploadFile

from app.engines.static.entropy import EntropyAccumulator
from app.engines.static.fingerprint import FingerprintAccumulator
from app.engines.static.indicators import inspect_strings
from app.engines.static.strings import PrintableStringExtractor
from app.schemas.content_inspection import (
    ContentInspectionResponse,
    EntropySummary,
    StringExtractionSummary,
)
from app.services.ingestion import consume_upload


async def inspect_content(
    upload: UploadFile,
    max_bytes: int,
    minimum_string_length: int,
    maximum_strings: int,
    maximum_string_length: int,
    maximum_indicators: int,
) -> ContentInspectionResponse:
    """Extract bounded static features during one safe ingestion pass."""
    fingerprint = FingerprintAccumulator()
    entropy = EntropyAccumulator()
    strings = PrintableStringExtractor(
        minimum_length=minimum_string_length,
        maximum_strings=maximum_strings,
        maximum_length=maximum_string_length,
    )

    def update(chunk: bytes) -> None:
        fingerprint.update(chunk)
        entropy.update(chunk)
        strings.update(chunk)

    metadata = await consume_upload(upload, max_bytes, update)
    fingerprint_result = fingerprint.finalize(metadata.filename)
    string_result = strings.finalize()
    indicator_result = inspect_strings(
        string_result.strings,
        maximum_indicators=maximum_indicators,
    )

    return ContentInspectionResponse(
        filename=metadata.filename,
        size_bytes=metadata.size_bytes,
        sha256=fingerprint_result.sha256,
        detected_format=fingerprint_result.detected_format,
        entropy=EntropySummary(
            shannon_entropy=entropy.shannon_entropy(),
            total_bytes=entropy.total_bytes,
        ),
        strings=StringExtractionSummary(
            observed_count=string_result.observed_count,
            retained_count=len(string_result.strings),
            truncated=string_result.truncated,
            raw_strings_exposed=False,
            minimum_length=minimum_string_length,
            maximum_retained_strings=maximum_strings,
            maximum_characters_per_string=maximum_string_length,
        ),
        indicators=list(indicator_result.indicators),
        indicators_truncated=indicator_result.truncated,
    )
