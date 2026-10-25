import asyncio
import hashlib
import math
import socket
from io import BytesIO
from pathlib import Path

import pytest
from fastapi import UploadFile
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.engines.static.entropy import EntropyAccumulator
from app.engines.static.indicators import inspect_strings
from app.engines.static.strings import ExtractedString, PrintableStringExtractor
from app.main import create_app
from app.services.content_inspection import inspect_content
from app.services.ingestion import EmptyUploadError


def post_inspection(
    client: TestClient,
    content: bytes,
    *,
    filename: str = "sample.bin",
    content_type: str = "application/octet-stream",
):
    return client.post(
        "/api/v1/content-inspections/",
        files={"file": (filename, content, content_type)},
    )


@pytest.mark.unit
def test_repeated_byte_entropy_is_zero() -> None:
    accumulator = EntropyAccumulator()
    accumulator.update(b"A" * 1000)

    assert accumulator.shannon_entropy() == 0.0
    assert accumulator.total_bytes == 1000


@pytest.mark.unit
def test_uniform_byte_distribution_entropy_is_eight() -> None:
    accumulator = EntropyAccumulator()
    accumulator.update(bytes(range(256)) * 4)

    assert accumulator.shannon_entropy() == 8.0
    assert accumulator.total_bytes == 1024


@pytest.mark.unit
def test_mixed_entropy_is_calculated_from_byte_frequencies() -> None:
    accumulator = EntropyAccumulator()
    accumulator.update(b"AAAB")

    expected = -(0.75 * math.log2(0.75) + 0.25 * math.log2(0.25))
    assert accumulator.shannon_entropy() == pytest.approx(expected)


@pytest.mark.unit
def test_empty_entropy_is_explicitly_rejected() -> None:
    with pytest.raises(ValueError, match="undefined for empty"):
        EntropyAccumulator().shannon_entropy()


@pytest.mark.unit
def test_single_byte_and_empty_chunk_entropy() -> None:
    accumulator = EntropyAccumulator()
    accumulator.update(b"")
    accumulator.update(b"Z")

    assert accumulator.shannon_entropy() == 0.0
    assert accumulator.total_bytes == 1


@pytest.mark.unit
def test_multichunk_entropy_matches_single_update_and_stays_finite() -> None:
    content = bytes(range(256)) * 3 + b"tail"
    single = EntropyAccumulator()
    multiple = EntropyAccumulator()
    single.update(content)
    multiple.update(content[:17])
    multiple.update(content[17:500])
    multiple.update(content[500:])

    value = multiple.shannon_entropy()
    assert value == single.shannon_entropy()
    assert multiple.total_bytes == len(content)
    assert math.isfinite(value)
    assert 0 <= value <= 8


def extractor(
    *,
    minimum: int = 4,
    maximum_strings: int = 100,
    maximum_length: int = 256,
) -> PrintableStringExtractor:
    return PrintableStringExtractor(minimum, maximum_strings, maximum_length)


@pytest.mark.unit
def test_printable_ascii_strings_offsets_and_separators() -> None:
    value = extractor()
    value.update(b"\x00ABCD\x01hello world\xffXYZ")
    result = value.finalize()

    assert [(item.text, item.offset) for item in result.strings] == [
        ("ABCD", 1),
        ("hello world", 6),
    ]
    assert result.observed_count == 2
    assert result.truncated is False


@pytest.mark.unit
def test_minimum_string_length_boundary() -> None:
    value = extractor(minimum=4)
    value.update(b"abc\x00abcd")

    assert [item.text for item in value.finalize().strings] == ["abcd"]


@pytest.mark.unit
def test_string_spans_chunk_boundary() -> None:
    value = extractor()
    value.update(b"\x00cross-")
    value.update(b"chunk\x00")

    result = value.finalize()
    assert result.strings[0].text == "cross-chunk"
    assert result.strings[0].offset == 1


@pytest.mark.unit
def test_long_string_is_retained_as_truncated_preview() -> None:
    value = extractor(maximum_length=8)
    value.update(b"abcdefghijklmnop\x00")

    result = value.finalize()
    assert result.strings[0].text == "abcdefgh"
    assert result.strings[0].original_length == 16
    assert result.strings[0].truncated is True
    assert result.truncated is True


@pytest.mark.unit
def test_string_count_is_exact_when_retention_limit_is_reached() -> None:
    value = extractor(maximum_strings=2)
    value.update(b"first\x00second\x00third\x00fourth")

    result = value.finalize()
    assert result.observed_count == 4
    assert [item.text for item in result.strings] == ["first", "second"]
    assert result.truncated is True


@pytest.mark.unit
def test_arbitrary_binary_and_trailing_printable_sequence() -> None:
    value = extractor()
    value.update(bytes(range(32)) + b"tail")

    result = value.finalize()
    assert len(result.strings) == 1
    assert result.strings[0].text == "tail"
    assert result.strings[0].offset == 32


@pytest.mark.unit
def test_extractor_memory_remains_bounded_for_very_long_run() -> None:
    value = extractor(maximum_length=16)
    value.update(b"A" * 100_000)

    result = value.finalize()
    assert len(result.strings[0].text) == 16
    assert result.strings[0].original_length == 100_000


@pytest.mark.parametrize(
    ("minimum", "maximum_strings", "maximum_length", "message"),
    [
        (0, 1, 4, "minimum_length"),
        (1, 0, 4, "maximum_strings"),
        (5, 1, 4, "maximum_length"),
    ],
)
def test_invalid_extractor_limits_are_rejected(
    minimum: int,
    maximum_strings: int,
    maximum_length: int,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        PrintableStringExtractor(minimum, maximum_strings, maximum_length)


def extracted(text: str, offset: int = 0) -> tuple[ExtractedString, ...]:
    return (
        ExtractedString(
            text=text,
            offset=offset,
            original_length=len(text),
            truncated=False,
        ),
    )


@pytest.mark.unit
def test_url_and_ipv4_indicators_are_redacted_and_offset() -> None:
    text = "prefix http://example.test/private?token=secret 192.168.1.42"
    result = inspect_strings(extracted(text, offset=10), maximum_indicators=10)
    by_id = {indicator.id: indicator for indicator in result.indicators}

    assert by_id["network.url_candidate"].evidence == ("http://example.test/[redacted]")
    assert by_id["network.url_candidate"].offset == 17
    assert by_id["network.ipv4_candidate"].evidence == "192.168.1.[redacted]"
    assert "secret" not in " ".join(
        indicator.evidence or "" for indicator in result.indicators
    )


@pytest.mark.unit
def test_malformed_url_candidate_is_safely_redacted() -> None:
    result = inspect_strings(extracted("http://a[invalid/path"), maximum_indicators=10)

    assert result.indicators[0].evidence == "http://[redacted-host]/[redacted]"


@pytest.mark.unit
def test_invalid_ipv4_candidate_is_not_reported() -> None:
    result = inspect_strings(extracted("address 999.1.2.3"), maximum_indicators=10)

    assert all(item.id != "network.ipv4_candidate" for item in result.indicators)


@pytest.mark.unit
def test_command_and_file_references_are_informational() -> None:
    text = "Benign docs: PowerShell -EncodedCommand cmd.exe tool.exe setup.ps1"
    result = inspect_strings(extracted(text), maximum_indicators=10)
    ids = {indicator.id for indicator in result.indicators}

    assert ids == {
        "command.powershell_reference",
        "command.encoded_command_token",
        "command.interpreter_reference",
        "file.executable_reference",
        "file.script_reference",
    }
    assert all(item.severity == "informational" for item in result.indicators)
    assert all(
        "malicious" not in item.description.lower() for item in result.indicators
    )
    assert (
        sum(item.id == "command.encoded_command_token" for item in result.indicators)
        == 1
    )


@pytest.mark.unit
def test_duplicate_evidence_is_reported_once() -> None:
    result = inspect_strings(
        extracted("powershell then powershell then POWERSHELL"),
        maximum_indicators=10,
    )

    assert [item.id for item in result.indicators] == ["command.powershell_reference"]


@pytest.mark.unit
def test_indicator_output_limit_is_explicit() -> None:
    value = tuple(
        ExtractedString(
            text=f"http://host{index}.test/path",
            offset=index * 30,
            original_length=25,
            truncated=False,
        )
        for index in range(5)
    )

    result = inspect_strings(value, maximum_indicators=2)
    assert len(result.indicators) == 2
    assert result.truncated is True


@pytest.mark.unit
def test_no_indicator_candidates_and_invalid_limit() -> None:
    assert inspect_strings(extracted("ordinary text"), 10).indicators == ()
    with pytest.raises(ValueError, match="maximum_indicators"):
        inspect_strings(extracted("ordinary text"), 0)


@pytest.mark.unit
def test_indicator_detection_survives_source_chunk_boundary() -> None:
    value = extractor()
    value.update(b"use Power")
    value.update(b"Shell safely\x00")
    strings = value.finalize().strings

    result = inspect_strings(strings, maximum_indicators=10)
    assert result.indicators[0].id == "command.powershell_reference"


@pytest.mark.contract
def test_valid_text_content_inspection(client: TestClient) -> None:
    content = b"Visit http://example.test/path then use PowerShell -EncodedCommand demo"
    response = post_inspection(client, content, filename="notes.txt")

    assert response.status_code == 200
    body = response.json()
    assert body["filename"] == "notes.txt"
    assert body["size_bytes"] == len(content)
    assert body["sha256"] == hashlib.sha256(content).hexdigest()
    assert body["detected_format"] == "unknown"
    assert body["entropy"]["total_bytes"] == len(content)
    assert body["strings"]["observed_count"] == 1
    assert body["strings"]["retained_count"] == 1
    assert body["strings"]["raw_strings_exposed"] is False
    assert "values" not in body["strings"]
    assert {item["id"] for item in body["indicators"]} >= {
        "network.url_candidate",
        "command.powershell_reference",
        "command.encoded_command_token",
    }


@pytest.mark.contract
def test_valid_binary_content_has_accurate_entropy(client: TestClient) -> None:
    content = bytes(range(256)) * 4
    response = post_inspection(client, content)

    assert response.status_code == 200
    assert response.json()["entropy"] == {
        "shannon_entropy": 8.0,
        "total_bytes": len(content),
    }


@pytest.mark.security
def test_empty_content_inspection_is_rejected(client: TestClient) -> None:
    assert post_inspection(client, b"").status_code == 422


@pytest.mark.security
def test_oversized_content_inspection_is_rejected() -> None:
    application = create_app(
        Settings(APP_ENV="testing", MAX_UPLOAD_BYTES=8, _env_file=None)
    )
    with TestClient(application) as client:
        response = post_inspection(client, b"123456789")

    assert response.status_code == 413


@pytest.mark.security
def test_invalid_filename_is_rejected(client: TestClient) -> None:
    assert post_inspection(client, b"data", filename="../unsafe.bin").status_code == 422


@pytest.mark.security
def test_missing_file_is_rejected(client: TestClient) -> None:
    assert client.post("/api/v1/content-inspections/").status_code == 422


@pytest.mark.security
def test_malformed_content_inspection_multipart(client: TestClient) -> None:
    response = client.post(
        "/api/v1/content-inspections/",
        content=b"not multipart",
        headers={"content-type": "multipart/form-data"},
    )

    assert 400 <= response.status_code < 500


@pytest.mark.security
def test_content_inspection_closes_resource_after_success_and_failure() -> None:
    valid = UploadFile(file=BytesIO(b"safe text"), filename="safe.txt")
    empty = UploadFile(file=BytesIO(b""), filename="empty.bin")
    arguments = {
        "max_bytes": 100,
        "minimum_string_length": 4,
        "maximum_strings": 10,
        "maximum_string_length": 20,
        "maximum_indicators": 10,
    }

    asyncio.run(inspect_content(valid, **arguments))
    with pytest.raises(EmptyUploadError):
        asyncio.run(inspect_content(empty, **arguments))

    assert valid.file.closed
    assert empty.file.closed


@pytest.mark.security
def test_content_is_not_executed_persisted_or_sent_to_network(
    client: TestClient,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "executed"
    payload = f"from pathlib import Path; Path({str(marker)!r}).touch()".encode()

    def reject_network(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "create_connection", reject_network)
    response = post_inspection(client, payload, filename="payload.py")

    assert response.status_code == 200
    assert not marker.exists()
    assert list(tmp_path.iterdir()) == []


@pytest.mark.integration
def test_content_inspection_openapi_and_existing_endpoints(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    operation = schema["paths"]["/api/v1/content-inspections/"]["post"]

    assert operation["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/ContentInspectionResponse"
    }
    assert "multipart/form-data" in operation["requestBody"]["content"]
    assert "413" in operation["responses"]
    assert client.get("/api/v1/health/").status_code == 200
    assert (
        client.post(
            "/api/v1/analyses/validate",
            json={"filename": "sample.bin"},
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/api/v1/uploads/",
            files={"file": ("sample.bin", b"data")},
        ).status_code
        == 201
    )
    assert (
        client.post(
            "/api/v1/fingerprints/",
            files={"file": ("sample.bin", b"data")},
        ).status_code
        == 200
    )
