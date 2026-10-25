import asyncio
import hashlib
import math
import socket
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from uuid import UUID

import pytest
from fastapi import UploadFile
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.api.v1.routes import static_analyses as static_analyses_route
from app.core.config import Settings
from app.main import create_app
from app.schemas.static_analysis import StaticAnalysisResponse
from app.services.static_analysis import ANALYSIS_LIMITATIONS, analyze_static_upload


def post_analysis(
    client: TestClient,
    content: bytes,
    *,
    filename: str = "sample.bin",
    content_type: str = "application/octet-stream",
):
    return client.post(
        "/api/v1/static-analyses/",
        files={"file": (filename, content, content_type)},
    )


def service_arguments(**overrides: int) -> dict[str, int]:
    arguments = {
        "max_bytes": 10 * 1024 * 1024,
        "minimum_string_length": 4,
        "maximum_strings": 100,
        "maximum_string_length": 256,
        "maximum_indicators": 100,
    }
    arguments.update(overrides)
    return arguments


@pytest.mark.contract
def test_unified_report_preserves_all_extractor_results(client: TestClient) -> None:
    content = b"%PDF-1.7\nVisit https://example.test/private and use PowerShell\n"
    response = post_analysis(client, content, filename="lesson.pdf")

    assert response.status_code == 200
    body = response.json()
    assert UUID(body["analysis_id"])
    assert body["analysis_type"] == "static"
    assert body["status"] == "completed"
    assert body["filename"] == "lesson.pdf"
    assert body["fingerprint"] == {
        "sha256": hashlib.sha256(content).hexdigest(),
        "size_bytes": len(content),
        "detected_format": "pdf",
        "format_consistency": "match",
    }
    assert body["content"]["entropy"]["total_bytes"] == len(content)
    assert body["content"]["entropy"]["shannon_entropy"] == pytest.approx(
        -sum(
            (count / len(content)) * math.log2(count / len(content))
            for value in set(content)
            if (count := content.count(value))
        )
    )
    assert body["content"]["strings"]["raw_strings_exposed"] is False
    assert {item["id"] for item in body["indicators"]} == {
        "network.url_candidate",
        "command.powershell_reference",
    }
    assert all(item["source"] == "printable_ascii" for item in body["indicators"])
    assert "verdict" not in body
    assert "risk_score" not in body


@pytest.mark.contract
def test_report_has_aware_ordered_timestamps_and_stable_limitations(
    client: TestClient,
) -> None:
    body = post_analysis(client, b"safe content").json()
    created = datetime.fromisoformat(body["created_at"])
    completed = datetime.fromisoformat(body["completed_at"])

    assert created.utcoffset() is not None
    assert completed.utcoffset() is not None
    assert created.utcoffset() == timedelta(0)
    assert completed.utcoffset() == timedelta(0)
    assert created <= completed
    assert [item["code"] for item in body["analysis_limitations"]] == [
        item.code for item in ANALYSIS_LIMITATIONS
    ]
    assert len(body["analysis_limitations"]) == 7


@pytest.mark.unit
def test_response_schema_rejects_naive_timestamps(client: TestClient) -> None:
    body = post_analysis(client, b"safe content").json()
    body["created_at"] = "2026-10-25T12:00:00"

    with pytest.raises(ValidationError, match="timezone-aware"):
        StaticAnalysisResponse.model_validate(body)


@pytest.mark.unit
def test_response_schema_rejects_non_utc_timestamps(client: TestClient) -> None:
    body = post_analysis(client, b"safe content").json()
    body["completed_at"] = datetime(
        2026,
        10,
        25,
        12,
        tzinfo=timezone(timedelta(hours=-6)),
    ).isoformat()

    with pytest.raises(ValidationError, match="must use UTC"):
        StaticAnalysisResponse.model_validate(body)


@pytest.mark.unit
def test_response_schema_rejects_reversed_timestamps(client: TestClient) -> None:
    body = post_analysis(client, b"safe content").json()
    body["created_at"] = "2026-10-25T12:00:01Z"
    body["completed_at"] = "2026-10-25T12:00:00Z"

    with pytest.raises(ValidationError, match="must not be earlier"):
        StaticAnalysisResponse.model_validate(body)


@pytest.mark.unit
def test_response_schema_rejects_mismatched_byte_counts(client: TestClient) -> None:
    body = post_analysis(client, b"safe content").json()
    body["content"]["entropy"]["total_bytes"] += 1

    with pytest.raises(ValidationError, match="same input"):
        StaticAnalysisResponse.model_validate(body)


@pytest.mark.unit
def test_response_schema_rejects_invalid_analysis_id(client: TestClient) -> None:
    body = post_analysis(client, b"safe content").json()
    body["analysis_id"] = "not-a-uuid"

    with pytest.raises(ValidationError, match="uuid_parsing"):
        StaticAnalysisResponse.model_validate(body)


@pytest.mark.unit
@pytest.mark.parametrize("value", ["A" * 64, "0" * 63])
def test_response_schema_rejects_invalid_sha256(
    client: TestClient,
    value: str,
) -> None:
    body = post_analysis(client, b"safe content").json()
    body["fingerprint"]["sha256"] = value

    with pytest.raises(ValidationError, match="string_pattern_mismatch"):
        StaticAnalysisResponse.model_validate(body)


@pytest.mark.unit
def test_response_schema_rejects_invalid_entropy(client: TestClient) -> None:
    body = post_analysis(client, b"safe content").json()
    body["content"]["entropy"]["shannon_entropy"] = 8.01

    with pytest.raises(ValidationError, match="less_than_equal"):
        StaticAnalysisResponse.model_validate(body)


@pytest.mark.unit
def test_response_schema_prevents_raw_string_exposure(client: TestClient) -> None:
    body = post_analysis(client, b"safe content").json()
    body["content"]["strings"]["raw_strings_exposed"] = True

    with pytest.raises(ValidationError, match="literal_error"):
        StaticAnalysisResponse.model_validate(body)


@pytest.mark.unit
@pytest.mark.parametrize(
    "location",
    [
        "report",
        "fingerprint",
        "content",
        "entropy",
        "strings",
        "indicator",
        "limitation",
    ],
)
def test_response_schema_forbids_unknown_fields(
    client: TestClient,
    location: str,
) -> None:
    body = post_analysis(client, b"PowerShell reference").json()
    if location == "report":
        body["unexpected"] = "value"
    elif location == "fingerprint":
        body["fingerprint"]["unexpected"] = "value"
    elif location == "content":
        body["content"]["unexpected"] = "value"
    elif location == "entropy":
        body["content"]["entropy"]["unexpected"] = "value"
    elif location == "strings":
        body["content"]["strings"]["unexpected"] = "value"
    elif location == "indicator":
        body["indicators"][0]["raw_string"] = "must not be accepted"
    else:
        body["analysis_limitations"][0]["unexpected"] = "value"

    with pytest.raises(ValidationError, match="extra_forbidden"):
        StaticAnalysisResponse.model_validate(body)


@pytest.mark.contract
def test_analysis_ids_are_unique_and_not_retrievable(client: TestClient) -> None:
    first = post_analysis(client, b"same content").json()
    second = post_analysis(client, b"same content").json()

    assert first["analysis_id"] != second["analysis_id"]
    assert (
        client.get(f"/api/v1/static-analyses/{first['analysis_id']}").status_code == 404
    )


@pytest.mark.integration
def test_uniform_binary_report_has_exact_entropy_and_unknown_format(
    client: TestClient,
) -> None:
    content = bytes(range(256)) * 4
    body = post_analysis(client, content).json()

    assert body["content"]["entropy"] == {
        "shannon_entropy": 8.0,
        "total_bytes": 1024,
    }
    assert body["fingerprint"]["detected_format"] == "unknown"
    assert body["fingerprint"]["format_consistency"] == "unknown"
    assert body["indicators"] == []


@pytest.mark.integration
def test_format_mismatch_is_reported_without_a_verdict(client: TestClient) -> None:
    body = post_analysis(client, b"%PDF-safe", filename="image.png").json()

    assert body["fingerprint"]["detected_format"] == "pdf"
    assert body["fingerprint"]["format_consistency"] == "mismatch"


@pytest.mark.integration
def test_string_and_indicator_truncation_propagate() -> None:
    application = create_app(
        Settings(
            APP_ENV="testing",
            INSPECTION_MAX_STRINGS=1,
            INSPECTION_MAX_STRING_LENGTH=16,
            INSPECTION_MAX_INDICATORS=1,
            _env_file=None,
        )
    )
    content = b"http://one.test/a\x00http://two.test/b\x00third-string"
    with TestClient(application) as client:
        body = post_analysis(client, content).json()

    assert body["content"]["strings"]["observed_count"] == 3
    assert body["content"]["strings"]["retained_count"] == 1
    assert body["content"]["strings"]["truncated"] is True
    assert len(body["indicators"]) == 1
    assert body["indicators_truncated"] is False


@pytest.mark.integration
def test_indicator_limit_propagates() -> None:
    application = create_app(
        Settings(
            APP_ENV="testing",
            INSPECTION_MAX_INDICATORS=1,
            _env_file=None,
        )
    )
    with TestClient(application) as client:
        body = post_analysis(
            client,
            b"http://example.test/path PowerShell",
        ).json()

    assert len(body["indicators"]) == 1
    assert body["indicators_truncated"] is True


class CountingBytesIO(BytesIO):
    def __init__(self, content: bytes) -> None:
        super().__init__(content)
        self.bytes_returned = 0
        self.read_sizes: list[int] = []
        self.returned_sizes: list[int] = []

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        value = super().read(size)
        self.bytes_returned += len(value)
        self.returned_sizes.append(len(value))
        return value


@pytest.mark.security
@pytest.mark.parametrize("size", [64 * 1024, 64 * 1024 + 1])
def test_service_consumes_one_forward_stream_at_chunk_boundaries(size: int) -> None:
    stream = CountingBytesIO(b"A" * size)
    upload = UploadFile(file=stream, filename="boundary.bin")

    report = asyncio.run(analyze_static_upload(upload, **service_arguments()))

    assert report.fingerprint.size_bytes == size
    assert stream.bytes_returned == size
    assert stream.returned_sizes[:-1] == [64 * 1024] * (size // (64 * 1024)) + (
        [size % (64 * 1024)] if size % (64 * 1024) else []
    )
    assert stream.returned_sizes[-1] == 0
    assert all(read_size == 64 * 1024 for read_size in stream.read_sizes)
    assert stream.closed


@pytest.mark.security
def test_exact_file_limit_succeeds_and_one_byte_over_is_rejected() -> None:
    application = create_app(
        Settings(APP_ENV="testing", MAX_UPLOAD_BYTES=8, _env_file=None)
    )
    with TestClient(application) as client:
        exact = post_analysis(client, b"12345678")
        oversized = post_analysis(client, b"123456789")

    assert exact.status_code == 200
    assert oversized.status_code == 413


@pytest.mark.security
@pytest.mark.parametrize(
    ("content", "filename", "status_code"),
    [
        (b"", "empty.bin", 422),
        (b"data", "../unsafe.bin", 422),
    ],
)
def test_invalid_uploads_are_rejected_and_closed(
    client: TestClient,
    content: bytes,
    filename: str,
    status_code: int,
) -> None:
    stream = BytesIO(content)
    upload = UploadFile(file=stream, filename=filename)

    with pytest.raises(ValueError):
        asyncio.run(analyze_static_upload(upload, **service_arguments()))

    response = post_analysis(client, content, filename=filename)

    assert stream.closed
    assert response.status_code == status_code


@pytest.mark.security
def test_processing_failure_closes_resource(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = BytesIO(b"content")
    upload = UploadFile(file=stream, filename="sample.bin")

    def fail_update(self: object, chunk: bytes) -> None:
        del self, chunk
        raise RuntimeError("synthetic engine failure")

    monkeypatch.setattr(
        "app.engines.static.fingerprint.FingerprintAccumulator.update",
        fail_update,
    )
    with pytest.raises(RuntimeError, match="synthetic engine failure"):
        asyncio.run(analyze_static_upload(upload, **service_arguments()))

    assert stream.closed


@pytest.mark.security
def test_missing_and_malformed_multipart_are_client_errors(client: TestClient) -> None:
    assert client.post("/api/v1/static-analyses/").status_code == 422
    malformed = client.post(
        "/api/v1/static-analyses/",
        content=b"not multipart",
        headers={"content-type": "multipart/form-data"},
    )
    assert 400 <= malformed.status_code < 500


@pytest.mark.security
def test_unexpected_failure_is_generic_and_closes_upload(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    logged: list[tuple[str, str]] = []

    async def fail(*args: object, **kwargs: object) -> StaticAnalysisResponse:
        del args, kwargs
        raise RuntimeError("sensitive internal context")

    def record_error(message: str, exception_type: str) -> None:
        logged.append((message, exception_type))

    monkeypatch.setattr(static_analyses_route, "analyze_static_upload", fail)
    monkeypatch.setattr(static_analyses_route.logger, "error", record_error)
    response = post_analysis(client, b"safe")

    assert response.status_code == 500
    assert response.json() == {"detail": "Static analysis could not be completed."}
    assert "sensitive" not in response.text
    assert logged == [("Static analysis failed with exception type %s", "RuntimeError")]
    assert "sensitive" not in str(logged)


@pytest.mark.security
def test_unified_analysis_does_not_execute_persist_or_use_network(
    client: TestClient,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "executed"
    content = (
        f"from pathlib import Path; Path({str(marker)!r}).touch(); "
        "http://example.test/private"
    ).encode()

    def reject_network(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "create_connection", reject_network)
    response = post_analysis(client, content, filename="lesson.py")

    assert response.status_code == 200
    assert not marker.exists()
    assert list(tmp_path.iterdir()) == []
    assert content.decode() not in response.text


@pytest.mark.integration
def test_openapi_registers_route_once_and_preserves_existing_endpoints(
    client: TestClient,
) -> None:
    schema = client.get("/openapi.json").json()
    operation = schema["paths"]["/api/v1/static-analyses/"]["post"]

    assert list(schema["paths"]).count("/api/v1/static-analyses/") == 1
    assert operation["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/StaticAnalysisResponse"
    }
    assert "multipart/form-data" in operation["requestBody"]["content"]
    assert {"413", "422", "500"} <= set(operation["responses"])
    assert client.get("/api/v1/health/").status_code == 200
    assert (
        client.post(
            "/api/v1/analyses/validate", json={"filename": "sample.bin"}
        ).status_code
        == 200
    )
    assert post_analysis(client, b"data").status_code == 200
    assert (
        client.post(
            "/api/v1/uploads/", files={"file": ("sample.bin", b"data")}
        ).status_code
        == 201
    )
    assert (
        client.post(
            "/api/v1/fingerprints/", files={"file": ("sample.bin", b"data")}
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/api/v1/content-inspections/",
            files={"file": ("sample.bin", b"data")},
        ).status_code
        == 200
    )
