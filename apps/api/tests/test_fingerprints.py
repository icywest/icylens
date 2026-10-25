import asyncio
import hashlib
import socket
from io import BytesIO
from pathlib import Path

import pytest
from fastapi import UploadFile
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import Settings
from app.engines.static.fingerprint import (
    compare_format,
    fingerprint_chunks,
)
from app.engines.static.signatures import detect_signature
from app.main import create_app
from app.schemas.fingerprint import FingerprintResponse
from app.services.ingestion import (
    UPLOAD_READ_CHUNK_BYTES,
    EmptyUploadError,
    fingerprint_upload,
)

PDF_SAMPLE = b"%PDF-1.7\nsynthetic document\n"
PNG_SAMPLE = b"\x89PNG\r\n\x1a\nsynthetic image"
UNKNOWN_SAMPLE = b"\x01\x02safe synthetic bytes"


def post_fingerprint(
    client: TestClient,
    content: bytes,
    *,
    filename: str = "sample.bin",
    content_type: str = "application/octet-stream",
):
    return client.post(
        "/api/v1/fingerprints/",
        files={"file": (filename, content, content_type)},
    )


@pytest.mark.unit
def test_known_sha256_vector() -> None:
    result = fingerprint_chunks([b"abc"], "vector.bin")

    assert result.sha256 == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    assert len(result.sha256) == 64
    assert result.sha256 == result.sha256.lower()


@pytest.mark.unit
def test_incremental_hash_matches_single_chunk_for_binary_payload() -> None:
    payload = bytes(range(256)) * 300
    single = fingerprint_chunks([payload], "sample.bin")
    multiple = fingerprint_chunks(
        [payload[:123], payload[123:65536], payload[65536:]],
        "sample.bin",
    )

    assert single.sha256 == hashlib.sha256(payload).hexdigest()
    assert multiple.sha256 == single.sha256
    assert multiple.size_bytes == len(payload)


@pytest.mark.unit
def test_hashes_are_deterministic_and_content_sensitive() -> None:
    first = fingerprint_chunks([b"identical"], "first.bin")
    second = fingerprint_chunks([b"identical"], "second.bin")
    different = fingerprint_chunks([b"different"], "first.bin")

    assert first.sha256 == second.sha256
    assert first.sha256 != different.sha256


@pytest.mark.unit
def test_accumulator_handles_exact_chunk_boundaries() -> None:
    payload = b"A" * (UPLOAD_READ_CHUNK_BYTES * 2)
    result = fingerprint_chunks(
        [
            payload[:UPLOAD_READ_CHUNK_BYTES],
            payload[UPLOAD_READ_CHUNK_BYTES:],
        ],
        "boundary.bin",
    )

    assert result.size_bytes == len(payload)
    assert result.sha256 == hashlib.sha256(payload).hexdigest()


@pytest.mark.parametrize(
    ("content", "expected_format", "expected_name"),
    [
        (PDF_SAMPLE, "pdf", "PDF"),
        (PNG_SAMPLE, "png", "PNG"),
        (b"\xff\xd8\xffsynthetic", "jpeg", "JPEG"),
        (b"GIF87asynthetic", "gif", "GIF87a"),
        (b"GIF89asynthetic", "gif", "GIF89a"),
        (b"PK\x03\x04synthetic", "zip", "ZIP local file header"),
        (b"PK\x05\x06synthetic", "zip", "ZIP empty archive"),
        (b"PK\x07\x08synthetic", "zip", "ZIP data descriptor"),
        (b"\x7fELFsynthetic", "elf", "ELF"),
    ],
)
def test_supported_leading_signatures(
    content: bytes,
    expected_format: str,
    expected_name: str,
) -> None:
    match = detect_signature(content)

    assert match.format == expected_format
    assert match.name == expected_name
    assert match.offset == 0
    assert match.signature is not None


def make_pe_sample(pe_offset: int = 0x80) -> bytes:
    content = bytearray(pe_offset + 4)
    content[:2] = b"MZ"
    content[0x3C:0x40] = pe_offset.to_bytes(4, byteorder="little")
    content[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    return bytes(content)


@pytest.mark.unit
def test_valid_pe_candidate_requires_checked_offset_and_signature() -> None:
    match = detect_signature(make_pe_sample())

    assert match.format == "pe"
    assert match.name == "Windows PE candidate"
    assert match.offset == 0x80
    assert match.signature == b"PE\x00\x00"


@pytest.mark.parametrize(
    "content",
    [
        b"MZ",
        b"MZ" + b"\x00" * 70,
        b"%PDF",
        b"\x89PNG\r\n",
        b"\xff\xd8",
        b"GIF89",
        b"PK\x03",
        b"\x7fEL",
        UNKNOWN_SAMPLE,
    ],
)
def test_truncated_invalid_and_unknown_signatures_are_unknown(content: bytes) -> None:
    assert detect_signature(content).format == "unknown"


@pytest.mark.unit
def test_pe_offset_must_point_inside_bounded_header() -> None:
    content = bytearray(128)
    content[:2] = b"MZ"
    content[0x3C:0x40] = (4094).to_bytes(4, byteorder="little")

    assert detect_signature(bytes(content)).format == "unknown"


@pytest.mark.unit
def test_leading_signature_has_deterministic_priority_for_polyglot_bytes() -> None:
    content = b"%PDF-1.7\n" + b"PK\x03\x04embedded"

    assert detect_signature(content).format == "pdf"


@pytest.mark.parametrize(
    ("filename", "content", "expected"),
    [
        ("document.pdf", PDF_SAMPLE, "match"),
        ("photo.jpeg", b"\xff\xd8\xffdata", "match"),
        ("program.dll", make_pe_sample(), "match"),
        ("document.pdf", make_pe_sample(), "mismatch"),
        ("archive.bin", b"PK\x03\x04data", "unknown"),
        ("unknown.pdf", UNKNOWN_SAMPLE, "unknown"),
        ("README", PDF_SAMPLE, "unknown"),
    ],
)
def test_extension_consistency_states(
    filename: str,
    content: bytes,
    expected: str,
) -> None:
    assert fingerprint_chunks([content], filename).format_consistency == expected


@pytest.mark.unit
def test_compare_format_covers_known_mismatch() -> None:
    assert compare_format(".png", "gif") == "mismatch"


@pytest.mark.unit
def test_fingerprint_schema_rejects_invalid_digest() -> None:
    with pytest.raises(ValidationError):
        FingerprintResponse(
            filename="sample.bin",
            sha256="not-a-digest",
            size_bytes=1,
            detected_format="unknown",
            signature_name=None,
            extension=".bin",
            format_consistency="unknown",
        )


@pytest.mark.contract
@pytest.mark.parametrize(
    ("filename", "content", "detected_format", "consistency"),
    [
        ("document.pdf", PDF_SAMPLE, "pdf", "match"),
        ("image.png", PNG_SAMPLE, "png", "match"),
        ("opaque.bin", UNKNOWN_SAMPLE, "unknown", "unknown"),
        ("disguised.pdf", make_pe_sample(), "pe", "mismatch"),
    ],
)
def test_fingerprint_endpoint_returns_real_typed_results(
    client: TestClient,
    filename: str,
    content: bytes,
    detected_format: str,
    consistency: str,
) -> None:
    response = post_fingerprint(client, content, filename=filename)

    assert response.status_code == 200
    body = response.json()
    assert body["filename"] == filename
    assert body["sha256"] == hashlib.sha256(content).hexdigest()
    assert body["size_bytes"] == len(content)
    assert body["detected_format"] == detected_format
    assert body["format_consistency"] == consistency
    assert set(body) == {
        "filename",
        "sha256",
        "size_bytes",
        "detected_format",
        "signature_name",
        "extension",
        "format_consistency",
        "signature_offset",
        "signature_hex",
    }


@pytest.mark.security
def test_fingerprint_endpoint_rejects_empty_file(client: TestClient) -> None:
    response = post_fingerprint(client, b"")

    assert response.status_code == 422


@pytest.mark.security
def test_fingerprint_endpoint_rejects_oversized_file() -> None:
    application = create_app(
        Settings(APP_ENV="testing", MAX_UPLOAD_BYTES=8, _env_file=None)
    )
    with TestClient(application) as client:
        response = post_fingerprint(client, b"123456789")

    assert response.status_code == 413


@pytest.mark.security
def test_fingerprint_endpoint_accepts_exact_configured_maximum() -> None:
    maximum = UPLOAD_READ_CHUNK_BYTES * 2
    content = b"A" * maximum
    application = create_app(
        Settings(APP_ENV="testing", MAX_UPLOAD_BYTES=maximum, _env_file=None)
    )
    with TestClient(application) as client:
        response = post_fingerprint(client, content)

    assert response.status_code == 200
    assert response.json()["size_bytes"] == maximum
    assert response.json()["sha256"] == hashlib.sha256(content).hexdigest()


@pytest.mark.security
def test_fingerprint_endpoint_rejects_invalid_filename(client: TestClient) -> None:
    response = post_fingerprint(client, b"data", filename="../sample.bin")

    assert response.status_code == 422


@pytest.mark.security
def test_fingerprint_endpoint_handles_malformed_multipart(client: TestClient) -> None:
    response = client.post(
        "/api/v1/fingerprints/",
        content=b"not multipart",
        headers={"content-type": "multipart/form-data"},
    )

    assert 400 <= response.status_code < 500


@pytest.mark.security
def test_fingerprint_read_is_bounded_and_resource_is_closed() -> None:
    class RecordingFile(BytesIO):
        _rolled = False

        def __init__(self, content: bytes) -> None:
            super().__init__(content)
            self.read_sizes: list[int] = []

        def read(self, size: int = -1) -> bytes:
            self.read_sizes.append(size)
            return super().read(size)

    content = b"A" * (UPLOAD_READ_CHUNK_BYTES * 2)
    stream = RecordingFile(content)
    uploaded = UploadFile(file=stream, filename="sample.bin")

    result = asyncio.run(fingerprint_upload(uploaded, len(content)))

    assert result.size_bytes == len(content)
    assert stream.read_sizes == [
        UPLOAD_READ_CHUNK_BYTES,
        UPLOAD_READ_CHUNK_BYTES,
        1,
    ]
    assert stream.closed


@pytest.mark.security
def test_fingerprint_cleanup_on_failure() -> None:
    uploaded = UploadFile(file=BytesIO(b""), filename="sample.bin")

    with pytest.raises(EmptyUploadError):
        asyncio.run(fingerprint_upload(uploaded, 10))

    assert uploaded.file.closed


@pytest.mark.security
def test_fingerprinting_does_not_execute_persist_or_open_network(
    client: TestClient,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "executed"
    payload = f"from pathlib import Path; Path({str(marker)!r}).touch()".encode()

    def reject_network(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("external network access attempted")

    monkeypatch.setattr(socket, "create_connection", reject_network)
    response = post_fingerprint(client, payload, filename="payload.py")

    assert response.status_code == 200
    assert not marker.exists()
    assert list(tmp_path.iterdir()) == []


@pytest.mark.integration
def test_fingerprint_openapi_contract_and_regressions(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    operation = schema["paths"]["/api/v1/fingerprints/"]["post"]

    assert operation["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/FingerprintResponse"
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


@pytest.mark.integration
def test_existing_upload_response_contract_is_unchanged(client: TestClient) -> None:
    response = client.post(
        "/api/v1/uploads/",
        files={"file": ("sample.bin", b"data", "application/octet-stream")},
    )

    assert response.status_code == 201
    assert set(response.json()) == {
        "upload_id",
        "filename",
        "size_bytes",
        "content_type",
        "status",
        "persisted",
    }
