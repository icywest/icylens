import asyncio
from io import BytesIO
from pathlib import Path
from uuid import UUID

import pytest
from fastapi import UploadFile
from fastapi.testclient import TestClient

from app.api.v1.routes import uploads as uploads_route
from app.core.config import Settings
from app.main import create_app
from app.services.ingestion import (
    EmptyUploadError,
    InvalidFilenameError,
    ingest_upload,
)

pytestmark = pytest.mark.security


def upload(
    client: TestClient,
    content: bytes,
    *,
    filename: str = "sample.txt",
    content_type: str = "text/plain",
):
    return client.post(
        "/api/v1/uploads/",
        files={"file": (filename, content, content_type)},
    )


def test_valid_text_upload_returns_measured_non_persisted_metadata(
    client: TestClient,
) -> None:
    content = "contenido seguro\n".encode()

    response = upload(client, content)

    assert response.status_code == 201
    body = response.json()
    assert UUID(body["upload_id"])
    assert body == {
        "upload_id": body["upload_id"],
        "filename": "sample.txt",
        "size_bytes": len(content),
        "content_type": "text/plain",
        "status": "validated",
        "persisted": False,
    }


def test_binary_upload_is_accepted_without_format_detection(client: TestClient) -> None:
    content = bytes(range(256))

    response = upload(
        client,
        content,
        filename="opaque.bin",
        content_type="application/x-made-up-format",
    )

    assert response.status_code == 201
    assert response.json()["size_bytes"] == 256
    assert response.json()["content_type"] == "application/x-made-up-format"


def test_upload_ids_are_generated_per_operation(client: TestClient) -> None:
    first = upload(client, b"same bytes").json()["upload_id"]
    second = upload(client, b"same bytes").json()["upload_id"]

    assert UUID(first) != UUID(second)


def test_empty_upload_is_rejected(client: TestClient) -> None:
    response = upload(client, b"")

    assert response.status_code == 422
    assert response.json() == {"detail": "file must not be empty"}


def test_missing_file_field_is_rejected(client: TestClient) -> None:
    response = client.post("/api/v1/uploads/", files={"other": ("x", b"data")})

    assert response.status_code == 422


def test_file_over_limit_is_rejected_with_413() -> None:
    application = create_app(
        Settings(APP_ENV="testing", MAX_UPLOAD_BYTES=8, _env_file=None)
    )

    with TestClient(application) as client:
        response = upload(client, b"123456789")

    assert response.status_code == 413
    assert response.json() == {"detail": "file exceeds the maximum size of 8 bytes"}


def test_file_exactly_at_limit_is_accepted() -> None:
    application = create_app(
        Settings(APP_ENV="testing", MAX_UPLOAD_BYTES=8, _env_file=None)
    )

    with TestClient(application) as client:
        response = upload(client, b"12345678")

    assert response.status_code == 201
    assert response.json()["size_bytes"] == 8


@pytest.mark.parametrize(
    "filename",
    [
        "directory/file.bin",
        "directory\\file.bin",
        ".",
        "..",
        "a" * 256,
    ],
    ids=["slash", "backslash", "dot", "dot-dot", "too-long"],
)
def test_invalid_upload_filename_is_rejected(
    client: TestClient,
    filename: str,
) -> None:
    response = upload(client, b"data", filename=filename)

    assert response.status_code == 422


@pytest.mark.parametrize(
    "filename",
    [b"nul\x00byte.bin", b"control\x01byte.bin"],
    ids=["nul", "control"],
)
def test_raw_multipart_control_character_filename_is_rejected(
    client: TestClient,
    filename: bytes,
) -> None:
    boundary = b"icylens-test-boundary"
    body = (
        b"--"
        + boundary
        + b'\r\nContent-Disposition: form-data; name="file"; filename="'
        + filename
        + b'"\r\nContent-Type: application/octet-stream\r\n\r\ndata\r\n--'
        + boundary
        + b"--\r\n"
    )

    response = client.post(
        "/api/v1/uploads/",
        content=body,
        headers={"content-type": f"multipart/form-data; boundary={boundary.decode()}"},
    )

    assert response.status_code == 422


def test_malformed_multipart_is_a_client_error(client: TestClient) -> None:
    response = client.post(
        "/api/v1/uploads/",
        content=b"not a multipart document",
        headers={"content-type": "multipart/form-data"},
    )

    assert 400 <= response.status_code < 500


def test_uploaded_content_is_not_executed_or_persisted(
    client: TestClient,
    tmp_path: Path,
) -> None:
    marker = tmp_path / "execution-marker"
    source = f"from pathlib import Path; Path({str(marker)!r}).touch()".encode()

    response = upload(client, source, filename="payload.py")

    assert response.status_code == 201
    assert response.json()["persisted"] is False
    assert not marker.exists()


def test_ingestion_closes_upload_after_success() -> None:
    uploaded = UploadFile(
        file=BytesIO(b"data"),
        filename="sample.bin",
        headers={"content-type": "application/octet-stream"},
    )

    result = asyncio.run(ingest_upload(uploaded, max_bytes=10))

    assert result.size_bytes == 4
    assert uploaded.file.closed


def test_ingestion_closes_upload_after_validation_error() -> None:
    uploaded = UploadFile(file=BytesIO(b""), filename="sample.bin")

    with pytest.raises(EmptyUploadError):
        asyncio.run(ingest_upload(uploaded, max_bytes=10))

    assert uploaded.file.closed


def test_ingestion_rejects_missing_filename_and_closes_upload() -> None:
    uploaded = UploadFile(file=BytesIO(b"data"), filename=None)

    with pytest.raises(InvalidFilenameError, match="filename is required"):
        asyncio.run(ingest_upload(uploaded, max_bytes=10))

    assert uploaded.file.closed


def test_ingestion_closes_upload_after_unexpected_read_failure() -> None:
    class FailingFile(BytesIO):
        def read(self, size: int = -1) -> bytes:
            raise RuntimeError("simulated read failure")

    uploaded = UploadFile(file=FailingFile(b"data"), filename="sample.bin")

    with pytest.raises(RuntimeError, match="simulated read failure"):
        asyncio.run(ingest_upload(uploaded, max_bytes=10))

    assert uploaded.file.closed


def test_unexpected_ingestion_failure_returns_generic_500(
    monkeypatch: pytest.MonkeyPatch,
    test_settings: Settings,
) -> None:
    async def fail_after_cleanup(uploaded: UploadFile, max_bytes: int) -> None:
        del max_bytes
        await uploaded.close()
        raise RuntimeError("sensitive internal failure")

    monkeypatch.setattr(uploads_route, "ingest_upload", fail_after_cleanup)
    with TestClient(
        create_app(test_settings),
        raise_server_exceptions=False,
    ) as client:
        response = upload(client, b"data")

    assert response.status_code == 500
    assert response.text == "Internal Server Error"
    assert "sensitive" not in response.text


def test_openapi_registers_typed_upload_contract(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    operation = schema["paths"]["/api/v1/uploads/"]["post"]

    assert operation["responses"]["201"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/UploadResponse"
    }
    assert "multipart/form-data" in operation["requestBody"]["content"]
    assert "413" in operation["responses"]
