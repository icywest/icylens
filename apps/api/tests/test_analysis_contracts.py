from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.schemas.analysis import (
    AnalysisIndicator,
    AnalysisResponse,
    AnalysisResult,
    EngineResult,
)
from app.schemas.common import AnalysisEngine, AnalysisStatus, ThreatVerdict

pytestmark = pytest.mark.contract


def test_valid_analysis_request(client: TestClient) -> None:
    payload = {"filename": "invoice_update.exe", "mode": "static"}

    response = client.post("/api/v1/analyses/validate", json=payload)

    assert response.status_code == 200
    assert response.json() == payload


@pytest.mark.parametrize(
    "payload",
    [
        {"filename": "invoice_update.exe", "mode": "dynamic"},
        {"filename": "", "mode": "static"},
        {
            "filename": "invoice_update.exe",
            "mode": "static",
            "unexpected": True,
        },
        {"filename": 123, "mode": "static"},
        {"mode": "static"},
        {"filename": "invoice_update.exe", "mode": None},
    ],
    ids=[
        "invalid-mode",
        "empty-filename",
        "extra-field",
        "invalid-type",
        "missing-filename",
        "null-mode",
    ],
)
def test_invalid_analysis_request_returns_422(
    client: TestClient,
    payload: dict[str, object],
) -> None:
    response = client.post("/api/v1/analyses/validate", json=payload)

    assert response.status_code == 422


def test_analysis_request_defaults_to_static_mode(client: TestClient) -> None:
    response = client.post(
        "/api/v1/analyses/validate",
        json={"filename": "sample.bin"},
    )

    assert response.status_code == 200
    assert response.json() == {"filename": "sample.bin", "mode": "static"}


def test_educational_mode_is_accepted(client: TestClient) -> None:
    payload = {"filename": "sample.bin", "mode": "educational"}

    response = client.post("/api/v1/analyses/validate", json=payload)

    assert response.status_code == 200
    assert response.json() == payload


def test_filename_longer_than_255_characters_returns_422(
    client: TestClient,
) -> None:
    response = client.post(
        "/api/v1/analyses/validate",
        json={"filename": "a" * 256},
    )

    assert response.status_code == 422


def test_filename_at_255_character_boundary_is_accepted(
    client: TestClient,
) -> None:
    filename = "a" * 255

    response = client.post(
        "/api/v1/analyses/validate",
        json={"filename": filename},
    )

    assert response.status_code == 200
    assert response.json()["filename"] == filename


@pytest.mark.parametrize("filename", ["archivo-ñ.exe", "my report.pdf"])
def test_printable_unicode_and_space_filenames_are_accepted(
    client: TestClient,
    filename: str,
) -> None:
    response = client.post(
        "/api/v1/analyses/validate",
        json={"filename": filename},
    )

    assert response.status_code == 200
    assert response.json()["filename"] == filename


@pytest.mark.parametrize(
    "filename",
    [
        "nul\u0000byte.exe",
        "newline\nbreak.exe",
        "tab\tname.exe",
        "delete\u007f.exe",
        "right-to-left\u202eoverride.exe",
        "../etc/passwd",
        "..\\windows\\system32\\cmd.exe",
        ".",
        "..",
    ],
    ids=[
        "nul",
        "newline",
        "tab",
        "delete",
        "bidi-override",
        "posix-traversal",
        "windows-traversal",
        "dot",
        "dot-dot",
    ],
)
def test_unsafe_filenames_are_rejected(
    client: TestClient,
    filename: str,
) -> None:
    response = client.post(
        "/api/v1/analyses/validate",
        json={"filename": filename},
    )

    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["body", "filename"]


def test_empty_body_returns_422(client: TestClient) -> None:
    response = client.post(
        "/api/v1/analyses/validate",
        content=b"",
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 422


def test_malformed_json_returns_422(client: TestClient) -> None:
    response = client.post(
        "/api/v1/analyses/validate",
        content=b"{not-json",
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 422


def test_non_json_content_type_returns_422(client: TestClient) -> None:
    response = client.post(
        "/api/v1/analyses/validate",
        content=b"filename=sample.bin",
        headers={"content-type": "text/plain"},
    )

    assert response.status_code == 422


def test_analysis_models_serialize_with_enum_and_optional_values() -> None:
    indicator = AnalysisIndicator(
        name="Unsigned executable",
        description="The executable has no digital signature.",
        source=AnalysisEngine.STATIC,
        severity="medium",
    )
    engine_result = EngineResult(
        engine=AnalysisEngine.STATIC,
        status="completed",
        indicators=[indicator],
    )
    result = AnalysisResult(
        verdict=ThreatVerdict.SUSPICIOUS,
        risk_score=42.5,
        engines=[engine_result],
    )
    response = AnalysisResponse(
        analysis_id=uuid4(),
        filename="sample.bin",
        status=AnalysisStatus.COMPLETED,
        created_at=datetime.now(UTC),
        completed_at=None,
        result=result,
    )

    dumped = response.model_dump(mode="json")
    dumped_json = response.model_dump_json()

    assert dumped["status"] == "completed"
    assert dumped["result"]["verdict"] == "suspicious"
    assert dumped["result"]["engines"][0]["engine"] == "static"
    assert '"risk_score":42.5' in dumped_json
    assert '"completed_at":null' in dumped_json


def test_analysis_result_defaults_and_lists_are_not_shared() -> None:
    first_result = AnalysisResult(verdict=ThreatVerdict.UNKNOWN)
    second_result = AnalysisResult(verdict=ThreatVerdict.CLEAN)
    first_engine = EngineResult(
        engine=AnalysisEngine.STATIC,
        status="completed",
    )
    second_engine = EngineResult(
        engine=AnalysisEngine.BEHAVIORAL,
        status="skipped",
    )

    first_result.engines.append(first_engine)
    first_engine.indicators.append(
        AnalysisIndicator(
            name="Test indicator",
            description="Used to verify list isolation.",
            source=AnalysisEngine.STATIC,
            severity="info",
        )
    )

    assert first_result.risk_score is None
    assert second_result.engines == []
    assert second_engine.indicators == []


@pytest.mark.parametrize("risk_score", [-0.1, 100.1])
def test_risk_score_outside_allowed_range_is_rejected(risk_score: float) -> None:
    with pytest.raises(ValidationError):
        AnalysisResult(
            verdict=ThreatVerdict.UNKNOWN,
            risk_score=risk_score,
        )


@pytest.mark.parametrize("risk_score", [0.0, 100.0])
def test_risk_score_boundaries_are_accepted(risk_score: float) -> None:
    result = AnalysisResult(
        verdict=ThreatVerdict.UNKNOWN,
        risk_score=risk_score,
    )

    assert result.risk_score == risk_score


@pytest.mark.integration
def test_health_contract_is_stable(client: TestClient) -> None:
    response = client.get("/api/v1/health/")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "service": "iCYLENS API",
        "version": "0.4.1",
        "message": "iCYLENS backend is operational",
    }


@pytest.mark.integration
def test_swagger_and_redoc_are_available(client: TestClient) -> None:
    assert client.get("/docs").status_code == 200
    assert client.get("/redoc").status_code == 200


@pytest.mark.integration
def test_openapi_contains_checkpoint_contracts_once(client: TestClient) -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200
    schema = response.json()
    assert set(schema["paths"]) == {
        "/api/v1/health/",
        "/api/v1/analyses/validate",
        "/api/v1/uploads/",
        "/api/v1/fingerprints/",
        "/api/v1/content-inspections/",
        "/api/v1/static-analyses/",
        "/api/v1/ml-inferences/",
        "/api/v1/vulnerabilities/{cve_id}",
        "/api/v1/vulnerabilities/{cve_id}/interpretation",
        "/api/v1/vulnerabilities/{cve_id}/applicability",
        "/api/v1/intelligence/kev/status",
        "/api/v1/intelligence/kev/{cve_id}",
        "/api/v1/intelligence/epss/{cve_id}",
        "/api/v1/intelligence/vulnerabilities/{cve_id}",
        "/api/v1/intelligence/vulnerabilities/{cve_id}/assessment",
        "/api/v1/attack/status",
        "/api/v1/attack/tactics",
        "/api/v1/attack/tactics/{tactic_id}",
        "/api/v1/attack/tactics/{tactic_id}/techniques",
        "/api/v1/attack/techniques/{technique_id}",
        "/api/v1/attack/techniques/{technique_id}/subtechniques",
        "/api/v1/behavior/events/validate",
        "/api/v1/behavior/scenarios/generate",
        "/api/v1/behavior/schema",
        "/api/v1/behavior/rules",
        "/api/v1/behavior/rules/evaluate",
        "/api/v1/behavior/sequences/correlate",
        "/api/v1/behavior/sequences/schema",
    }
    assert "AnalysisRequest" in schema["components"]["schemas"]
    assert "HealthResponse" in schema["components"]["schemas"]
    assert "TemporalCorrelationRequest" in schema["components"]["schemas"]
    assert "TemporalCorrelationResult" in schema["components"]["schemas"]
    health_response = schema["paths"]["/api/v1/health/"]["get"]["responses"]["200"]
    assert (
        health_response["content"]["application/json"]["schema"]["$ref"]
        == "#/components/schemas/HealthResponse"
    )
    validate_operations = [
        operation
        for path, methods in schema["paths"].items()
        for operation in methods.values()
        if path == "/api/v1/analyses/validate"
    ]
    assert len(validate_operations) == 1
