from __future__ import annotations

import asyncio
import json
from threading import Event
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

import app.multilayer.service as multilayer_service_module
import app.schemas.multilayer_analysis as multilayer_schema_module
from app.api.v1.routes import multilayer_analysis as multilayer_route_module
from app.main import create_app
from app.multilayer.service import (
    MultilayerAnalysisCapacityError,
    MultilayerAnalysisService,
    MultilayerAnalysisTimeoutError,
    execute_multilayer_analysis,
)
from app.schemas.multilayer_analysis import (
    MAX_MULTILAYER_ASSERTIONS,
    MAX_MULTILAYER_REQUEST_BYTES,
    MAX_MULTILAYER_SOURCES,
    DeclaredMLInput,
    DeclaredStaticInput,
    MultilayerAnalysisRequest,
)
from app.services.synchronous_workers import SynchronousWorkerManager

HASH_A = "a" * 64
HASH_B = "b" * 64
DIGEST = "d" * 64
CONTEXT_A = "00000000-0000-0000-0000-000000000001"
CONTEXT_B = "00000000-0000-0000-0000-000000000002"


def _static(
    source_id: str, *, digest: str = HASH_A, context: str = CONTEXT_A
) -> dict[str, object]:
    return {
        "input_type": "declared_static",
        "source_id": source_id,
        "analysis_context_id": context,
        "sha256": digest,
        "size_bytes": 128,
    }


def _vulnerability(source_id: str, *, cve: str = "CVE-2021-44228") -> dict[str, object]:
    return {
        "input_type": "declared_vulnerability",
        "source_id": source_id,
        "analysis_context_id": CONTEXT_A if source_id.endswith("a") else CONTEXT_B,
        "cve_id": cve,
    }


def _ml(
    source_id: str, *, model_id: str, malicious_probability: float = 0.75
) -> dict[str, object]:
    return {
        "input_type": "declared_ml",
        "source_id": source_id,
        "analysis_context_id": CONTEXT_A,
        "model_id": model_id,
        "model_version": "1.0.0",
        "dataset_id": f"dataset-{model_id}",
        "dataset_integrity_digest": DIGEST,
        "output_label": "malicious",
        "benign_probability": 1.0 - malicious_probability,
        "malicious_probability": malicious_probability,
    }


def _payload(
    sources: list[dict[str, object]] | None = None,
    *,
    assertion_id: str = "AS-CONTENT-001",
    source_ids: list[str] | None = None,
) -> dict[str, object]:
    selected_sources = sources or [
        _static("src_a", context=CONTEXT_A),
        _static("src_b", context=CONTEXT_B),
    ]
    selected_ids = source_ids or [str(item["source_id"]) for item in selected_sources]
    return {
        "schema_version": "1.0.0",
        "sources": selected_sources,
        "assertions": [{"assertion_id": assertion_id, "source_ids": selected_ids}],
    }


def _analyze(payload: dict[str, object]) -> Any:
    request = MultilayerAnalysisRequest.model_validate(payload)
    return MultilayerAnalysisService().analyze(request)


def test_valid_http_request_preserves_declared_trust_and_consistency(
    client: TestClient,
) -> None:
    response = client.post("/api/v1/multilayer/analyze", json=_payload())
    assert response.status_code == 200
    body = response.json()
    assert body["sufficiency"]["assessments"][0]["status"] == "sufficient"
    assert body["evidence"]["record_count"] == 2
    assert all(
        item["origin_type"] == "client_declared"
        and item["trust_classification"] == "client_declared"
        and item["origin_verified"] is False
        and item["synthetic"] is False
        for item in body["evidence"]["records"]
    )
    assert body["explanation"]["trace_count"] == 1
    assert body["explanation"]["trace_ids"] == [
        body["explanation"]["traces"][0]["identifier"]["trace_id"]
    ]
    assert body["persistence_performed"] is False
    assert body["external_io_performed"] is False


@pytest.mark.parametrize(
    ("payload", "expected"),
    (
        (_payload([_static("src_a")], source_ids=["src_a"]), "insufficient_evidence"),
        (
            _payload(
                [_vulnerability("src_a"), _vulnerability("src_b")],
                assertion_id="AS-VULN-001",
            ),
            "sufficient",
        ),
        (
            _payload(
                [
                    _ml("src_a", model_id="model-a"),
                    _ml("src_b", model_id="model-a", malicious_probability=0.65),
                ],
                assertion_id="AS-ANALYSIS-001",
            ),
            "sufficient",
        ),
        (_payload(assertion_id="AS-MALWARE-001"), "unsupported_assertion"),
        (_payload(assertion_id="AS-REF-001"), "insufficient_evidence"),
        (
            _payload(
                [_static("src_a"), _vulnerability("src_b")],
                assertion_id="AS-CONTENT-001",
            ),
            "not_applicable",
        ),
    ),
)
def test_supported_insufficient_and_safe_negative_states(
    payload: dict[str, object], expected: str
) -> None:
    result = _analyze(payload)
    assert result.sufficiency.assessments[0].status.value == expected
    assert result.threat_verdict_generated is False
    assert result.malware_confirmed is False
    assert result.exploitation_inferred is False
    assert result.attack_execution_confirmed is False


@pytest.mark.parametrize(
    "mutation",
    (
        {"schema_version": "2.0.0"},
        {"trusted": True},
        {"evidence_batch": {"records": []}},
        {"identity_result": {}},
        {"correlation_graph": {}},
        {"sufficiency_assessment": {}},
        {"decision_trace": {}},
        {"rules": "dynamic"},
        {"execute": True},
        {"risk_score": 100},
    ),
)
def test_request_rejects_versions_trust_escalation_and_forged_results(
    client: TestClient, mutation: dict[str, object]
) -> None:
    payload = {**_payload(), **mutation}
    response = client.post("/api/v1/multilayer/analyze", json=payload)
    assert response.status_code == 422


@pytest.mark.parametrize(
    "source_mutation",
    (
        {"input_type": "backend_verified"},
        {"origin_verified": True},
        {"trust_level": "verified"},
        {"confirmed": True},
        {"is_malware": True},
        {"synthetic": True},
        {"raw_payload": "secret"},
    ),
)
def test_source_discriminator_and_extra_fields_are_strict(
    client: TestClient, source_mutation: dict[str, object]
) -> None:
    source = {**_static("src_a"), **source_mutation}
    response = client.post(
        "/api/v1/multilayer/analyze",
        json=_payload([source], source_ids=["src_a"]),
    )
    assert response.status_code == 422


def test_validation_error_does_not_echo_forbidden_input(client: TestClient) -> None:
    canary = "C:\\private\\secret.txt password=hunter2"
    source = {**_static("src_a"), "raw_payload": canary}
    response = client.post(
        "/api/v1/multilayer/analyze",
        json=_payload([source], source_ids=["src_a"]),
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "The multilayer request schema is invalid."}
    assert canary not in response.text


def test_duplicate_and_missing_source_references_are_rejected(
    client: TestClient,
) -> None:
    duplicate = _payload([_static("src_a"), _static("src_a", digest=HASH_B)])
    assert client.post("/api/v1/multilayer/analyze", json=duplicate).status_code == 422
    missing = _payload(source_ids=["src_a", "src_missing"])
    response = client.post("/api/v1/multilayer/analyze", json=missing)
    assert response.status_code == 422
    assert "src_missing" not in response.text


def test_semantic_input_and_assertion_permutations_are_deterministic() -> None:
    sources = [_static("src_a", context=CONTEXT_A), _static("src_b", context=CONTEXT_B)]
    first = _payload(sources)
    first["assertions"] = [
        {"assertion_id": "AS-CONTENT-001", "source_ids": ["src_a", "src_b"]},
        {"assertion_id": "AS-REF-001", "source_ids": ["src_a", "src_b"]},
    ]
    second = _payload(list(reversed(sources)))
    second["assertions"] = [
        {"assertion_id": "AS-REF-001", "source_ids": ["src_b", "src_a"]},
        {"assertion_id": "AS-CONTENT-001", "source_ids": ["src_b", "src_a"]},
    ]
    left = _analyze(first).model_dump_json()
    right = _analyze(second).model_dump_json()
    assert left == right


def test_summary_and_trace_reference_closure() -> None:
    result = _analyze(_payload())
    evidence_ids = {item.evidence_id for item in result.evidence.records}
    identity_ids = set(result.identity.reference_ids)
    correlation_ids = set(result.correlation.reference_ids)
    assessment_ids = {item.assessment_id for item in result.sufficiency.assessments}
    for trace in result.explanation.traces:
        assert {item.evidence_id for item in trace.evidence_references} <= evidence_ids
        assert {
            item.identity_object_id for item in trace.identity_references
        } <= identity_ids
        assert {
            item.correlation_object_id for item in trace.correlation_references
        } <= correlation_ids
        assert trace.identifier.source_assessment_id in assessment_ids


def test_declared_ml_is_not_server_inference_or_malware_confirmation() -> None:
    result = _analyze(
        _payload(
            [
                _ml("src_a", model_id="model-a"),
                _ml("src_b", model_id="model-a", malicious_probability=0.65),
            ],
            assertion_id="AS-ANALYSIS-001",
        )
    )
    encoded = result.model_dump_json()
    assert all(item.synthetic is False for item in result.evidence.records)
    assert '"malware_confirmed":false' in encoded
    assert "server-executed inference" in encoded


def test_schema_descriptor_is_public_safe_and_complete(client: TestClient) -> None:
    response = client.get("/api/v1/multilayer/schema")
    assert response.status_code == 200
    body = response.json()
    assert body["input_modes"] == [
        "declared_static",
        "declared_vulnerability",
        "declared_ml",
    ]
    assert set(body["supported_assertion_ids"]) == {
        "AS-CONTENT-001",
        "AS-VULN-001",
        "AS-ANALYSIS-001",
        "AS-REF-001",
    }
    assert body["accepts_evidence_batches"] is False
    assert body["accepts_precomputed_results"] is False
    assert body["authenticates_client_origin"] is False
    assert body["limits"]["maximum_request_bytes"] == MAX_MULTILAYER_REQUEST_BYTES


def test_body_and_collection_limits_are_enforced_before_analysis(
    client: TestClient,
) -> None:
    response = client.post(
        "/api/v1/multilayer/analyze",
        content=b"{}",
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(MAX_MULTILAYER_REQUEST_BYTES + 1),
        },
    )
    assert response.status_code == 413
    too_many_sources = [
        _static(f"src_{index}") for index in range(MAX_MULTILAYER_SOURCES + 1)
    ]
    assert (
        client.post(
            "/api/v1/multilayer/analyze", json=_payload(too_many_sources)
        ).status_code
        == 422
    )
    payload = _payload()
    payload["assertions"] = [
        {"assertion_id": "AS-CONTENT-001", "source_ids": ["src_a"]}
        for _ in range(MAX_MULTILAYER_ASSERTIONS + 1)
    ]
    assert client.post("/api/v1/multilayer/analyze", json=payload).status_code == 422


def test_output_limit_is_contract_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(multilayer_schema_module, "MAX_MULTILAYER_RESPONSE_BYTES", 1)
    with pytest.raises(Exception, match="resource limit"):
        _analyze(_payload())


def test_capacity_exhaustion_returns_controlled_429(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    application: Any = client.app
    capacity = application.state.multilayer_analysis_capacity
    monkeypatch.setattr(capacity, "try_submit", lambda operation: None)
    response = client.post("/api/v1/multilayer/analyze", json=_payload())
    assert response.status_code == 429
    assert response.json() == {"detail": "Multilayer analysis capacity is exhausted."}


@pytest.mark.parametrize(
    ("error", "status_code", "detail"),
    (
        (
            multilayer_service_module.MultilayerAnalysisTimeoutError("private"),
            504,
            "Multilayer analysis timed out.",
        ),
        (
            multilayer_service_module.MultilayerAnalysisLimitError("private"),
            503,
            "Multilayer analysis exceeded its resource budget.",
        ),
        (
            multilayer_service_module.MultilayerAnalysisConsistencyError("private"),
            500,
            "Multilayer analysis could not be completed.",
        ),
    ),
)
def test_controlled_service_errors_are_redacted(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    status_code: int,
    detail: str,
) -> None:
    async def fail(*args: object, **kwargs: object) -> object:
        raise error

    monkeypatch.setattr(multilayer_route_module, "execute_multilayer_analysis", fail)
    response = client.post("/api/v1/multilayer/analyze", json=_payload())
    assert response.status_code == status_code
    assert response.json() == {"detail": detail}
    assert "private" not in response.text


@pytest.mark.anyio
async def test_timeout_and_cancellation_retain_worker_until_real_completion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = SynchronousWorkerManager(1, thread_name_prefix="test-multilayer")
    started = Event()
    finish = Event()

    def operation() -> object:
        started.set()
        finish.wait()
        return object()

    monkeypatch.setattr(
        multilayer_service_module, "MULTILAYER_OPERATION_TIMEOUT_SECONDS", 0.01
    )
    task = asyncio.create_task(execute_multilayer_analysis(operation, manager))  # type: ignore[arg-type]
    assert await asyncio.to_thread(started.wait, 1)
    with pytest.raises(MultilayerAnalysisTimeoutError):
        await task
    assert manager.active == 1
    with pytest.raises(MultilayerAnalysisCapacityError):
        await execute_multilayer_analysis(operation, manager)  # type: ignore[arg-type]
    finish.set()
    await manager.aclose()
    assert manager.active == 0 and manager.shutdown_complete is True


@pytest.mark.anyio
async def test_client_cancellation_and_repeated_shutdown_are_owned() -> None:
    manager = SynchronousWorkerManager(1, thread_name_prefix="test-multilayer-cancel")
    started = Event()
    finish = Event()

    def operation() -> object:
        started.set()
        finish.wait()
        return object()

    task = asyncio.create_task(execute_multilayer_analysis(operation, manager))  # type: ignore[arg-type]
    assert await asyncio.to_thread(started.wait, 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert manager.active == 1 and manager.owned_workers == 1
    close_one = asyncio.create_task(manager.aclose())
    close_two = asyncio.create_task(manager.aclose())
    await asyncio.sleep(0)
    assert not close_one.done() and not close_two.done()
    finish.set()
    await asyncio.gather(close_one, close_two)
    assert manager.active == 0 and manager.shutdown_complete is True


def test_errors_logs_and_privacy_canaries_are_redacted(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    canary = "C:\\private\\secret.txt user=alice host=workstation ip=192.0.2.1"

    def fail(_: object) -> object:
        raise RuntimeError(canary)

    monkeypatch.setattr(MultilayerAnalysisService, "analyze", fail)
    response = client.post("/api/v1/multilayer/analyze", json=_payload())
    assert response.status_code == 500
    assert canary not in response.text and canary not in caplog.text


def test_complete_success_response_omits_privacy_canaries() -> None:
    canaries = (
        "C:\\private\\sample.exe",
        "powershell -enc secret",
        "alice",
        "workstation-01",
        "192.0.2.1",
        "registry-secret",
        "raw-event-payload",
    )
    encoded = _analyze(_payload()).model_dump_json()
    assert all(item not in encoded for item in canaries)


def test_no_external_effect_or_dynamic_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "socket.create_connection", lambda *args, **kwargs: pytest.fail("network")
    )
    monkeypatch.setattr(
        "subprocess.run", lambda *args, **kwargs: pytest.fail("subprocess")
    )
    monkeypatch.setattr(
        "pathlib.Path.write_text", lambda *args, **kwargs: pytest.fail("filesystem")
    )
    monkeypatch.setattr(
        "pathlib.Path.write_bytes", lambda *args, **kwargs: pytest.fail("filesystem")
    )
    result = _analyze(_payload())
    assert result.persistence_performed is False
    assert result.external_io_performed is False
    assert result.dynamic_rule_execution_performed is False
    assert result.response_action_performed is False


def test_openapi_and_legacy_routes_remain_compatible(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    assert "/api/v1/multilayer/analyze" in schema["paths"]
    assert "/api/v1/multilayer/schema" in schema["paths"]
    operations = sum(
        method in {"get", "post", "put", "patch", "delete"}
        for path in schema["paths"].values()
        for method in path
    )
    assert operations == 35
    assert client.get("/api/v1/health").status_code == 200


def test_request_models_are_frozen_and_reject_probability_inconsistency() -> None:
    with pytest.raises(ValidationError):
        DeclaredMLInput.model_validate(
            {**_ml("src_a", model_id="model-a"), "malicious_probability": 0.5}
        )
    source = DeclaredStaticInput.model_validate(_static("src_a"))
    with pytest.raises(ValidationError):
        source.size_bytes = 1  # type: ignore[misc]
    request = MultilayerAnalysisRequest.model_validate(_payload())
    assert isinstance(request.sources, tuple)
    assert isinstance(request.assertions, tuple)


def test_response_serialization_is_canonical_json_compatible() -> None:
    result = _analyze(_payload())
    canonical = json.dumps(
        result.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    )
    assert json.loads(canonical) == result.model_dump(mode="json")
    assert len(canonical.encode()) < 1024 * 1024


def test_application_reuses_owned_worker_manager(test_settings: Any) -> None:
    application = create_app(test_settings)
    assert (
        application.state.multilayer_analysis_capacity
        is application.state.phase05_worker_manager
    )
