from __future__ import annotations

import gzip
import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.attack.catalog import (
    ATTACK_SOURCE_SHA256,
    ATTACKCatalogSnapshot,
    ATTACKCatalogStore,
    ATTACKCatalogUnavailableError,
    ATTACKCatalogValidationError,
    _build_fixture_snapshot_from_stix,
    _load_fixture_snapshot,
    build_snapshot_from_stix,
    load_snapshot,
    load_verified_snapshot,
    serialize_snapshot,
)
from app.main import create_app
from app.schemas.attack import ATTACKObjectStatus, ATTACKTechnique
from app.services.attack_knowledge import ATTACKKnowledgeService

FIXTURE = Path(__file__).parent / "fixtures" / "attack_bundle_synthetic.json"
NOW = datetime(2026, 10, 26, tzinfo=timezone.utc)


def fixture_document() -> dict[str, object]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def fixture_bytes(document: dict[str, object] | None = None) -> bytes:
    value = document if document is not None else fixture_document()
    return json.dumps(value, ensure_ascii=False).encode()


def objects(document: dict[str, object]) -> list[dict[str, object]]:
    return document["objects"]  # type: ignore[return-value]


def synthetic_snapshot() -> ATTACKCatalogSnapshot:
    return _build_fixture_snapshot_from_stix(fixture_bytes(), NOW)


class FixtureATTACKCatalogStore(ATTACKCatalogStore):
    """Test-only store for unverified synthetic catalogs."""

    def __init__(
        self,
        path: Path | None = None,
        snapshot: ATTACKCatalogSnapshot | None = None,
    ) -> None:
        super().__init__(path)
        if snapshot is not None:
            self._snapshot = snapshot

    def load(self) -> ATTACKCatalogSnapshot:
        if self._path is None:
            return self.snapshot
        return super().load()


def synthetic_store() -> ATTACKCatalogStore:
    return FixtureATTACKCatalogStore(snapshot=synthetic_snapshot())


@pytest.fixture(scope="module")
def verified_official():
    return load_verified_snapshot()


@pytest.mark.unit
def test_valid_synthetic_bundle_normalizes_identifiers_and_provenance() -> None:
    snapshot = synthetic_snapshot()
    assert snapshot.statistics.object_count == 5
    assert snapshot.statistics.tactic_count == 1
    assert snapshot.statistics.technique_count == 2
    assert snapshot.statistics.subtechnique_count == 1
    assert snapshot.statistics.relationship_count == 1
    assert snapshot.techniques_by_id["T1000"].stix_id.startswith("attack-pattern--")
    assert snapshot.techniques_by_id["T1000"].tactic_ids == ("TA0002",)
    assert snapshot.techniques_by_id["T1000"].platforms == ("Windows", "Linux")
    assert snapshot.techniques_by_id["T1000.001"].parent_attack_id == "T1000"
    assert snapshot.techniques_by_id["T1000.001"].description is None
    assert snapshot.provenance.source_digest != ATTACK_SOURCE_SHA256


@pytest.mark.unit
def test_deprecated_is_distinct_and_excluded_by_default() -> None:
    service = ATTACKKnowledgeService(synthetic_store())
    item = service.technique("T1000.001", True)
    assert item is not None and item.status is ATTACKObjectStatus.DEPRECATED
    assert service.technique("T1000.001", False) is None
    assert service.subtechniques("T1000", 0, 10, False).total == 0
    assert service.subtechniques("T1000", 0, 10, True).total == 1


@pytest.mark.unit
def test_snapshot_is_immutable_and_unverified_publication_is_rejected(
    verified_official,
) -> None:
    snapshot = synthetic_snapshot()
    with pytest.raises(TypeError):
        snapshot.techniques_by_id["T9999"] = snapshot.techniques_by_id["T1000"]  # type: ignore[index]
    with pytest.raises(TypeError, match="VerifiedAttackCatalogSnapshot"):
        ATTACKCatalogStore().publish(snapshot)  # type: ignore[arg-type]
    store = ATTACKCatalogStore()
    store.publish(verified_official)
    store.publish(verified_official)
    assert store.snapshot == verified_official.snapshot


@pytest.mark.unit
def test_failed_load_does_not_replace_valid_snapshot(tmp_path: Path) -> None:
    path = tmp_path / "broken.gz"
    path.write_bytes(b"not gzip")
    valid = synthetic_snapshot()
    store = FixtureATTACKCatalogStore(path, snapshot=valid)
    with pytest.raises(ATTACKCatalogValidationError):
        store.load()
    assert store.snapshot is valid


@pytest.mark.unit
def test_store_reports_unavailable_before_load() -> None:
    store = ATTACKCatalogStore(Path("missing"))
    with pytest.raises(ATTACKCatalogUnavailableError):
        _ = store.snapshot
    assert ATTACKKnowledgeService(store).status().available is False


@pytest.mark.unit
def test_pinned_digest_rejects_synthetic_source() -> None:
    with pytest.raises(ATTACKCatalogValidationError, match="digest"):
        build_snapshot_from_stix(fixture_bytes(), NOW)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda doc: doc.update(type="collection"), "STIX bundle"),
        (lambda doc: doc.update(objects=[]), "cardinality"),
        (
            lambda doc: doc["objects"].append(deepcopy(doc["objects"][0])),
            "Duplicate STIX",
        ),  # type: ignore[attr-defined,index]
        (lambda doc: doc["objects"][0].update(id="bad"), "Invalid STIX"),  # type: ignore[index,union-attr]
        (
            lambda doc: doc["objects"][0].update(x_mitre_domains=["mobile-attack"]),
            "domain mismatch",
        ),  # type: ignore[index,union-attr]
        (
            lambda doc: doc["objects"][1].update(
                kill_chain_phases=[
                    {"kill_chain_name": "mitre-attack", "phase_name": "missing"}
                ]
            ),
            "unknown tactic",
        ),  # type: ignore[index,union-attr]
        (
            lambda doc: doc["objects"][3].update(
                target_ref="attack-pattern--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
            ),
            "does not resolve",
        ),  # type: ignore[index,union-attr]
    ],
)
def test_adversarial_bundle_validation(mutation, message: str) -> None:
    document = fixture_document()
    mutation(document)
    with pytest.raises(ATTACKCatalogValidationError, match=message):
        _build_fixture_snapshot_from_stix(fixture_bytes(document), NOW)


@pytest.mark.unit
def test_corrupt_json_size_depth_and_naive_time_are_rejected() -> None:
    with pytest.raises(ATTACKCatalogValidationError, match="UTF-8 JSON"):
        _build_fixture_snapshot_from_stix(b"{", NOW)
    with pytest.raises(ATTACKCatalogValidationError, match="byte limit"):
        _build_fixture_snapshot_from_stix(fixture_bytes(), NOW, maximum_bytes=10)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("index", "field", "value", "message"),
    [
        (0, "name", 7, "Invalid or oversized name"),
        (0, "revoked", "false", "Invalid revoked"),
        (0, "created", "not-a-time", "Invalid created"),
        (0, "created", "2020-01-01T00:00:00", "Timezone missing"),
        (0, "x_mitre_domains", "enterprise-attack", "domains"),
        (1, "kill_chain_phases", "execution", "kill chain phases"),
        (1, "x_mitre_platforms", [7], "platforms"),
        (1, "description", "x" * 131_073, "string limit"),
    ],
    ids=[
        "invalid-name",
        "invalid-revoked",
        "invalid-time",
        "naive-time",
        "invalid-domains",
        "invalid-phases",
        "invalid-platforms",
        "oversized-string",
    ],
)
def test_field_limits_and_types_fail_closed(
    index: int, field: str, value: object, message: str
) -> None:
    document = fixture_document()
    objects(document)[index][field] = value
    with pytest.raises(ATTACKCatalogValidationError, match=message):
        _build_fixture_snapshot_from_stix(fixture_bytes(document), NOW)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("references", "message"),
    [
        ({}, "external references"),
        (["bad"], "Malformed external"),
        ([{"source_name": "other"}], "external ID"),
    ],
)
def test_external_reference_failures(references: object, message: str) -> None:
    document = fixture_document()
    objects(document)[0]["external_references"] = references
    with pytest.raises(ATTACKCatalogValidationError, match=message):
        _build_fixture_snapshot_from_stix(fixture_bytes(document), NOW)


@pytest.mark.unit
def test_object_relationship_and_identity_cardinality_failures() -> None:
    document = fixture_document()
    objects(document).append("not-an-object")  # type: ignore[arg-type]
    with pytest.raises(ATTACKCatalogValidationError, match="mapping"):
        _build_fixture_snapshot_from_stix(fixture_bytes(document), NOW)

    document = fixture_document()
    del objects(document)[0]["x_mitre_shortname"]
    with pytest.raises(ATTACKCatalogValidationError, match="short name"):
        _build_fixture_snapshot_from_stix(fixture_bytes(document), NOW)

    document = fixture_document()
    with pytest.raises(ATTACKCatalogValidationError, match="Relationship limit"):
        _build_fixture_snapshot_from_stix(
            fixture_bytes(document),
            NOW,
            maximum_relationships=0,
        )

    document = fixture_document()
    duplicate = deepcopy(objects(document)[1])
    duplicate["id"] = "attack-pattern--66666666-6666-4666-8666-666666666666"
    objects(document).append(duplicate)
    with pytest.raises(ATTACKCatalogValidationError, match="Duplicate technique"):
        _build_fixture_snapshot_from_stix(fixture_bytes(document), NOW)


@pytest.mark.unit
def test_revoked_subtechnique_constrained_parent_fallback() -> None:
    document = fixture_document()
    objects(document).pop(3)
    child = objects(document)[2]
    child.pop("x_mitre_deprecated")
    child["revoked"] = True
    snapshot = _build_fixture_snapshot_from_stix(fixture_bytes(document), NOW)
    assert snapshot.techniques_by_id["T1000.001"].parent_attack_id == "T1000"
    assert snapshot.techniques_by_id["T1000.001"].status is ATTACKObjectStatus.REVOKED


@pytest.mark.unit
def test_active_subtechnique_requires_relationship() -> None:
    document = fixture_document()
    objects(document).pop(3)
    with pytest.raises(ATTACKCatalogValidationError, match="parent relationship"):
        _build_fixture_snapshot_from_stix(fixture_bytes(document), NOW)


def pinned_synthetic_payload() -> dict[str, object]:
    payload = json.loads(serialize_snapshot(synthetic_snapshot()))
    payload["provenance"] = load_snapshot().provenance.model_dump(mode="json")
    return payload


def write_snapshot(path: Path, payload: object) -> None:
    path.write_bytes(
        gzip.compress(
            json.dumps(payload, ensure_ascii=False).encode(), compresslevel=1, mtime=0
        )
    )


@pytest.mark.unit
def test_snapshot_loader_resource_and_schema_failures(tmp_path: Path) -> None:
    path = tmp_path / "snapshot.gz"
    path.write_bytes(b"x" * 11)
    with pytest.raises(ATTACKCatalogValidationError, match="Compressed"):
        load_snapshot(path, maximum_compressed_bytes=10)

    write_snapshot(path, {"padding": "x" * 200})
    with pytest.raises(ATTACKCatalogValidationError, match="Expanded"):
        _load_fixture_snapshot(path, maximum_bytes=100)

    payload = pinned_synthetic_payload()
    payload["schema_version"] = "2.0.0"
    write_snapshot(path, payload)
    with pytest.raises(ATTACKCatalogValidationError, match="schema"):
        _load_fixture_snapshot(path)

    write_snapshot(path, [])
    with pytest.raises(ATTACKCatalogValidationError, match="schema"):
        _load_fixture_snapshot(path)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda payload: payload["tactics"].append(deepcopy(payload["tactics"][0])),
            "duplicate identities",
        ),
        (
            lambda payload: payload["statistics"].update(tactic_count=99),
            "statistics",
        ),
        (
            lambda payload: payload["techniques"][0].update(tactic_ids=["TA9999"]),
            "unresolved tactic",
        ),
        (
            lambda payload: payload["techniques"][1].update(parent_attack_id="T9999"),
            "unresolved parent",
        ),
    ],
)
def test_snapshot_loader_integrity_failures(
    tmp_path: Path, mutation, message: str
) -> None:
    payload = pinned_synthetic_payload()
    mutation(payload)
    path = tmp_path / "snapshot.gz"
    write_snapshot(path, payload)
    with pytest.raises(ATTACKCatalogValidationError, match=message):
        _load_fixture_snapshot(path)
    with pytest.raises(ATTACKCatalogValidationError, match="timezone-aware"):
        _build_fixture_snapshot_from_stix(fixture_bytes(), datetime(2026, 1, 1))
    deep: object = "value"
    for _ in range(22):
        deep = [deep]
    with pytest.raises(ATTACKCatalogValidationError, match="nesting"):
        _build_fixture_snapshot_from_stix(
            json.dumps({"type": "bundle", "objects": deep}).encode(),
            NOW,
        )


@pytest.mark.unit
def test_snapshot_loader_rejects_tampered_provenance(tmp_path: Path) -> None:
    payload = json.loads(serialize_snapshot(synthetic_snapshot()))
    payload["provenance"]["source_digest"] = "0" * 64
    path = tmp_path / "snapshot.gz"
    path.write_bytes(gzip.compress(json.dumps(payload).encode(), mtime=0))
    with pytest.raises(ATTACKCatalogValidationError, match="provenance"):
        _load_fixture_snapshot(path)


@pytest.mark.unit
def test_contract_rejects_malformed_attack_id() -> None:
    data = synthetic_snapshot().techniques_by_id["T1000"].model_dump()
    data["attack_id"] = "attack-pattern--not-an-external-id"
    with pytest.raises(ValidationError):
        ATTACKTechnique.model_validate(data)


@pytest.mark.integration
def test_packaged_official_snapshot_loads_offline() -> None:
    snapshot = load_snapshot()
    assert snapshot.provenance.source_digest == ATTACK_SOURCE_SHA256
    assert snapshot.statistics.technique_count == 858
    assert snapshot.statistics.tactic_count == 15
    assert snapshot.statistics.relationship_count == 21262


@pytest.fixture
def attack_client(test_settings) -> TestClient:
    with TestClient(
        create_app(test_settings, attack_store_factory=synthetic_store)
    ) as client:
        yield client


@pytest.mark.contract
def test_attack_status_and_openapi_contract(attack_client: TestClient) -> None:
    response = attack_client.get("/api/v1/attack/status")
    assert response.status_code == 200
    assert response.json()["scientific_boundary"] == "knowledge_not_observation"
    schema = attack_client.get("/openapi.json").json()
    assert "/api/v1/attack/techniques/{technique_id}" in schema["paths"]
    assert set(schema["paths"]["/api/v1/attack/status"]) == {"get"}


@pytest.mark.integration
def test_attack_api_queries_and_pagination(attack_client: TestClient) -> None:
    tactics = attack_client.get("/api/v1/attack/tactics?limit=1").json()
    assert tactics["total"] == 1 and len(tactics["items"]) == 1
    tactic = attack_client.get("/api/v1/attack/tactics/TA0002")
    assert tactic.status_code == 200
    techniques = attack_client.get("/api/v1/attack/tactics/TA0002/techniques")
    assert techniques.status_code == 200 and techniques.json()["total"] == 1
    technique = attack_client.get("/api/v1/attack/techniques/T1000")
    assert technique.status_code == 200
    hidden = attack_client.get("/api/v1/attack/techniques/T1000.001")
    assert hidden.status_code == 404
    retired = attack_client.get(
        "/api/v1/attack/techniques/T1000.001?include_retired=true"
    )
    assert retired.status_code == 200 and retired.json()["status"] == "deprecated"
    children = attack_client.get(
        "/api/v1/attack/techniques/T1000/subtechniques?include_retired=true"
    )
    assert children.status_code == 200 and children.json()["total"] == 1


@pytest.mark.contract
def test_attack_api_rejects_invalid_ids_limits_and_methods(
    attack_client: TestClient,
) -> None:
    assert attack_client.get("/api/v1/attack/techniques/not-an-id").status_code == 422
    assert attack_client.get("/api/v1/attack/tactics/TA9999").status_code == 404
    assert attack_client.get("/api/v1/attack/tactics?limit=201").status_code == 422
    assert attack_client.post("/api/v1/attack/status").status_code == 405


@pytest.mark.integration
def test_unavailable_catalog_returns_status_and_503(test_settings) -> None:
    empty = ATTACKCatalogStore(Path("does-not-exist"))
    with TestClient(
        create_app(test_settings, attack_store_factory=lambda: empty)
    ) as client:
        assert client.get("/api/v1/attack/status").json()["available"] is False
        assert client.get("/api/v1/attack/techniques/T1000").status_code == 503
        assert client.get("/api/v1/attack/tactics").status_code == 503
        assert client.get("/api/v1/attack/tactics/TA0002/techniques").status_code == 503
        assert (
            client.get("/api/v1/attack/techniques/T1000/subtechniques").status_code
            == 503
        )


@pytest.mark.integration
def test_nested_lookup_missing_and_invalid_parent_paths(
    attack_client: TestClient,
) -> None:
    assert (
        attack_client.get("/api/v1/attack/tactics/TA9999/techniques").status_code == 404
    )
    assert (
        attack_client.get(
            "/api/v1/attack/techniques/T1000.001/subtechniques?include_retired=true"
        ).status_code
        == 404
    )


@pytest.mark.integration
def test_unexpected_lookup_failure_is_sanitized(test_settings) -> None:
    class BrokenStore(ATTACKCatalogStore):
        @property
        def snapshot(self):
            raise RuntimeError("sensitive detail")

        def load(self):
            return synthetic_snapshot()

    with TestClient(
        create_app(test_settings, attack_store_factory=BrokenStore),
        raise_server_exceptions=False,
    ) as client:
        response = client.get("/api/v1/attack/techniques/T1000")
        assert response.status_code == 500
        assert "sensitive" not in response.text
