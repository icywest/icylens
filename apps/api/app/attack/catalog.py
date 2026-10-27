from __future__ import annotations

import gzip
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.resources import files
from io import BytesIO
from pathlib import Path
from types import MappingProxyType
from typing import Any, cast

from pydantic import ValidationError

from app.schemas.attack import (
    ATTACKCatalogStatistics,
    ATTACKExternalReference,
    ATTACKObjectStatus,
    ATTACKProvenance,
    ATTACKRelationship,
    ATTACKTactic,
    ATTACKTechnique,
)

ATTACK_DOMAIN = "enterprise-attack"
ATTACK_VERSION = "19.2"
ATTACK_SOURCE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "v19.2/enterprise-attack/enterprise-attack-19.2.json"
)
ATTACK_SOURCE_SHA256 = (
    "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4"
)
ATTACK_ARTIFACT_SHA256 = (
    "916eabb166a794e881f23be2fe9bf5590bdba5117db892fc405af636eaa0bc88"
)
ATTACK_SNAPSHOT_RESOURCE_PACKAGE = "app.attack.data"
ATTACK_SNAPSHOT_RESOURCE = "enterprise-attack-19.2.json.gz"
DEFAULT_SNAPSHOT_PATH = (
    Path(__file__).resolve().parent / "data" / "enterprise-attack-19.2.json.gz"
)
_MAX_COMPRESSED_SNAPSHOT_BYTES = 2 * 1024 * 1024
_STIX_ID = re.compile(
    r"^[a-z][a-z0-9-]*--[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_MAX_STRING = 131_072


class ATTACKCatalogValidationError(RuntimeError):
    """A candidate ATT&CK catalog failed closed validation."""


class ATTACKCatalogUnavailableError(RuntimeError):
    """No validated ATT&CK snapshot is loaded."""


@dataclass(frozen=True)
class ATTACKCatalogSnapshot:
    provenance: ATTACKProvenance
    tactics_by_id: Mapping[str, ATTACKTactic]
    techniques_by_id: Mapping[str, ATTACKTechnique]
    relationships: tuple[ATTACKRelationship, ...]
    statistics: ATTACKCatalogStatistics


def _text(value: object, field: str, *, required: bool = False) -> str | None:
    if value is None and not required:
        return None
    if (
        not isinstance(value, str)
        or (required and not value)
        or len(value) > _MAX_STRING
    ):
        raise ATTACKCatalogValidationError(f"Invalid or oversized {field}")
    return value


def _boolean(value: object, field: str) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise ATTACKCatalogValidationError(f"Invalid {field}")
    return value


def _timestamp(value: object, field: str) -> datetime | None:
    text = _text(value, field)
    if text is None:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise ATTACKCatalogValidationError(f"Invalid {field}") from error
    if parsed.tzinfo is None:
        raise ATTACKCatalogValidationError(f"Timezone missing from {field}")
    return parsed.astimezone(timezone.utc)


def _status(revoked: bool | None, deprecated: bool | None) -> ATTACKObjectStatus:
    if revoked is True:
        return ATTACKObjectStatus.REVOKED
    if deprecated is True:
        return ATTACKObjectStatus.DEPRECATED
    if revoked is False or deprecated is False:
        return ATTACKObjectStatus.ACTIVE
    return ATTACKObjectStatus.UNKNOWN


def _references(raw: object) -> tuple[ATTACKExternalReference, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list) or len(raw) > 256:
        raise ATTACKCatalogValidationError("Invalid external references")
    result: list[ATTACKExternalReference] = []
    for item in raw:
        if not isinstance(item, dict):
            raise ATTACKCatalogValidationError("Malformed external reference")
        source_name = _text(item.get("source_name"), "reference source", required=True)
        result.append(
            ATTACKExternalReference(
                source_name=cast(str, source_name),
                external_id=_text(item.get("external_id"), "external ID"),
                url=_text(item.get("url"), "reference URL"),
                description=_text(item.get("description"), "reference description"),
            )
        )
    return tuple(result)


def _external_id(references: tuple[ATTACKExternalReference, ...], prefix: str) -> str:
    values = {
        ref.external_id
        for ref in references
        if ref.source_name == "mitre-attack"
        and ref.external_id
        and ref.external_id.startswith(prefix)
    }
    if len(values) != 1:
        raise ATTACKCatalogValidationError("Missing or conflicting ATT&CK external ID")
    return values.pop()


def _domains(obj: dict[str, Any]) -> tuple[str, ...]:
    raw = obj.get("x_mitre_domains")
    if (
        not isinstance(raw, list)
        or not raw
        or any(not isinstance(item, str) for item in raw)
    ):
        raise ATTACKCatalogValidationError("Missing or invalid ATT&CK domains")
    return tuple(cast(list[str], raw))


def _base(obj: dict[str, Any]) -> dict[str, Any]:
    stix_id = _text(obj.get("id"), "STIX ID", required=True)
    if stix_id is None or not _STIX_ID.fullmatch(stix_id):
        raise ATTACKCatalogValidationError("Invalid STIX ID")
    if ATTACK_DOMAIN not in _domains(obj):
        raise ATTACKCatalogValidationError("ATT&CK domain mismatch")
    revoked = _boolean(obj.get("revoked"), "revoked")
    deprecated = _boolean(obj.get("x_mitre_deprecated"), "deprecated")
    return {
        "stix_id": stix_id,
        "name": _text(obj.get("name"), "name", required=True),
        "description": _text(obj.get("description"), "description"),
        "domain": ATTACK_DOMAIN,
        "attack_spec_version": _text(obj.get("spec_version"), "spec version"),
        "object_version": _text(obj.get("x_mitre_version"), "object version"),
        "status": _status(revoked, deprecated),
        "revoked": revoked,
        "deprecated": deprecated,
        "created": _timestamp(obj.get("created"), "created"),
        "modified": _timestamp(obj.get("modified"), "modified"),
    }


def _ensure_json_depth(value: object, maximum: int, depth: int = 0) -> None:
    if depth > maximum:
        raise ATTACKCatalogValidationError("JSON nesting limit exceeded")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or len(key) > 256:
                raise ATTACKCatalogValidationError("Invalid JSON object key")
            _ensure_json_depth(child, maximum, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _ensure_json_depth(child, maximum, depth + 1)
    elif isinstance(value, str) and len(value) > _MAX_STRING:
        raise ATTACKCatalogValidationError("STIX string limit exceeded")


def build_snapshot_from_stix(
    source_bytes: bytes,
    imported_at: datetime,
    *,
    maximum_bytes: int = 64 * 1024 * 1024,
    maximum_objects: int = 50_000,
    maximum_relationships: int = 40_000,
    expected_source_digest: str | None = ATTACK_SOURCE_SHA256,
) -> ATTACKCatalogSnapshot:
    if len(source_bytes) > maximum_bytes:
        raise ATTACKCatalogValidationError("Dataset exceeds byte limit")
    try:
        document = json.loads(source_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ATTACKCatalogValidationError("Dataset is not valid UTF-8 JSON") from error
    _ensure_json_depth(document, 20)
    if not isinstance(document, dict) or document.get("type") != "bundle":
        raise ATTACKCatalogValidationError("Dataset is not a STIX bundle")
    raw_objects = document.get("objects")
    if (
        not isinstance(raw_objects, list)
        or not raw_objects
        or len(raw_objects) > maximum_objects
    ):
        raise ATTACKCatalogValidationError("Invalid STIX object cardinality")
    if imported_at.tzinfo is None:
        raise ATTACKCatalogValidationError("Import time must be timezone-aware")

    all_ids: set[str] = set()
    objects: list[dict[str, Any]] = []
    for raw in raw_objects:
        if not isinstance(raw, dict):
            raise ATTACKCatalogValidationError("STIX object must be a mapping")
        obj = cast(dict[str, Any], raw)
        stix_id = obj.get("id")
        if not isinstance(stix_id, str) or not _STIX_ID.fullmatch(stix_id):
            raise ATTACKCatalogValidationError("Invalid STIX object ID")
        if stix_id in all_ids:
            raise ATTACKCatalogValidationError("Duplicate STIX object ID")
        all_ids.add(stix_id)
        objects.append(obj)

    tactic_short_names: dict[str, str] = {}
    tactics: dict[str, ATTACKTactic] = {}
    tactic_stix_to_attack: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") != "x-mitre-tactic":
            continue
        if ATTACK_DOMAIN not in _domains(obj):
            raise ATTACKCatalogValidationError("ATT&CK domain mismatch")
        refs = _references(obj.get("external_references"))
        attack_id = _external_id(refs, "TA")
        short_name = _text(obj.get("x_mitre_shortname"), "tactic short name")
        if short_name is None or short_name in tactic_short_names:
            raise ATTACKCatalogValidationError("Missing or duplicate tactic short name")
        if attack_id in tactics:
            raise ATTACKCatalogValidationError("Duplicate tactic ATT&CK ID")
        tactic = ATTACKTactic(
            attack_id=attack_id, short_name=short_name, references=refs, **_base(obj)
        )
        tactics[attack_id] = tactic
        tactic_short_names[short_name] = attack_id
        tactic_stix_to_attack[tactic.stix_id] = attack_id

    parent_by_child_stix: dict[str, str] = {}
    raw_relationships: list[dict[str, Any]] = []
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if len(raw_relationships) >= maximum_relationships:
            raise ATTACKCatalogValidationError("Relationship limit exceeded")
        source = _text(obj.get("source_ref"), "relationship source", required=True)
        target = _text(obj.get("target_ref"), "relationship target", required=True)
        relation = _text(
            obj.get("relationship_type"), "relationship type", required=True
        )
        if source not in all_ids or target not in all_ids:
            raise ATTACKCatalogValidationError("Relationship endpoint does not resolve")
        raw_relationships.append(obj)
        if relation == "subtechnique-of":
            if (
                source in parent_by_child_stix
                and parent_by_child_stix[source] != target
            ):
                raise ATTACKCatalogValidationError("Conflicting sub-technique parents")
            parent_by_child_stix[source] = target

    raw_techniques = [obj for obj in objects if obj.get("type") == "attack-pattern"]
    if any(ATTACK_DOMAIN not in _domains(obj) for obj in raw_techniques):
        raise ATTACKCatalogValidationError("ATT&CK domain mismatch")
    attack_id_by_stix: dict[str, str] = {}
    refs_by_stix: dict[str, tuple[ATTACKExternalReference, ...]] = {}
    for obj in raw_techniques:
        refs = _references(obj.get("external_references"))
        attack_id = _external_id(refs, "T")
        stix_id = cast(str, obj["id"])
        if attack_id in attack_id_by_stix.values():
            raise ATTACKCatalogValidationError("Duplicate technique ATT&CK ID")
        attack_id_by_stix[stix_id] = attack_id
        refs_by_stix[stix_id] = refs

    techniques: dict[str, ATTACKTechnique] = {}
    for obj in raw_techniques:
        stix_id = cast(str, obj["id"])
        attack_id = attack_id_by_stix[stix_id]
        is_sub = _boolean(obj.get("x_mitre_is_subtechnique"), "sub-technique") is True
        parent_stix = parent_by_child_stix.get(stix_id)
        parent_id = attack_id_by_stix.get(parent_stix) if parent_stix else None
        if (
            is_sub
            and parent_id is None
            and _boolean(obj.get("revoked"), "revoked") is True
            and "." in attack_id
        ):
            # Current ATT&CK releases may retain revoked sub-technique objects
            # after removing their historical relationship. This constrained
            # fallback uses three official facts: the sub-technique marker,
            # the dotted external ID, and a parent object present in the same
            # verified bundle. Active objects never use this fallback.
            candidate_parent = attack_id.split(".", 1)[0]
            if candidate_parent in attack_id_by_stix.values():
                parent_id = candidate_parent
        if is_sub != (parent_id is not None):
            raise ATTACKCatalogValidationError(
                "Sub-technique parent relationship mismatch"
            )
        phases = obj.get("kill_chain_phases", [])
        if not isinstance(phases, list) or len(phases) > 32:
            raise ATTACKCatalogValidationError("Invalid kill chain phases")
        tactic_ids: list[str] = []
        for phase in phases:
            if (
                not isinstance(phase, dict)
                or phase.get("kill_chain_name") != "mitre-attack"
            ):
                continue
            phase_name = phase.get("phase_name")
            if not isinstance(phase_name, str) or phase_name not in tactic_short_names:
                raise ATTACKCatalogValidationError(
                    "Technique references unknown tactic"
                )
            tactic_ids.append(tactic_short_names[phase_name])
        platforms = obj.get("x_mitre_platforms", [])
        if (
            not isinstance(platforms, list)
            or len(platforms) > 64
            or any(not isinstance(item, str) or len(item) > 128 for item in platforms)
        ):
            raise ATTACKCatalogValidationError("Invalid technique platforms")
        technique = ATTACKTechnique(
            attack_id=attack_id,
            parent_attack_id=parent_id,
            is_subtechnique=is_sub,
            tactic_ids=tuple(dict.fromkeys(tactic_ids)),
            platforms=tuple(cast(list[str], platforms)),
            references=refs_by_stix[stix_id],
            **_base(obj),
        )
        techniques[attack_id] = technique

    relationships: list[ATTACKRelationship] = []
    for obj in raw_relationships:
        relationships.append(
            ATTACKRelationship(
                stix_id=cast(str, obj["id"]),
                source_stix_id=cast(str, obj["source_ref"]),
                target_stix_id=cast(str, obj["target_ref"]),
                relationship_type=cast(str, obj["relationship_type"]),
                domain=ATTACK_DOMAIN,
                attack_version=ATTACK_VERSION,
                revoked=_boolean(obj.get("revoked"), "relationship revoked"),
                deprecated=_boolean(
                    obj.get("x_mitre_deprecated"), "relationship deprecated"
                ),
            )
        )
    source_digest = hashlib.sha256(source_bytes).hexdigest()
    if expected_source_digest is not None and source_digest != expected_source_digest:
        raise ATTACKCatalogValidationError("Dataset digest does not match the pin")
    provenance = ATTACKProvenance(
        domain=ATTACK_DOMAIN,
        attack_version=ATTACK_VERSION,
        source_url=ATTACK_SOURCE_URL,
        source_digest=source_digest,
        imported_at=imported_at,
    )
    retired = sum(
        t.status is not ATTACKObjectStatus.ACTIVE for t in techniques.values()
    )
    statistics = ATTACKCatalogStatistics(
        object_count=len(objects),
        tactic_count=len(tactics),
        technique_count=len(techniques),
        subtechnique_count=sum(t.is_subtechnique for t in techniques.values()),
        relationship_count=len(relationships),
        active_technique_count=len(techniques) - retired,
        retired_technique_count=retired,
    )
    return ATTACKCatalogSnapshot(
        provenance=provenance,
        tactics_by_id=MappingProxyType(dict(sorted(tactics.items()))),
        techniques_by_id=MappingProxyType(dict(sorted(techniques.items()))),
        relationships=tuple(relationships),
        statistics=statistics,
    )


def serialize_snapshot(snapshot: ATTACKCatalogSnapshot) -> bytes:
    payload = {
        "schema_version": "1.0.0",
        "provenance": snapshot.provenance.model_dump(mode="json"),
        "statistics": snapshot.statistics.model_dump(mode="json"),
        "tactics": [
            item.model_dump(mode="json") for item in snapshot.tactics_by_id.values()
        ],
        "techniques": [
            item.model_dump(mode="json") for item in snapshot.techniques_by_id.values()
        ],
        "relationships": [
            item.model_dump(mode="json") for item in snapshot.relationships
        ],
    }
    return json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


def load_snapshot(
    path: Path | None = None,
    *,
    maximum_bytes: int = 16 * 1024 * 1024,
    maximum_compressed_bytes: int = _MAX_COMPRESSED_SNAPSHOT_BYTES,
    expected_artifact_digest: str | None = ATTACK_ARTIFACT_SHA256,
) -> ATTACKCatalogSnapshot:
    try:
        stream = (
            path.open("rb")
            if path is not None
            else files(ATTACK_SNAPSHOT_RESOURCE_PACKAGE)
            .joinpath(ATTACK_SNAPSHOT_RESOURCE)
            .open("rb")
        )
        with stream:
            artifact = stream.read(maximum_compressed_bytes + 1)
        if len(artifact) > maximum_compressed_bytes:
            raise ATTACKCatalogValidationError("Compressed snapshot exceeds byte limit")
    except OSError as error:
        raise ATTACKCatalogValidationError("Snapshot cannot be read") from error
    artifact_digest = hashlib.sha256(artifact).hexdigest()
    if (
        expected_artifact_digest is not None
        and artifact_digest != expected_artifact_digest
    ):
        raise ATTACKCatalogValidationError(
            "Snapshot artifact digest does not match the pin"
        )
    try:
        with gzip.GzipFile(fileobj=BytesIO(artifact), mode="rb") as gzip_stream:
            data = gzip_stream.read(maximum_bytes + 1)
    except (OSError, EOFError, gzip.BadGzipFile) as error:
        raise ATTACKCatalogValidationError("Snapshot cannot be decompressed") from error
    if len(data) > maximum_bytes:
        raise ATTACKCatalogValidationError("Expanded snapshot exceeds byte limit")
    try:
        payload = json.loads(data)
        if not isinstance(payload, dict) or payload.get("schema_version") != "1.0.0":
            raise ATTACKCatalogValidationError("Unsupported snapshot schema")
        provenance = ATTACKProvenance.model_validate(payload["provenance"])
        if (
            provenance.attack_version != ATTACK_VERSION
            or provenance.domain != ATTACK_DOMAIN
            or provenance.source_url != ATTACK_SOURCE_URL
            or provenance.source_digest != ATTACK_SOURCE_SHA256
        ):
            raise ATTACKCatalogValidationError(
                "Snapshot provenance does not match the pin"
            )
        statistics = ATTACKCatalogStatistics.model_validate(payload["statistics"])
        tactics_list = [
            ATTACKTactic.model_validate(item) for item in payload["tactics"]
        ]
        techniques_list = [
            ATTACKTechnique.model_validate(item) for item in payload["techniques"]
        ]
        relationships = tuple(
            ATTACKRelationship.model_validate(item) for item in payload["relationships"]
        )
    except (
        KeyError,
        TypeError,
        json.JSONDecodeError,
        UnicodeDecodeError,
        ValidationError,
    ) as error:
        raise ATTACKCatalogValidationError("Snapshot structure is invalid") from error
    tactics = {item.attack_id: item for item in tactics_list}
    techniques = {item.attack_id: item for item in techniques_list}
    if len(tactics) != len(tactics_list) or len(techniques) != len(techniques_list):
        raise ATTACKCatalogValidationError("Snapshot contains duplicate identities")
    if (
        statistics.tactic_count != len(tactics)
        or statistics.technique_count != len(techniques)
        or statistics.relationship_count != len(relationships)
    ):
        raise ATTACKCatalogValidationError("Snapshot statistics do not match content")
    for technique in techniques.values():
        if any(tactic_id not in tactics for tactic_id in technique.tactic_ids):
            raise ATTACKCatalogValidationError("Snapshot contains an unresolved tactic")
        if technique.parent_attack_id and technique.parent_attack_id not in techniques:
            raise ATTACKCatalogValidationError("Snapshot contains an unresolved parent")
    return ATTACKCatalogSnapshot(
        provenance=provenance,
        tactics_by_id=MappingProxyType(tactics),
        techniques_by_id=MappingProxyType(techniques),
        relationships=relationships,
        statistics=statistics,
    )


class ATTACKCatalogStore:
    def __init__(self, path: Path | None = None) -> None:
        self._snapshot: ATTACKCatalogSnapshot | None = None
        self._path = path

    @property
    def snapshot(self) -> ATTACKCatalogSnapshot:
        if self._snapshot is None:
            raise ATTACKCatalogUnavailableError("ATT&CK catalog is unavailable")
        return self._snapshot

    def load(self) -> ATTACKCatalogSnapshot:
        candidate = load_snapshot(self._path)
        self._snapshot = candidate
        return candidate

    def publish(self, candidate: ATTACKCatalogSnapshot) -> None:
        self._snapshot = candidate
