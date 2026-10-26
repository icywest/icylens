from __future__ import annotations

from collections.abc import Iterable, Mapping
from types import MappingProxyType

from app.attack.catalog import ATTACKCatalogSnapshot
from app.behavior.attack_mapping_policies import BUILTIN_ATTACK_MAPPING_POLICIES
from app.schemas.attack_mapping import (
    AttackMappingPolicy,
    AttackMappingPolicyIdentifier,
)


class MappingPolicyValidationError(RuntimeError):
    pass


class UnknownMappingPolicyError(LookupError):
    pass


class AttackMappingPolicyRegistry:
    def __init__(
        self, policies: Iterable[AttackMappingPolicy] = BUILTIN_ATTACK_MAPPING_POLICIES
    ) -> None:
        ordered = tuple(sorted(policies, key=lambda item: item.policy_id))
        by_id: dict[str, AttackMappingPolicy] = {}
        for policy in ordered:
            if policy.policy_id in by_id:
                raise MappingPolicyValidationError(
                    "Duplicate mapping policy identifier"
                )
            by_id[policy.policy_id] = policy
        if not by_id:
            raise MappingPolicyValidationError(
                "Mapping policy registry must not be empty"
            )
        self._policies = ordered
        self._by_id: Mapping[str, AttackMappingPolicy] = MappingProxyType(by_id)

    @property
    def policies(self) -> tuple[AttackMappingPolicy, ...]:
        return self._policies

    def select(
        self, policy_ids: tuple[AttackMappingPolicyIdentifier, ...] | None
    ) -> tuple[AttackMappingPolicy, ...]:
        if policy_ids is None:
            return self._policies
        selected: list[AttackMappingPolicy] = []
        for policy_id in policy_ids:
            policy = self._by_id.get(policy_id)
            if policy is None:
                raise UnknownMappingPolicyError(policy_id)
            selected.append(policy)
        return tuple(sorted(selected, key=lambda item: item.policy_id))

    def validate_catalog(self, snapshot: ATTACKCatalogSnapshot) -> None:
        for policy in self._policies:
            if policy.technique_id not in snapshot.techniques_by_id:
                raise MappingPolicyValidationError(
                    "Mapping policy references an unknown ATT&CK technique"
                )


DEFAULT_ATTACK_MAPPING_POLICY_REGISTRY = AttackMappingPolicyRegistry()
