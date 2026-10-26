from __future__ import annotations

from collections.abc import Iterable, Mapping
from types import MappingProxyType

from app.behavior.rules import BUILTIN_RULES
from app.schemas.behavior_rules import BehavioralRule, RuleIdentifier


class RuleRegistryValidationError(RuntimeError):
    """Trusted rule definitions conflict or violate registry invariants."""


class UnknownRuleError(LookupError):
    """A syntactically valid requested rule ID is not registered."""


class RuleRegistry:
    def __init__(self, rules: Iterable[BehavioralRule] = BUILTIN_RULES) -> None:
        ordered = tuple(sorted(rules, key=lambda rule: rule.rule_id))
        by_id: dict[str, BehavioralRule] = {}
        for rule in ordered:
            if rule.rule_id in by_id:
                raise RuleRegistryValidationError("Duplicate rule identifier")
            by_id[rule.rule_id] = rule
        if not by_id:
            raise RuleRegistryValidationError("Rule registry must not be empty")
        self._rules = ordered
        self._by_id: Mapping[str, BehavioralRule] = MappingProxyType(by_id)

    @property
    def rules(self) -> tuple[BehavioralRule, ...]:
        return self._rules

    def select(
        self, rule_ids: tuple[RuleIdentifier, ...] | None
    ) -> tuple[BehavioralRule, ...]:
        if rule_ids is None:
            return tuple(rule for rule in self._rules if rule.enabled)
        selected: list[BehavioralRule] = []
        for rule_id in rule_ids:
            rule = self._by_id.get(rule_id)
            if rule is None:
                raise UnknownRuleError(rule_id)
            selected.append(rule)
        return tuple(sorted(selected, key=lambda rule: rule.rule_id))


DEFAULT_RULE_REGISTRY = RuleRegistry()
