from __future__ import annotations

from collections.abc import Iterable

from aws_tools.cloudformation import StackOwnership


def tag_dict(tags: Iterable[dict] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for tag in tags or []:
        key = tag.get("Key") or tag.get("key")
        value = tag.get("Value") or tag.get("value")
        if key is not None and value is not None:
            result[str(key)] = str(value)
    return result


def stack_owner_for(
    ownership: dict[str, StackOwnership],
    *identifiers: str | None,
) -> StackOwnership | None:
    for identifier in _stack_owner_candidates(*identifiers):
        owner = ownership.get(identifier)
        if owner:
            return owner
    return None


def stack_fields(owner: StackOwnership | None) -> dict[str, str]:
    if owner is None:
        return {}
    return {
        "stack_id": owner.stack_id,
        "stack_name": owner.stack_name,
        "stack_logical_resource_id": owner.logical_resource_id,
        "stack_resource_type": owner.resource_type,
        "stack_region": owner.region,
    }


def _stack_owner_candidates(*identifiers: str | None) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()
    for identifier in identifiers:
        if not identifier:
            continue
        for candidate in _identifier_candidates(identifier):
            if candidate and candidate not in seen:
                seen.add(candidate)
                candidates.append(candidate)
    return candidates


def _identifier_candidates(identifier: str) -> list[str]:
    candidates = [identifier]
    if not identifier.startswith("arn:"):
        return candidates

    parts = identifier.split(":", 5)
    if len(parts) < 6:
        return candidates

    resource = parts[5]
    candidates.append(resource)
    if resource.startswith("log-group:"):
        candidates.append(resource.removeprefix("log-group:").removesuffix(":*"))
    if "/" in resource:
        candidates.append(resource.rsplit("/", 1)[-1])
    if ":" in resource:
        candidates.append(resource.rsplit(":", 1)[-1])
    return candidates
