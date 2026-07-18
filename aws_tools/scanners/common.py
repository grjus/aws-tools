from __future__ import annotations

from collections.abc import Iterable


def tag_dict(tags: Iterable[dict] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for tag in tags or []:
        key = tag.get("Key") or tag.get("key")
        value = tag.get("Value") or tag.get("value")
        if key is not None and value is not None:
            result[str(key)] = str(value)
    return result
