"""Domain-separated semantic hashes shared by Shortcut Authority V2 primitives."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from fieldtrue.canonical import sha256_value

INCIDENT_ID_LIST_DOMAIN: Final = "inbar.iter001.shortcut-incident-id-list.v1"


def incident_id_list_sha256(incident_ids: Sequence[str]) -> str:
    """Hash one canonical, duplicate-free incident-ID list under a fixed domain."""

    frozen = tuple(incident_ids)
    try:
        ordered = tuple(sorted(frozen, key=lambda item: item.encode("utf-8")))
    except (AttributeError, UnicodeEncodeError) as error:
        raise ValueError("incident IDs must be valid UTF-8 strings") from error
    if frozen != ordered:
        raise ValueError("incident IDs must be in canonical UTF-8 order")
    if len(frozen) != len(set(frozen)):
        raise ValueError("incident IDs must be unique")
    return sha256_value({"domain": INCIDENT_ID_LIST_DOMAIN, "items": list(frozen)})
