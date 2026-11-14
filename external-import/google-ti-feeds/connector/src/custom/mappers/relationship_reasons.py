"""Relationship descriptions stating why the connector created a relationship.

"Stated by GTI" marks a GTI association, "Inferred by the connector" a link GTI
does not state. Written only with GTI_RELATIONSHIP_DESCRIPTIONS: by default the
connector leaves relationship descriptions empty, so it never overwrites a
description written by an analyst or another source (#5775).
"""

from typing import Any

from pydantic import BaseModel

# Set by the converters from GTI_RELATIONSHIP_DESCRIPTIONS.
_SETTINGS = {"enabled": False}


def set_relationship_descriptions(enabled: bool) -> None:
    """Enable or disable the relationship descriptions of this module."""
    _SETTINGS["enabled"] = enabled


def optional_reason(reason: str) -> str | None:
    """Return the reason when relationship descriptions are enabled, else None."""
    return reason if _SETTINGS["enabled"] else None


# STIX type -> label used in descriptions. Other types: type with spaces.
STIX_TYPE_LABELS = {
    "attack-pattern": "attack pattern",
    "autonomous-system": "autonomous system",
    "domain-name": "domain",
    "intrusion-set": "intrusion set",
    "ipv4-addr": "IP address",
    "ipv6-addr": "IP address",
    "url": "URL",
}


def type_label(obj: Any) -> str:
    """Return the label of the STIX type of an object, e.g. 'intrusion set'."""
    stix_type = str(getattr(obj, "type", "object"))
    return STIX_TYPE_LABELS.get(stix_type, stix_type.replace("-", " "))


def display_name(obj: Any) -> str:
    """Return the name shown for an object: name, value, SHA-256, AS number, or ID."""
    for field in ("name", "value"):
        value = getattr(obj, field, None)
        if value:
            return str(value)
    hashes = getattr(obj, "hashes", None) or {}
    if sha256 := hashes.get("SHA-256"):
        return str(sha256)
    if (number := getattr(obj, "number", None)) is not None:
        return f"AS{number}"
    return str(getattr(obj, "id", "unknown"))


def describe(obj: Any) -> str:
    """Return "the <type> '<name>'"."""
    return f"the {type_label(obj)} '{display_name(obj)}'"


def with_description(relationship: Any, description: str) -> Any:
    """Return the relationship model with `description` when it has none and enabled.

    Objects other than Pydantic relationship models are returned unchanged.
    """
    if not _SETTINGS["enabled"] or (
        not isinstance(relationship, BaseModel)
        or "description" not in type(relationship).model_fields
    ):
        return relationship
    if getattr(relationship, "description", None):
        return relationship
    return relationship.model_copy(update={"description": description})


def gti_association_reason(context_entity: Any, entity: Any) -> str:
    """Reason for a link from a GTI collection to an entity it lists."""
    return (
        f"Stated by GTI: Google Threat Intelligence lists {describe(entity)} "
        f"among the related objects of {describe(context_entity)}."
    )


def ioc_delta_association_reason(target: Any) -> str:
    """Reason for a link from an IOC deltas feed indicator to an entity of its entry."""
    return (
        f"Stated by GTI: the IOC deltas feed lists {describe(target)} among the "
        "relationships of this IOC."
    )


def ip_autonomous_system_reason(asn: int, as_owner: str | None) -> str:
    """Reason for the link from an IP to its autonomous system."""
    owner = f" ({as_owner})" if as_owner else ""
    return (
        f"Stated by GTI: GTI lists AS{asn}{owner} as the autonomous system of this IP."
    )


def ip_country_reason(country_name: str, country_code: str) -> str:
    """Reason for the link from an IP to its country."""
    return (
        f"Stated by GTI: GTI geolocates this IP in {country_name} "
        f"(country code {country_code})."
    )


def co_occurrence_reason(source: Any, target: Any, container: Any | None) -> str:
    """Reason for a link between two entities of the same report or campaign."""
    where = describe(container) if container is not None else "a GTI report or campaign"
    return (
        f"Inferred by the connector, not stated by GTI: {describe(source)} and "
        f"{describe(target)} are both referenced by {where}."
    )
