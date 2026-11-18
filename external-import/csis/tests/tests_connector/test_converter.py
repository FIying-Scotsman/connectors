from datetime import datetime, timezone

import pytest
from connector import Converter
from connectors_sdk.models import (
    DomainName,
    Indicator,
    IntrusionSet,
    IPV4Address,
    IPV6Address,
    Malware,
    Relationship,
)
from connectors_sdk.models.enums import RelationshipType, TLPLevel
from csis_client import CSISIndicatorRow


@pytest.fixture
def converter() -> Converter:
    return Converter(tlp_level=TLPLevel.AMBER)


def _row(raw_row: dict, **overrides) -> CSISIndicatorRow:
    return CSISIndicatorRow.model_validate(
        {**raw_row, "feed_type": "advanced", **overrides}
    )


def _first(objects: list, cls: type):
    return next(o for o in objects if isinstance(o, cls))


def _has_rel(objects: list, rel_type: RelationshipType, source, target) -> bool:
    return any(
        isinstance(o, Relationship)
        and o.type == rel_type
        and o.source.id == source.id
        and o.target.id == target.id
        for o in objects
    )


def test_bootstrap_objects(converter) -> None:
    assert [o.id for o in converter.bootstrap_objects] == [
        converter.author.id,
        converter.marking.id,
    ]


def test_from_row_builds_observable_and_indicator(converter, raw_row) -> None:
    objects = converter.from_row(_row(raw_row))
    domain = _first(objects, DomainName)
    indicator = _first(objects, Indicator)

    assert domain.value == "evil.example.com"
    assert domain.score == 90
    assert domain.labels == ["Command and control"]
    assert indicator.score == 90
    assert indicator.valid_from == datetime(2026, 7, 25, 17, 25, 1, tzinfo=timezone.utc)
    assert indicator.main_observable_type == "Domain-Name"
    assert indicator.pattern == "[domain-name:value = 'evil.example.com']"
    assert _has_rel(objects, RelationshipType.BASED_ON, indicator, domain)


@pytest.mark.parametrize(
    "value, cls, pattern",
    [
        ("1.2.3.4", IPV4Address, "[ipv4-addr:value = '1.2.3.4']"),
        ("2001:db8::1", IPV6Address, "[ipv6-addr:value = '2001:db8::1']"),
    ],
)
def test_from_row_ip_kinds(converter, raw_row, value, cls, pattern) -> None:
    objects = converter.from_row(_row(raw_row, kind="ip", value=value))

    assert _first(objects, cls).value == value
    assert _first(objects, Indicator).pattern == pattern


def test_from_row_links_malware_and_intrusion_set(converter, raw_row) -> None:
    objects = converter.from_row(_row(raw_row))
    indicator = _first(objects, Indicator)
    domain = _first(objects, DomainName)
    malware = _first(objects, Malware)
    intrusion_set = _first(objects, IntrusionSet)

    assert malware.name == "clearfake"
    assert malware.is_family is True
    assert intrusion_set.name == "APT33"
    for threat in (malware, intrusion_set):
        assert _has_rel(objects, RelationshipType.INDICATES, indicator, threat)
        assert _has_rel(objects, RelationshipType.RELATED_TO, domain, threat)


def test_from_row_always_emits_referenced_threats(converter, raw_row) -> None:
    converter.from_row(_row(raw_row, value="a.example.com"))
    objects = converter.from_row(_row(raw_row, value="b.example.com"))

    assert any(isinstance(o, Malware) for o in objects)
    assert any(isinstance(o, IntrusionSet) for o in objects)
