from datetime import datetime, timezone

import pytest
from csis_client import CSISIndicatorRow
from pydantic import ValidationError


def test_row_parses_stringified_arrays(raw_row) -> None:
    row = CSISIndicatorRow.model_validate(raw_row | {"feed_type": "advanced"})

    assert row.malware == ["clearfake"]
    assert row.category == ["Command and control"]
    assert row.threat_actors == ["APT33"]
    assert row.first_seen == datetime(2026, 7, 25, 17, 25, 1, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "value, expected",
    [
        (["gigawiper"], ["gigawiper"]),
        ("[]", []),
        ("", []),
        ("not-json", []),
        (None, []),
    ],
)
def test_row_array_field_variants(raw_row, value, expected) -> None:
    row = CSISIndicatorRow.model_validate(
        raw_row | {"malware": value, "feed_type": "essential"}
    )
    assert row.malware == expected


def test_row_missing_optional_arrays_default_empty(raw_row) -> None:
    del raw_row["category"], raw_row["threat_actors"]
    row = CSISIndicatorRow.model_validate(raw_row | {"feed_type": "essential"})

    assert row.category == []
    assert row.threat_actors == []


@pytest.mark.parametrize(
    "kind, value, expected",
    [("ip", "2001:db8::1", True), ("ip", "1.2.3.4", False), ("domain", "a.com", False)],
)
def test_row_is_ipv6(raw_row, kind, value, expected) -> None:
    row = CSISIndicatorRow.model_validate(
        raw_row | {"kind": kind, "value": value, "feed_type": "essential"}
    )
    assert row.is_ipv6 is expected


def test_row_rejects_naive_first_seen(raw_row) -> None:
    with pytest.raises(ValidationError):
        CSISIndicatorRow.model_validate(
            raw_row | {"first_seen": "2026-07-25T17:25:01", "feed_type": "essential"}
        )
