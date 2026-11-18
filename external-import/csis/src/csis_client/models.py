"""CSIS CDF row model."""

import ipaddress
import json
from typing import Literal

from pydantic import AwareDatetime, BaseModel, Field, field_validator

FeedType = Literal["essential", "advanced"]
FEED_TYPES: tuple[str, ...] = FeedType.__args__


def _parse_json_array(value: object) -> list[str]:
    """Accept a native list or a JSON-encoded string list (CSIS sends the latter)."""
    if isinstance(value, str):
        try:
            value = json.loads(value) if value else []
        except json.JSONDecodeError:
            return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return []


class CSISIndicatorRow(BaseModel):
    """One IOC record from a CSIS CDF feed."""

    kind: Literal["domain", "ip"]
    value: str = Field(min_length=1)
    first_seen: AwareDatetime
    confidence_score: int = Field(ge=0, le=100)
    malware: list[str] = Field(default_factory=list)
    # 'advanced' feed only
    category: list[str] = Field(default_factory=list)
    threat_actors: list[str] = Field(default_factory=list)
    feed_type: FeedType

    @field_validator("malware", "category", "threat_actors", mode="before")
    @classmethod
    def _validate_array_fields(cls, value: object) -> list[str]:
        return _parse_json_array(value)

    @property
    def is_ipv6(self) -> bool:
        if self.kind != "ip":
            return False
        try:
            return ipaddress.ip_address(self.value).version == 6
        except ValueError:
            return False
