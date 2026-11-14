"""STIX locations and sectors paired with the dates GTI associated them with an entity."""

from datetime import datetime

from pydantic import BaseModel
from stix2.v21 import Identity, Location  # type: ignore


class LocationWithTiming(BaseModel):
    """Container for a STIX Location object with timing metadata."""

    model_config = {"arbitrary_types_allowed": True}

    location: Location
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    is_targeted: bool = False
    is_source: bool = False


class IdentityWithTiming(BaseModel):
    """Container for a STIX Identity object with timing metadata."""

    model_config = {"arbitrary_types_allowed": True}

    identity: Identity
    first_seen: datetime | None = None
    last_seen: datetime | None = None
