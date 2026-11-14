"""Pydantic models for GTI IOC delta NDJSON format."""

from connector.src.custom.models.gti.gti_assessment_model import GTIAssessment
from pydantic import BaseModel, Field


class IOCDeltaRelationshipItemAttributes(BaseModel):
    collection_type: str | None = Field(None)
    name: str | None = Field(None)


class IOCDeltaRelationshipItem(BaseModel):
    type: str | None = Field(None)
    id: str | None = Field(None)
    attributes: IOCDeltaRelationshipItemAttributes | None = Field(None)


class IOCDeltaRelationshipData(BaseModel):
    data: list[IOCDeltaRelationshipItem] = Field(default_factory=list)


class IOCDeltaRelationships(BaseModel):
    malware_families: IOCDeltaRelationshipData | None = Field(None)
    campaigns: IOCDeltaRelationshipData | None = Field(None)
    threat_actors: IOCDeltaRelationshipData | None = Field(None)
    reports: IOCDeltaRelationshipData | None = Field(None)
    software_toolkits: IOCDeltaRelationshipData | None = Field(None)
    vulnerabilities: IOCDeltaRelationshipData | None = Field(None)
    attack_techniques: IOCDeltaRelationshipData | None = Field(None)


class IOCDeltaAttributes(BaseModel):
    # File fields
    sha256: str | None = Field(None)
    md5: str | None = Field(None)
    sha1: str | None = Field(None)
    meaningful_name: str | None = Field(None)
    names: list[str] | None = Field(None)
    size: int | None = Field(None)
    # URL fields
    url: str | None = Field(None)
    # IP address fields
    asn: int | None = Field(None)
    as_owner: str | None = Field(None)
    country: str | None = Field(None)
    continent: str | None = Field(None)
    network: str | None = Field(None)
    regional_internet_registry: str | None = Field(None)
    # Common fields
    gti_assessment: GTIAssessment | None = Field(None)
    tags: list[str] | None = Field(None)
    creation_date: int | None = Field(None)
    last_modification_date: int | None = Field(None)


class IOCDeltaEntry(BaseModel):
    """A single IOC entry from the delta NDJSON stream."""

    id: str = Field(...)
    type: str = Field(...)  # "file", "ip_address", "domain", "url"
    attributes: IOCDeltaAttributes | None = Field(None)
    relationships: IOCDeltaRelationships | None = Field(None)
