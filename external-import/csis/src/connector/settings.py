"""Connector configuration (env vars `CSIS_*` or `config.yml`)."""

from datetime import timedelta
from typing import Annotated

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from connectors_sdk.settings.annotated_types import parse_comma_separated_list
from csis_client import FeedType
from pydantic import BeforeValidator, Field, SecretStr

FeedTypesFromString = Annotated[
    list[FeedType], BeforeValidator(parse_comma_separated_list)
]


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    id: str = Field(
        description="The unique identifier of the connector.",
        default="548409fd-7c10-4c16-9015-6e44ba7e1513",
    )
    name: str = Field(
        description="The name of the connector.",
        default="CSIS Cyber Data Feed",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, i.e. the entity types it imports.",
        default=[
            "IPv4-Addr",
            "IPv6-Addr",
            "Domain-Name",
            "Indicator",
            "Malware",
            "Intrusion-Set",
        ],
    )
    duration_period: timedelta = Field(
        description="Time to wait between two runs of the connector, as an ISO 8601 "
        "duration (e.g. `PT6H` for six hours).",
        default=timedelta(hours=6),
    )


class CSISConfig(BaseConfigModel):
    """Options specific to the CSIS connector."""

    client_id: SecretStr = Field(description="CSIS OAuth2 client ID.")
    client_secret: SecretStr = Field(description="CSIS OAuth2 client secret.")
    feed_types: FeedTypesFromString = Field(
        description="Comma-separated CSIS CDF feeds to ingest: `essential` (IOCs + "
        "malware) and/or `advanced` (IOCs + malware + threat category + threat actors).",
        default=["advanced"],
        min_length=1,
    )
    tlp_level: TLPLevel = Field(
        description="TLP marking applied to every object this connector creates.",
        default=TLPLevel.AMBER,
    )
    min_confidence_score: int = Field(
        description="Minimum CSIS `confidence_score` (0-100) an IOC must have to be ingested.",
        default=0,
        ge=0,
        le=100,
    )
    request_timeout_seconds: int = Field(
        description="Timeout in seconds for each request to the CSIS API.",
        default=60,
        ge=1,
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    csis: CSISConfig = Field(default_factory=CSISConfig)  # type: ignore[arg-type]
