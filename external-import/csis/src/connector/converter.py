"""Convert CSIS CDF rows into connectors-sdk objects."""

from connectors_sdk.models import (
    BaseIdentifiedEntity,
    BaseIdentifiedObject,
    DomainName,
    Indicator,
    IntrusionSet,
    IPV4Address,
    IPV6Address,
    Malware,
    OrganizationAuthor,
    Relationship,
    TLPMarking,
)
from connectors_sdk.models.enums import RelationshipType, TLPLevel
from csis_client import CSISIndicatorRow

Observable = DomainName | IPV4Address | IPV6Address


class Converter:
    """Build the OpenCTI objects for each CSIS IOC row."""

    def __init__(self, tlp_level: TLPLevel) -> None:
        self.author = OrganizationAuthor(name="CSIS Cyber Data Feed (CDF)")
        self.marking = TLPMarking(level=tlp_level)
        self.markings = [self.marking]

    @property
    def bootstrap_objects(self) -> list[BaseIdentifiedObject]:
        """Author and marking; referenced by every object so needed in every bundle."""
        return [self.author, self.marking]

    def from_row(self, row: CSISIndicatorRow) -> list[BaseIdentifiedObject]:
        """Observable, indicator, linked malware/intrusion sets and relationships."""
        description = (
            f"CSIS Cyber Data Feed ('{row.feed_type}' feed). "
            f"First seen: {row.first_seen.isoformat()}. "
            f"Confidence score: {row.confidence_score}."
        )
        labels = row.category or None
        observable = self._build_observable(row, description, labels)
        indicator = Indicator(
            name=row.value,
            pattern=self._build_pattern(row),
            pattern_type="stix",
            main_observable_type=self._observable_type(row),
            description=description,
            labels=labels,
            indicator_types=["malicious-activity"],
            score=row.confidence_score,
            valid_from=row.first_seen,
            author=self.author,
            markings=self.markings,
        )
        objects: list[BaseIdentifiedObject] = [
            observable,
            indicator,
            self._relationship(RelationshipType.BASED_ON, indicator, observable),
        ]

        threats: list[BaseIdentifiedEntity] = [
            Malware(
                name=name, is_family=True, author=self.author, markings=self.markings
            )
            for name in row.malware
        ]
        threats += [
            IntrusionSet(name=name, author=self.author, markings=self.markings)
            for name in row.threat_actors
        ]
        for threat in threats:
            objects += [
                threat,
                self._relationship(RelationshipType.INDICATES, indicator, threat),
                self._relationship(RelationshipType.RELATED_TO, observable, threat),
            ]
        return objects

    def _build_observable(
        self, row: CSISIndicatorRow, description: str, labels: list[str] | None
    ) -> Observable:
        if row.kind == "domain":
            observable_cls = DomainName
        elif row.is_ipv6:
            observable_cls = IPV6Address
        else:
            observable_cls = IPV4Address
        return observable_cls(
            value=row.value,
            description=description,
            labels=labels,
            score=row.confidence_score,
            author=self.author,
            markings=self.markings,
        )

    @staticmethod
    def _observable_type(row: CSISIndicatorRow) -> str:
        if row.kind == "domain":
            return "Domain-Name"
        return "IPv6-Addr" if row.is_ipv6 else "IPv4-Addr"

    @classmethod
    def _build_pattern(cls, row: CSISIndicatorRow) -> str:
        value = row.value.replace("\\", "\\\\").replace("'", "\\'")
        return f"[{cls._observable_type(row).lower()}:value = '{value}']"

    def _relationship(
        self,
        relationship_type: RelationshipType,
        source: BaseIdentifiedEntity,
        target: BaseIdentifiedEntity,
    ) -> Relationship:
        return Relationship(
            type=relationship_type,
            source=source,
            target=target,
            author=self.author,
            markings=self.markings,
        )
