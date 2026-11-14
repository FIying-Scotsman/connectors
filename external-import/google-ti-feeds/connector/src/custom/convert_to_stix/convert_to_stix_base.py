"""Base converter class with common functionality."""

import logging
from collections import defaultdict
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any, Literal, cast

from connector.src.custom.configs import (
    GTIConfig,
)
from connector.src.custom.configs.converter_config import (
    CONVERTER_CONFIGS,
)
from connector.src.custom.configs.gti_config_common import IOC_SUBENTITY_TYPES
from connector.src.stix.octi.models.relationship_model import OctiRelationshipModel
from connector.src.stix.v21.models.sros.relationship_model import RelationshipModel
from connector.src.utils.converters import GenericConverterFactory
from connectors_sdk.models import (  # type: ignore[import-untyped]
    OrganizationAuthor,
    TLPMarking,
)

LOG_PREFIX = "[BaseConverter]"

IOC_OBSERVABLE_STIX_TYPES = ("domain-name", "file", "url", "ipv4-addr", "ipv6-addr")


def ioc_threat_relationship_types(
    threat_types: Iterable[str],
) -> dict[tuple[str, str], str]:
    """Return the co-occurrence rules linking IOCs to the given threat types.

    Indicators get 'indicates', observables get 'related-to'.
    """
    return {
        (ioc_type, threat_type): (
            "indicates" if ioc_type == "indicator" else "related-to"
        )
        for ioc_type in ("indicator", *IOC_OBSERVABLE_STIX_TYPES)
        for threat_type in threat_types
    }


class BaseConvertToSTIX:
    """Base converter class with common functionality."""

    def __init__(self, config: GTIConfig, logger: logging.Logger, tlp_level: str):
        """Initialize Base Convert to STIX."""
        self.config = config
        self.logger = logger
        self.tlp_level = tlp_level.lower()
        self.organization = self._create_organization()
        self.tlp_marking = self._create_tlp_marking()
        self.converter_factory = self._create_converter_factory()

    def _create_converter_factory(self) -> GenericConverterFactory:
        """Create and configure the converter factory with all configurations.

        Returns:
            Configured GenericConverterFactory instance

        """
        global_dependencies = {
            "organization": self.organization,
            "tlp_marking": self.tlp_marking,
        }

        factory = GenericConverterFactory(
            global_dependencies=global_dependencies,
            logger=self.logger,
        )

        for entity_type, config in CONVERTER_CONFIGS.items():
            factory.register_config(entity_type, config)
            self.logger.debug(
                "Registered converter config",
                {"prefix": LOG_PREFIX, "entity_type": entity_type},
            )

        return factory

    def _create_organization(self) -> OrganizationAuthor:
        """Create the organization identity object.

        Returns:
            Identity: The organization identity object

        """
        organization = OrganizationAuthor(
            name="Google Threat Intelligence",
            description="Google Threat Intelligence provides information on the latest threats.",
            contact_information="https://gtidocs.virustotal.com",
            organization_type="vendor",
            reliability=None,
            aliases=["GTI"],
        )

        self.logger.debug("Created organization identity", {"prefix": LOG_PREFIX})
        return organization

    def _create_tlp_marking(self) -> TLPMarking:
        """Create the TLP marking definition object.

        Returns:
            MarkingDefinition: The TLP marking definition object

        """
        tlp_level = self.tlp_level.lower()
        normalized_level = tlp_level.lower()

        if normalized_level not in (
            "white",
            "green",
            "amber",
            "amber+strict",
            "red",
        ):
            normalized_level = "amber"
            self.logger.warning(
                "Invalid TLP level, defaulting to 'amber'",
                {
                    "prefix": LOG_PREFIX,
                    "tlp_level": tlp_level,
                    "default_level": "amber",
                },
            )

        tlp_literal = cast(
            Literal["white", "green", "amber", "amber+strict", "red"],
            normalized_level,
        )

        tlp_marking = TLPMarking(level=tlp_literal)

        self.logger.debug(
            "Created TLP marking", {"prefix": LOG_PREFIX, "level": normalized_level}
        )
        return tlp_marking

    def convert_subentities_to_stix(
        self, subentities: dict[str, list[Any]], main_entity: str | None = None
    ) -> list[Any]:
        """Convert each subentity to STIX format.

        Args:
            subentities: dictionary mapping entity types to lists of entities
            main_entity: Type of the main entity

        Returns:
            list of converted STIX objects

        """
        all_stix_entities = []
        _prefix = ""
        if main_entity:
            _prefix = f"{main_entity}_"

        for entity_type, entities in subentities.items():
            if not entities:
                continue

            try:
                # Check if we need to pass additional dependencies for aliases
                additional_deps = {}
                if entity_type == "malware_families" and hasattr(
                    self.config, "enable_malware_aliases"
                ):
                    additional_deps["enable_malware_aliases"] = (
                        self.config.enable_malware_aliases
                    )
                elif entity_type == "threat_actors" and hasattr(
                    self.config, "enable_threat_actor_aliases"
                ):
                    additional_deps["enable_threat_actor_aliases"] = (
                        self.config.enable_threat_actor_aliases
                    )
                elif entity_type in IOC_SUBENTITY_TYPES and hasattr(
                    self.config, "indicator_scoring"
                ):
                    additional_deps["indicator_scoring"] = self.config.indicator_scoring

                converter = self.converter_factory.create_converter_by_name(
                    f"{_prefix}{entity_type}", additional_dependencies=additional_deps
                )
                stix_entities = converter.convert_multiple(entities)
                all_stix_entities.extend(stix_entities)
                self.logger.debug(
                    "Converted entities to STIX",
                    {
                        "prefix": LOG_PREFIX,
                        "entity_count": len(stix_entities),
                        "entity_type": entity_type,
                    },
                )

            except Exception as e:
                self.logger.warning(
                    "Failed to convert entity to STIX",
                    {"prefix": LOG_PREFIX, "entity_type": entity_type, "error": str(e)},
                )

        return all_stix_entities

    def convert_subentities_to_stix_with_linking(
        self,
        subentities: dict[str, list[Any]],
        main_entity: str,
        main_entities: list[Any],
    ) -> list[Any] | None:
        """Convert each subentity to STIX format with linking.

        Args:
            subentities: dictionary mapping entity types to lists of entities
            main_entity: The main entity type
            main_entities: list containing the main entity STIX object

        Returns:
            list of converted STIX objects

        """
        all_stix_entities = self.convert_subentities_to_stix(subentities, main_entity)

        self.logger.debug(
            "Converted sub-entities with linking",
            {"prefix": LOG_PREFIX, "main_entity": main_entity},
        )

        return all_stix_entities

    def create_co_occurrence_relationships(
        self,
        stix_objects: list[Any],
        relationship_types: Mapping[tuple[str, str], str],
    ) -> list[RelationshipModel]:
        """Link entities converted for the same report or campaign.

        Every object of a source type is linked to every object of its target type.

        Args:
            stix_objects: Converted sub-entities of a single report or campaign.
            relationship_types: Relationship type keyed by (source, target) STIX type.

        Returns:
            The created relationships.

        """
        ids_by_type: dict[str, list[str]] = defaultdict(list)
        for obj in stix_objects:
            obj_type = getattr(obj, "type", None)
            if obj_type:
                ids_by_type[obj_type].append(obj.id)

        now = datetime.now(timezone.utc)
        relationships = [
            OctiRelationshipModel.create(
                relationship_type=relationship_type,
                source_ref=source_id,
                target_ref=target_id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                created=now,
                modified=now,
            )
            for (source_type, target_type), relationship_type in (
                relationship_types.items()
            )
            for source_id in ids_by_type.get(source_type, [])
            for target_id in ids_by_type.get(target_type, [])
        ]

        self.logger.debug(
            "Created co-occurrence relationships",
            {"prefix": LOG_PREFIX, "count": len(relationships)},
        )
        return relationships
