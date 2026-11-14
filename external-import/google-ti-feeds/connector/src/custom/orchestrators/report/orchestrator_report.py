"""Report-specific orchestrator for fetching and processing report data."""

import base64
import re
from collections.abc import AsyncIterator
from datetime import timedelta
from typing import Any

from connector.src.custom.configs import REPORT_BATCH_PROCESSOR_CONFIG
from connector.src.custom.convert_to_stix.report.convert_to_stix_report import (
    ConvertToSTIXReport,
)
from connector.src.custom.mappers.gti_reports.gti_report_to_stix_report import (
    GTIReportToSTIXReport,
)
from connector.src.custom.orchestrators.collection_orchestrator import (
    CollectionOrchestrator,
)


class OrchestratorReport(CollectionOrchestrator):
    """Report-specific orchestrator for fetching and processing report data."""

    LOG_PREFIX = "[OrchestratorReport]"
    collection = "report"
    progress_label = "reports"
    converter_class = ConvertToSTIXReport
    converter: ConvertToSTIXReport
    batch_processor_config = REPORT_BATCH_PROCESSOR_CONFIG

    def _subentity_types(self) -> list[str]:
        return list(self.config.report_subentities)

    def _import_start_date(self) -> timedelta:
        return self.config.report_import_start_date

    def _fetch(self, initial_state: dict[str, Any] | None) -> AsyncIterator[Any]:
        return self.client_api.fetch_reports(initial_state)

    def _convert(self, entity: Any) -> list[Any]:
        return self.converter.convert_report_to_stix(entity)

    def _progress_total(self) -> int | None:
        return self.client_api.real_total_reports

    async def _finalize_entities(
        self, entity: Any, all_entities: list[Any]
    ) -> list[Any]:
        """Attach the report PDF when enabled.

        Args:
            entity: The GTI report.
            all_entities: STIX objects of the report and its sub-entities.

        Returns:
            The STIX objects to send.

        """
        if not self.config.report_download_pdf:
            return all_entities
        return await self._attach_report_pdf(entity, all_entities)

    def _link_co_occurring_entities(
        self, main_entities: list[Any], subentity_stix: list[Any]
    ) -> list[Any]:
        """Create the enabled co-occurrence relationships and add them to the report.

        Args:
            main_entities: STIX objects of the report, including the report.
            subentity_stix: Converted sub-entities of the report.

        Returns:
            The created relationships.

        """
        relationship_types = self._co_occurrence_relationship_types(
            ("intrusion-set", "malware", "campaign")
        )
        if not relationship_types:
            return []
        report = self._main_entity(main_entities, "report")
        relationships = self.converter.create_co_occurrence_relationships(
            subentity_stix, relationship_types, container=report
        )
        if report is not None:
            GTIReportToSTIXReport.add_object_refs(
                [relationship.id for relationship in relationships if relationship.id],
                report,
            )
        return relationships

    async def _attach_report_pdf(
        self, report: Any, all_entities: list[Any]
    ) -> list[Any]:
        """Download and attach a report PDF to the STIX report entity.

        Args:
            report: The GTI report data object.
            all_entities: The list of STIX entities (including the report).

        Returns:
            The updated list of STIX entities with the PDF attached.

        """
        pdf_content = await self.client_api.download_report_pdf(report.id)
        if not pdf_content:
            return all_entities

        self.logger.info(
            "Attaching PDF to report",
            {
                "prefix": self.LOG_PREFIX,
                "report_id": report.id,
                "pdf_size": len(pdf_content),
            },
        )

        report_name = (
            report.attributes.name
            if report.attributes and report.attributes.name
            else report.id
        )
        safe_name = re.sub(r"[^\w\s\-.]", "_", report_name)[:100]

        pdf_file = {
            "name": f"{safe_name}.pdf",
            "data": base64.b64encode(pdf_content).decode("utf-8"),
            "mime_type": "application/pdf",
            "no_trigger_import": True,
        }

        for entity in all_entities:
            if getattr(entity, "type", None) == "report":
                if hasattr(entity, "custom_properties"):
                    if entity.custom_properties is None:
                        entity.custom_properties = {}
                    existing_files = entity.custom_properties.get("x_opencti_files", [])
                    existing_files.append(pdf_file)
                    entity.custom_properties["x_opencti_files"] = existing_files
                break

        return all_entities
