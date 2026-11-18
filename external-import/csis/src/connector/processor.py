"""Fetch each configured CSIS CDF feed and stream it to OpenCTI in bundles."""

from collections.abc import Generator

from connector.converter import Converter
from connectors_sdk import BaseDataProcessor
from connectors_sdk.models import BaseIdentifiedObject
from csis_client import CSISClient, CSISIndicatorRow
from pydantic import ValidationError

# Objects per bundle; bounds memory and bundle size (~44k rows on 'advanced').
BATCH_SIZE = 5000

Feed = tuple[str, list[dict]]


class FeedProcessor(BaseDataProcessor):
    work_name = "CSIS Cyber Data Feed"

    def __init__(
        self,
        client: CSISClient,
        converter: Converter,
        feed_types: list[str],
        min_confidence_score: int = 0,
    ) -> None:
        self.client = client
        self.converter = converter
        self.feed_types = feed_types
        self.min_confidence_score = min_confidence_score

    def collect(self) -> Generator[Feed, None, None]:
        """Yield `(feed_type, rows)`; a failing feed is logged and skipped."""
        for feed_type in self.feed_types:
            self.logger.info("Fetching CSIS feed.", {"feed_type": feed_type})
            try:
                rows = self.client.fetch_feed(feed_type)
            except Exception as err:  # noqa: BLE001
                self.logger.error(
                    "Failed to fetch CSIS feed.",
                    {"feed_type": feed_type, "error": str(err)},
                )
                continue
            yield feed_type, rows

    def transform(
        self, data: Generator[Feed, None, None]
    ) -> Generator[list[BaseIdentifiedObject], None, None]:
        for feed_type, rows in data:
            self.work_name = f"CSIS Cyber Data Feed - {feed_type}"
            yield from self._batches(feed_type, rows)

    def _batches(
        self, feed_type: str, rows: list[dict]
    ) -> Generator[list[BaseIdentifiedObject], None, None]:
        # Keyed by id: dedupes shared malware/intrusion sets within a bundle while
        # keeping every bundle self-contained (no refs to objects in other bundles).
        batch: dict[str, BaseIdentifiedObject] = {}
        processed = skipped = 0

        for raw_row in rows:
            try:
                row = CSISIndicatorRow.model_validate(
                    {**raw_row, "feed_type": feed_type}
                )
            except ValidationError as err:
                skipped += 1
                self.logger.warning(
                    "Skipping malformed CSIS row.",
                    {"feed_type": feed_type, "error": str(err)},
                )
                continue
            if row.confidence_score < self.min_confidence_score:
                continue

            batch.update((obj.id, obj) for obj in self.converter.from_row(row))
            processed += 1
            if len(batch) >= BATCH_SIZE:
                yield self.converter.bootstrap_objects + list(batch.values())
                batch = {}

        if batch:
            yield self.converter.bootstrap_objects + list(batch.values())

        self.logger.info(
            "CSIS feed processed.",
            {"feed_type": feed_type, "processed": processed, "skipped": skipped},
        )
