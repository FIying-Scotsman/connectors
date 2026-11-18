"""Connector entry point."""

import traceback

from connector import ConnectorSettings, Converter, FeedProcessor
from connectors_sdk import ExternalImportConnector as CSISConnector
from csis_client import CSISClient

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        processor = FeedProcessor(
            client=CSISClient(
                client_id=settings.csis.client_id.get_secret_value(),
                client_secret=settings.csis.client_secret.get_secret_value(),
                request_timeout_seconds=settings.csis.request_timeout_seconds,
            ),
            converter=Converter(tlp_level=settings.csis.tlp_level),
            feed_types=settings.csis.feed_types,
            min_confidence_score=settings.csis.min_confidence_score,
        )
        connector = CSISConnector(settings=settings, data_processors=[processor])
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
