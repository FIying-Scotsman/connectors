from unittest.mock import MagicMock

import connector.processor as processor_module
import pytest
from connector import Converter, FeedProcessor
from connectors_sdk.models import Malware, Relationship
from connectors_sdk.models.enums import TLPLevel
from csis_client import CSISClient


@pytest.fixture
def make_processor(fake_logger):
    def _make(feed_types: list[str], min_confidence_score: int = 0) -> FeedProcessor:
        processor = FeedProcessor(
            client=MagicMock(spec=CSISClient),
            converter=Converter(tlp_level=TLPLevel.AMBER),
            feed_types=feed_types,
            min_confidence_score=min_confidence_score,
        )
        processor.logger = fake_logger
        return processor

    return _make


def test_collect_fetches_every_feed(make_processor, raw_row) -> None:
    processor = make_processor(["essential", "advanced"])
    processor.client.fetch_feed.return_value = [raw_row]

    assert [feed for feed, _ in processor.collect()] == ["essential", "advanced"]


def test_collect_skips_failing_feed(make_processor, raw_row) -> None:
    processor = make_processor(["essential", "advanced"])
    processor.client.fetch_feed.side_effect = [RuntimeError("boom"), [raw_row]]

    assert [feed for feed, _ in processor.collect()] == ["advanced"]
    processor.logger.error.assert_called_once()


def test_transform_prefixes_bundle_with_author_and_marking(
    make_processor, raw_row
) -> None:
    processor = make_processor(["advanced"])

    (bundle,) = processor.transform(iter([("advanced", [raw_row])]))

    assert bundle[:2] == processor.converter.bootstrap_objects
    assert len(bundle) > 2
    assert processor.work_name == "CSIS Cyber Data Feed - advanced"


def test_transform_skips_malformed_rows(make_processor, raw_row) -> None:
    processor = make_processor(["advanced"])

    bundles = list(
        processor.transform(iter([("advanced", [{"kind": "domain"}, raw_row])]))
    )

    assert len(bundles) == 1
    processor.logger.warning.assert_called_once()


def test_transform_filters_low_confidence(make_processor, raw_row) -> None:
    processor = make_processor(["advanced"], min_confidence_score=95)

    assert list(processor.transform(iter([("advanced", [raw_row])]))) == []


def test_transform_dedupes_shared_threats_within_bundle(
    make_processor, raw_row
) -> None:
    processor = make_processor(["advanced"])
    rows = [raw_row | {"value": f"evil-{i}.example.com"} for i in range(3)]

    (bundle,) = processor.transform(iter([("advanced", rows)]))

    assert sum(isinstance(o, Malware) for o in bundle) == 1
    assert len({o.id for o in bundle}) == len(bundle)


def test_transform_batches_are_self_contained(
    make_processor, raw_row, monkeypatch
) -> None:
    monkeypatch.setattr(processor_module, "BATCH_SIZE", 2)
    processor = make_processor(["advanced"])
    rows = [raw_row | {"value": f"evil-{i}.example.com"} for i in range(3)]

    bundles = list(processor.transform(iter([("advanced", rows)])))

    assert len(bundles) == 3
    for bundle in bundles:
        ids = {o.id for o in bundle}
        for rel in (o for o in bundle if isinstance(o, Relationship)):
            assert rel.source.id in ids and rel.target.id in ids
