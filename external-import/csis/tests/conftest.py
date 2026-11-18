"""Shared pytest fixtures."""

import os
import sys
from typing import Any
from unittest.mock import MagicMock

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from connector import ConnectorSettings  # noqa: E402


@pytest.fixture
def config_dict() -> dict[str, Any]:
    return {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {"id": "test-id"},
        "csis": {"client_id": "csis-client-id", "client_secret": "csis-secret"},
    }


@pytest.fixture
def make_settings():
    def _make(config: dict[str, Any]) -> ConnectorSettings:
        class FakeConnectorSettings(ConnectorSettings):
            @classmethod
            def _load_config_dict(cls, _: Any, handler: Any) -> dict[str, Any]:
                return handler(config)

        return FakeConnectorSettings()

    return _make


@pytest.fixture
def raw_row() -> dict[str, Any]:
    return {
        "kind": "domain",
        "value": "evil.example.com",
        "first_seen": "2026-07-25T17:25:01+00:00",
        "confidence_score": 90,
        "malware": '["clearfake"]',
        "category": '["Command and control"]',
        "threat_actors": '["APT33"]',
    }


@pytest.fixture
def fake_logger() -> MagicMock:
    return MagicMock()
