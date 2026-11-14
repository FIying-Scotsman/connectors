"""Tests for the GTI configuration shared by several collections."""

from os import environ as os_environ
from unittest.mock import patch

import pytest
from connector.src.custom.configs.gti_config import GTIConfig
from connector.src.custom.configs.shared.gti_config_shared import GTISharedConfig
from pydantic import ValidationError


def _load_config(env: dict[str, str]) -> GTISharedConfig:
    with patch.dict(os_environ, {"GTI_API_KEY": "fake-key", **env}):
        return GTISharedConfig()


def test_indicator_scoring_defaults_to_threat_score() -> None:
    """The default keeps the scoring used before the setting existed."""
    # Given a configuration without indicator_scoring
    # When it is loaded
    config = _load_config({})
    # Then the threat_score strategy is used
    assert config.indicator_scoring == "threat_score"  # noqa: S101


@pytest.mark.parametrize(
    "strategy", ["threat_score", "gti_derived", "average_detection"]
)
def test_indicator_scoring_accepts_known_strategies(strategy: str) -> None:
    """Each documented strategy is accepted."""
    # Given a supported strategy
    # When the configuration is loaded
    config = _load_config({"GTI_INDICATOR_SCORING": strategy})
    # Then it is kept as is
    assert config.indicator_scoring == strategy  # noqa: S101


def test_indicator_scoring_rejects_unknown_strategy() -> None:
    """An unknown strategy fails validation."""
    # Given an unsupported strategy
    # When the configuration is loaded
    # Then validation fails
    with pytest.raises(ValidationError):
        _load_config({"GTI_INDICATOR_SCORING": "random"})


def test_gti_config_exposes_shared_settings() -> None:
    """The unified GTI configuration includes the shared settings."""
    # Given the unified configuration
    # When its fields are listed
    # Then the shared settings are present
    assert "indicator_scoring" in GTIConfig.model_fields  # noqa: S101
