from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import ConfigValidationError
from connectors_sdk.models.enums import TLPLevel


def test_settings_defaults(config_dict) -> None:
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _: Any, handler: Any) -> dict[str, Any]:
            return handler(config_dict)

    settings = FakeConnectorSettings()

    assert settings.csis.client_id.get_secret_value() == "csis-client-id"
    assert settings.csis.feed_types == ["advanced"]
    assert settings.csis.tlp_level == TLPLevel.AMBER
    assert settings.csis.min_confidence_score == 0
    assert settings.csis.request_timeout_seconds == 60
    assert settings.connector.name == "CSIS Cyber Data Feed"
    assert settings.connector.duration_period.total_seconds() == 6 * 3600


def test_settings_parse_custom_values(make_settings, config_dict) -> None:
    config_dict["csis"] |= {
        "feed_types": "essential,advanced",
        "tlp_level": "TLP:GREEN",
        "min_confidence_score": 75,
    }
    settings = make_settings(config_dict)

    assert settings.csis.feed_types == ["essential", "advanced"]
    assert settings.csis.tlp_level == TLPLevel.GREEN
    assert settings.csis.min_confidence_score == 75


@pytest.mark.parametrize(
    "overrides",
    [
        {"feed_types": "essential,bogus"},
        {"feed_types": ""},
        {"tlp_level": "TLP:PURPLE"},
        {"min_confidence_score": 101},
    ],
)
def test_settings_reject_invalid_values(make_settings, config_dict, overrides) -> None:
    config_dict["csis"] |= overrides
    with pytest.raises(ConfigValidationError):
        make_settings(config_dict)


def test_settings_require_credentials(make_settings, config_dict) -> None:
    del config_dict["csis"]["client_secret"]
    with pytest.raises(ConfigValidationError):
        make_settings(config_dict)
