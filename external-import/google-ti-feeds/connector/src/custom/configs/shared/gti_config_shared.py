"""GTI configuration shared by several data collections.

IOC settings apply to the IOCs (files, domains, URLs, IP addresses) of every
data collection, including the Steady-State IOC Deltas feed.
"""

from typing import Literal

from connector.src.custom.configs.gti_config_common import GTIBaseConfig
from pydantic import Field

IndicatorScoring = Literal["threat_score", "gti_derived", "average_detection"]


class GTISharedConfig(GTIBaseConfig):
    """Configuration shared by several data collections."""

    indicator_scoring: IndicatorScoring = Field(
        default="threat_score",
        description="Strategy used to compute the score of IOC indicators and "
        "observables. 'threat_score': GTI threat score, then GTI confidence "
        "score, then Mandiant confidence score (deprecated by GTI). "
        "'gti_derived': computed from the GTI verdict and severity. "
        "'average_detection': computed from the share of AV engines flagging the "
        "IOC (last_analysis_stats). When the selected strategy has no data for an "
        "IOC, 'threat_score' is used.",
    )
