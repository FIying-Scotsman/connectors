"""Converts a GTI IP to a STIX IP object and indicator."""

import ipaddress
from datetime import datetime, timezone

from connector.src.custom.mappers.gti_iocs.base_ioc_mapper import BaseIOCMapper
from connector.src.custom.models.gti.gti_ip_addresses_model import (
    GTIIPData,
)
from connector.src.stix.octi.models.ipv4_address_model import OctiIPv4AddressModel
from connector.src.stix.octi.models.ipv6_address_model import OctiIPv6AddressModel
from connector.src.stix.octi.observable_type_ov_enum import ObservableTypeOV
from connector.src.stix.v21.models.scos.ipv4_address_model import IPv4AddressModel
from connector.src.stix.v21.models.scos.ipv6_address_model import IPv6AddressModel
from stix2 import IPv4Address, IPv6Address  # type: ignore[import-untyped]


class GTIIPToSTIXIP(BaseIOCMapper[GTIIPData]):
    """Converts a GTI IP to a STIX IP object and indicator."""

    ioc_type = "ip_address"

    @property
    def ip(self) -> GTIIPData:
        """The GTI ip address being converted."""
        return self.ioc

    def _detect_ip_version(self) -> str:
        """Detect if IP is IPv4 or IPv6.

        Returns:
            str: "ipv4" or "ipv6"

        Raises:
            ValueError: If IP format is invalid

        """
        try:
            ip_obj = ipaddress.ip_address(self.ip.id)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                return "ipv4"
            elif isinstance(ip_obj, ipaddress.IPv6Address):
                return "ipv6"
            else:
                raise ValueError(f"Unknown IP address type: {type(ip_obj)}")
        except ValueError as e:
            raise ValueError(f"Invalid IP address format '{self.ip.id}': {e}") from e

    def _create_stix_observable(self) -> IPv4Address | IPv6Address:
        """Create the STIX IP observable object (IPv4 or IPv6).

        Returns:
         IPv4Address | IPv6Address: The STIX IP observable model object.

        """
        score = self._get_score()

        ip_version = self._detect_ip_version()

        timestamps = self._get_timestamps()

        ip_model: IPv4AddressModel | IPv6AddressModel
        if ip_version == "ipv4":
            ip_model = OctiIPv4AddressModel.create(
                value=self.ip.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                score=score,
                custom_properties=self._observable_custom_properties(),
                created=timestamps["created"],
                modified=timestamps["modified"],
            )
        else:
            ip_model = OctiIPv6AddressModel.create(
                value=self.ip.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                score=score,
                custom_properties=self._observable_custom_properties(),
                created=timestamps["created"],
                modified=timestamps["modified"],
            )

        return ip_model.to_stix2_object()

    def _get_timestamps(self) -> dict[str, datetime]:
        """Extract creation and modification timestamps from IP attributes.

        Returns:
            dict[str, datetime]: dictionary with 'created' and 'modified' timestamps

        """
        created = datetime.now(timezone.utc)
        modified = datetime.now(timezone.utc)

        if self.ip.attributes:
            if self.ip.attributes.last_analysis_date:
                created = datetime.fromtimestamp(
                    self.ip.attributes.last_analysis_date, tz=timezone.utc
                )
            if self.ip.attributes.last_modification_date:
                modified = datetime.fromtimestamp(
                    self.ip.attributes.last_modification_date, tz=timezone.utc
                )

        return {"created": created, "modified": modified}

    def _build_stix_pattern(self) -> str:
        """Build STIX pattern for the IP indicator.

        Returns:
            str: STIX pattern string

        """
        ip_version = self._detect_ip_version()

        if ip_version == "ipv4":
            return f"[ipv4-addr:value = '{self.ip.id}']"
        else:
            return f"[ipv6-addr:value = '{self.ip.id}']"

    def _observable_type(self) -> ObservableTypeOV:
        """Return the main observable type of the indicator."""
        if self._detect_ip_version() == "ipv4":
            return ObservableTypeOV.IPV4_ADDR
        return ObservableTypeOV.IPV6_ADDR
