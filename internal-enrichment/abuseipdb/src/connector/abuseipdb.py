from collections import Counter, defaultdict
from typing import Dict

import requests
import stix2
from dateutil.parser import parse
from pycti import (
    STIX_EXT_OCTI_SCO,
    Location,
    OpenCTIConnectorHelper,
    OpenCTIStix2,
    StixSightingRelationship,
)
from src.connector.models import ConfigLoader


class ConnectorAbuseIPDB:
    def __init__(self, config: ConfigLoader, helper: OpenCTIConnectorHelper):
        # Instantiate the connector helper from config
        self.config = config
        self.helper = helper
        self.whitelist_label = self.helper.api.label.read_or_create_unchecked(
            value="whitelist", color="#4caf50"
        )
        if self.whitelist_label is None:
            raise ValueError(
                "The whitelist label could not be created. If your connector does not have the permission to create labels, please create it manually before launching"
            )

    @staticmethod
    def extract_abuse_ipdb_category(category_number):
        # Reference: https://www.abuseipdb.com/categories
        mapping = {
            "3": "Fraud Orders",
            "4": "DDOS Attack",
            "5": "FTP Brute-Force",
            "6": "Ping of Death",
            "7": "Phishing",
            "8": "Fraud VOIP",
            "9": "Open Proxy",
            "10": "Web Spam",
            "11": "Email Spam",
            "12": "Blog Spam",
            "13": "VPN IP",
            "14": "Port Scan",
            "15": "Hacking",
            "16": "SQL Injection",
            "17": "Spoofing",
            "18": "Brute Force",
            "19": "Bad Web Bot",
            "20": "Exploited Host",
            "21": "Web App Attack",
            "22": "SSH",
            "23": "IoT Targeted",
        }
        return mapping.get(str(category_number), "unknown category")

    def generate_markdown(self, data: Dict) -> str:
        yes_no = lambda value: "✅ Yes" if value else "❌ No"  # noqa: E731
        hostnames = data.get("hostnames") or []

        markdown = "### 🌐 IP Address Info\n"
        markdown += f"- IP Address: {data.get('ipAddress', 'N/A')}\n"
        markdown += f"- Public: {yes_no(data.get('isPublic'))}\n"
        markdown += f"- IP Version: IPv{data.get('ipVersion', '?')}\n"
        markdown += f"- Whitelisted: {yes_no(data.get('isWhitelisted'))}\n"
        markdown += (
            f"- Abuse Confidence Score: {data.get('abuseConfidenceScore', 'N/A')}\n\n"
        )

        markdown += "### 🗺️ Location & Network\n"
        markdown += (
            f"- Country: {data.get('countryName', 'Unknown')} "
            f"({data.get('countryCode', '--')})\n"
        )
        markdown += f"- Usage Type: {data.get('usageType', 'N/A')}\n"
        markdown += f"- ISP: {data.get('isp', 'N/A')}\n"
        markdown += f"- Domain: {data.get('domain', 'N/A')}\n"
        markdown += (
            f"- Hostnames: {', '.join(hostnames) if hostnames else '*(none listed)*'}\n"
        )
        markdown += f"- Tor Exit Node: {yes_no(data.get('isTor'))}\n\n"

        markdown += "### 🧾 Abuse Summary\n"
        reports = data.get("reports") or []
        if reports:
            category_counter: Counter = Counter()
            country_counter: Counter = Counter()
            first_seen = last_seen = None
            for report in reports:
                for cat in report.get("categories", []):
                    category_counter[self.extract_abuse_ipdb_category(cat)] += 1
                country = report.get("reporterCountryCode")
                if country:
                    country_counter[country] += 1
                reported_at = report.get("reportedAt")
                if reported_at:
                    reported_dt = parse(reported_at)
                    if not first_seen or reported_dt < first_seen:
                        first_seen = reported_dt
                    if not last_seen or reported_dt > last_seen:
                        last_seen = reported_dt

            categories = ", ".join(
                f"{k} ({v})" for k, v in category_counter.most_common()
            )
            countries = ", ".join(
                f"{k} ({v})" for k, v in country_counter.most_common()
            )
            markdown += f"- Total Reports: {data.get('totalReports', 0)}\n"
            markdown += (
                f"- Distinct Users Reporting: {data.get('numDistinctUsers', 0)}\n"
            )
            markdown += f"- Most Common Categories: {categories or 'None'}\n"
            markdown += f"- Reporter Countries: {countries or 'None'}\n"
            markdown += (
                f"- First Reported: {first_seen.date() if first_seen else 'N/A'}\n"
            )
            markdown += (
                f"- Last Reported: {last_seen.date() if last_seen else 'N/A'}\n\n"
            )
        else:
            markdown += "- ⚠️ No reports found\n\n"

        markdown += (
            "View on AbuseIPDB: "
            f"https://www.abuseipdb.com/check/{data.get('ipAddress', '')}"
        )
        return markdown

    def _process_message(self, data: Dict) -> str:
        opencti_entity = data["enrichment_entity"]

        # Extract TLP
        tlp = "TLP:CLEAR"
        for marking_definition in opencti_entity.get("objectMarking", []):
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.config.abuseipdb.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )

        stix_objects = data["stix_objects"]
        stix_entity = data["stix_entity"]
        # Extract IP from entity data
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "Key": "%s" % self.config.abuseipdb.api_key.get_secret_value(),
        }
        params = {
            "maxAgeInDays": 365,
            "verbose": "True",
            "ipAddress": stix_entity["value"],
        }
        r = requests.get(url, headers=headers, params=params)
        r.raise_for_status()
        data = r.json()
        data = data["data"]

        content = self.generate_markdown(data)

        identity = self.helper.api.identity.create(
            type="Organization",
            name="AbuseIPDB",
            description="AbuseIPDB threat intelligence feed",
            x_opencti_reliability="B - Usually reliable",
        )

        if content:
            note_id = self.helper.api.note.create(
                abstract=f"AbuseIPDB enrichment for {stix_entity['value']}",
                content=content,
                createdBy=identity["id"],
                objects=[opencti_entity["id"]],
                note_types=["analysis"],
            )
            self.helper.connector_logger.debug(
                f"[AbuseIPDB] Note created with ID: {note_id} and linked to observable."
            )
        else:
            self.helper.connector_logger.debug(
                f"[AbuseIPDB] No data returned for {stix_entity['value']}"
            )

        if data["isWhitelisted"]:
            OpenCTIStix2.put_attribute_in_extension(
                stix_entity, STIX_EXT_OCTI_SCO, "score", data["abuseConfidenceScore"]
            )
            # External references
            OpenCTIStix2.put_attribute_in_extension(
                stix_entity,
                STIX_EXT_OCTI_SCO,
                "external_references",
                {
                    "source_name": "AbuseIPDB (whitelist)",
                    "url": "https://www.abuseipdb.com/check/"
                    + opencti_entity["observable_value"],
                    "description": "This IP address is from within our whitelist.",
                },
                True,
            )
            OpenCTIStix2.put_attribute_in_extension(
                stix_entity,
                STIX_EXT_OCTI_SCO,
                "labels",
                self.whitelist_label["value"],
                True,
            )
        elif len(data["reports"]) > 0:
            OpenCTIStix2.put_attribute_in_extension(
                stix_entity, STIX_EXT_OCTI_SCO, "score", data["abuseConfidenceScore"]
            )
            found = []
            cl = defaultdict(dict)
            for report in data["reports"]:
                countryN = report.get("reporterCountryCode")
                if countryN in cl:
                    cl[countryN]["count"] += 1
                    cl[countryN]["firstseen"] = report["reportedAt"]
                else:
                    cl[countryN]["count"] = 1
                    cl[countryN]["firstseen"] = report["reportedAt"]
                    cl[countryN]["lastseen"] = report["reportedAt"]

                for category in report["categories"]:
                    if category not in found:
                        found.append(category)
                        category_text = self.extract_abuse_ipdb_category(category)
                        OpenCTIStix2.put_attribute_in_extension(
                            stix_entity,
                            STIX_EXT_OCTI_SCO,
                            "labels",
                            category_text,
                            True,
                        )

            for ckey in list(cl.keys()):
                if ckey is None:
                    continue
                country_location = stix2.Location(
                    id=Location.generate_id(ckey, "Country"),
                    name=ckey,
                    country=ckey,
                    custom_properties={
                        "x_opencti_location_type": "Country",
                        "x_opencti_aliases": [ckey],
                    },
                )
                stix_objects.append(country_location)
                sighting = stix2.Sighting(
                    id=StixSightingRelationship.generate_id(
                        stix_entity["id"],
                        country_location.id,
                        parse(cl[ckey]["firstseen"]),
                        parse(cl[ckey]["lastseen"]),
                    ),
                    where_sighted_refs=[country_location.id],
                    count=cl[ckey]["count"],
                    first_seen=parse(cl[ckey]["firstseen"]),
                    last_seen=parse(cl[ckey]["lastseen"]),
                    # As SDO are not supported in official STIX, we use a fake ID in ref
                    # Worker will use custom_properties instead
                    sighting_of_ref="indicator--c1034564-a9fb-429b-a1c1-c80116cc8e1e",  # Fake
                    custom_properties={"x_opencti_sighting_of_ref": stix_entity["id"]},
                )
                stix_objects.append(sighting)
        serialized_bundle = self.helper.stix2_create_bundle(stix_objects)
        self.helper.send_stix2_bundle(serialized_bundle)
        return "IP found in AbuseIPDB, knowledge attached."

    # Start the main loop
    def run(self):
        self.helper.listen(message_callback=self._process_message)
