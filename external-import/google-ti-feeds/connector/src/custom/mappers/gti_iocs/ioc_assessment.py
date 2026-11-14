"""Markdown summary of a GTI assessment, for IOC descriptions."""

from typing import Any

from connector.src.custom.mappers.description_details import (
    bullet_section,
    details_section,
    join_sections,
)

# Boolean contributing factors, in display order. Fields missing on an IOC type are skipped.
CONTRIBUTING_FACTOR_LABELS = {
    "mandiant_analyst_malicious": "Determined malicious by a Mandiant analyst",
    "mandiant_analyst_benign": "Determined benign by a Mandiant analyst",
    "mandiant_association_actor": "Associated with a tracked threat actor",
    "mandiant_association_malware": "Associated with a tracked malware family",
    "mandiant_association_report": "Referenced in a GTI intelligence report",
    "associated_actor": "Associated with a community threat actor",
    "associated_malware_configuration": "Contains a known malware configuration",
    "malicious_sandbox_verdict": "Detected as malicious by sandbox analysis",
    "matched_malicious_yara": "Matches malicious YARA rules",
    "mandiant_domain_hijack": "Domain hijacked",
    "high_severity_related_files": "Related to high severity malicious files",
    "medium_severity_related_files": "Related to medium severity malicious files",
    "low_severity_related_files": "Related to low severity malicious files",
    "mandiant_osint": "Widespread in OSINT sources",
    "pervasive_indicator": "Pervasive indicator",
    "associated_reference": "Referenced in public sources",
    "legitimate_software": "Associated with legitimate software",
}


# Valued contributing factors, shown as "label: value".
CONTRIBUTING_FACTOR_VALUES = {
    "gti_confidence_score": "GTI confidence score",
    "mandiant_confidence_score": "Mandiant confidence score",
    "gavs_detections": "Google threat filtering detections",
    "safebrowsing_verdict": "Google Safe Browsing verdict",
}


def _humanize(value: str | None, prefix: str) -> str | None:
    """Turn 'VERDICT_MALICIOUS' into 'Malicious'."""
    if not value:
        return None
    return value.removeprefix(prefix).replace("_", " ").capitalize()


def _contributing_factors(factors: Any) -> list[str]:
    if factors is None:
        return []
    lines = [
        label
        for field, label in CONTRIBUTING_FACTOR_LABELS.items()
        if getattr(factors, field, None) is True
    ]
    for field, label in CONTRIBUTING_FACTOR_VALUES.items():
        value = getattr(factors, field, None)
        if value:
            lines.append(f"{label}: {value}")
    return lines


def build_assessment_description(gti_assessment: Any) -> str | None:
    """Build a Markdown summary of the verdict, severity, score and their reasons.

    Args:
        gti_assessment: GTI assessment of a collection IOC or an IOC delta entry.

    Returns:
        The description, or None when the assessment holds nothing to show.

    """
    if gti_assessment is None:
        return None

    verdict = getattr(gti_assessment, "verdict", None)
    severity = getattr(gti_assessment, "severity", None)
    threat_score = getattr(gti_assessment, "threat_score", None)
    return join_sections(
        details_section(
            "GTI assessment",
            {
                "Verdict": _humanize(getattr(verdict, "value", None), "VERDICT_"),
                "Severity": _humanize(getattr(severity, "value", None), "SEVERITY_"),
                "Threat score": getattr(threat_score, "value", None),
            },
        ),
        getattr(gti_assessment, "description", None),
        bullet_section(
            "Contributing factors",
            _contributing_factors(
                getattr(gti_assessment, "contributing_factors", None)
            ),
        ),
    )


def observable_description_properties(description: str | None) -> dict[str, Any]:
    """Return the custom properties carrying an observable description."""
    return {"x_opencti_description": description} if description else {}
