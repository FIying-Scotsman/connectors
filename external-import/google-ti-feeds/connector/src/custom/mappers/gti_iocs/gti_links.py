"""External reference to the GTI page of an IOC."""

# GTI IOC type -> (display label, GUI path segment)
GTI_GUI_PATHS = {
    "file": ("File", "file"),
    "domain": ("Domain", "domain"),
    "ip_address": ("IP", "ip-address"),
    "url": ("URL", "url"),
}


def gti_external_reference(
    ioc_type: str, ioc_id: str, name: str | None = None
) -> dict[str, str]:
    """Return the external reference to the GTI page of an IOC.

    Args:
        ioc_type: GTI IOC type: file, domain, ip_address or url.
        ioc_id: GTI identifier; for URLs, the URL identifier, not the URL.
        name: Value shown in the source name, defaults to the identifier.

    Returns:
        The external reference fields.

    """
    label, path = GTI_GUI_PATHS[ioc_type]
    return {
        "source_name": f"[GTI] {label} {name or ioc_id}",
        "description": f"Google Threat Intelligence {label} Link",
        "url": f"https://www.virustotal.com/gui/{path}/{ioc_id}",
    }
