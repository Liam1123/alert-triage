"""Validation for indicators before they are sent to any API.

Each check returns an EnrichmentResult when the lookup should NOT happen
(invalid input, or an address/domain that no threat intel source will know
about), or None when it is fine to go ahead.
"""

import ipaddress
import re

from enrichers.common import error_result, skipped_result
from models import EnrichmentResult

# Ranges reserved for documentation and examples (RFC 5737, RFC 3849).
DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
]

# TLDs that can never resolve on the public internet (RFC 2606, RFC 6761,
# RFC 6762 for .local, and ICANN's 2024 reservation of .internal).
RESERVED_TLDS = {"example", "test", "invalid", "localhost", "local", "internal"}

# Second-level domains reserved for documentation (RFC 2606).
RESERVED_DOMAINS = {"example.com", "example.net", "example.org"}

# One label: 1-63 letters, digits, or hyphens, not starting or ending with a hyphen.
_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
# A TLD is letters only, or an internationalized "xn--" TLD.
_TLD = r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})"
DOMAIN_PATTERN = re.compile(rf"^(?:{_LABEL}\.)+{_TLD}$")


def check_ip(source: str, ip: str) -> EnrichmentResult | None:
    """Return an error/skip result for an invalid or non-routable IP, else None."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return error_result(source, ip, "ip", "Not a valid IP address")

    reason = non_routable_reason(address)
    if reason:
        return skipped_result(source, ip, "ip", f"non-routable address ({reason})")
    return None


def non_routable_reason(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Explain why an address is not on the public internet, or None if it is."""
    # Treat an IPv4 address written as IPv6 (::ffff:10.0.0.1) as plain IPv4.
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped

    # Order matters: Python also counts most of these ranges as "private",
    # so check the more specific labels first.
    if any(address in network for network in DOCUMENTATION_NETWORKS):
        return "documentation range"
    if address.is_unspecified:
        return "unspecified address"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link-local"
    if address.is_multicast:
        return "multicast"
    if address.is_reserved:
        return "reserved range"
    if address.is_private:
        return "private range"
    if not address.is_global:
        return "not globally routable"
    return None


def normalize_domain(domain: str) -> str:
    """Lowercase and drop surrounding whitespace and a trailing dot."""
    return domain.strip().lower().rstrip(".")


def check_domain(source: str, domain: str) -> EnrichmentResult | None:
    """Return an error/skip result for an invalid or reserved domain, else None."""
    if len(domain) > 253 or not DOMAIN_PATTERN.match(domain):
        return error_result(source, domain, "domain", "Not a valid domain name")

    tld = domain.rsplit(".", 1)[-1]
    if tld in RESERVED_TLDS:
        return skipped_result(source, domain, "domain", f"reserved TLD (.{tld})")

    for reserved in RESERVED_DOMAINS:
        if domain == reserved or domain.endswith("." + reserved):
            return skipped_result(source, domain, "domain", f"reserved domain ({reserved})")
    return None
