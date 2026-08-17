"""Shared data models used across all reconnaissance modules.

The :class:`Subdomain` dataclass is the single source of truth for every
asset discovered during a scan: each enrichment phase (DNS resolution,
HTTP probing, port scanning, fingerprinting) only ever writes into these
fields, which keeps the modules decoupled and the final report consistent.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Subdomain:
    """A discovered subdomain and everything we learned about it.

    Attributes:
        name: Fully qualified hostname, e.g. ``api.example.com``.
        source: How it was found, e.g. ``crt.sh``, ``bruteforce`` or both.
        resolved_ips: IPv4 addresses the name resolved to (empty if none).
        alive: Whether an HTTP(S) response or an open TCP port proved life.
        http_status: Status code of the final HTTP(S) response, if any.
        page_title: Parsed ``<title>`` of the probed page, if any.
        final_url: Effective URL after redirects, if any.
        server_header: Value of the ``Server`` response header, if any.
        response_headers: Normalized (lower-cased) response headers.
        body_sample: Truncated HTML body used for fingerprinting.
        open_ports: TCP ports that accepted a connection.
        port_banners: ``{port: banner}`` for services that sent a banner.
        technologies: Detected technologies/frameworks (sorted, unique).
    """

    name: str
    source: str
    resolved_ips: List[str] = field(default_factory=list)
    alive: bool = False
    http_status: Optional[int] = None
    page_title: Optional[str] = None
    final_url: Optional[str] = None
    server_header: Optional[str] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    body_sample: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    port_banners: Dict[int, str] = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize this subdomain into a JSON-friendly dictionary."""
        return asdict(self)

    def add_source(self, source: str) -> None:
        """Merge another discovery source into ``source``, deduplicated."""
        sources = [s.strip() for s in self.source.split(",")]
        if source not in sources:
            self.source = ", ".join(sources + [source])


@dataclass
class ReconReport:
    """Top-level report container written by the JSON/HTML reporters."""

    domain: str
    scan_started_at: str
    scan_duration_seconds: float
    subdomains: List[Subdomain]
    tool: Dict[str, str] = field(default_factory=dict)
    stats: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the full report into a JSON-friendly dictionary."""
        return {
            "domain": self.domain,
            "scan_started_at": self.scan_started_at,
            "scan_duration_seconds": round(self.scan_duration_seconds, 3),
            "tool": self.tool,
            "stats": self.stats,
            "subdomains": [s.to_dict() for s in self.subdomains],
        }
