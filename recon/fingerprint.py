"""Module 3: Technology fingerprinting and banner grabbing.

Two passive analysis techniques are implemented here:

* **HTTP fingerprinting** -- the response headers and the truncated body
  captured by :class:`recon.live_check.LiveHostChecker` are matched against
  curated, strict regex rules to identify web servers, frameworks, CMSs,
  front-end libraries and third-party services.
* **Banner grabbing** -- for open non-HTTP TCP ports, the service banner
  is read (and if needed prompted) to identify the daemon and its version.

Fingerprinting is deliberately conservative: rules require unambiguous
markers (e.g. ``__NEXT_DATA__``, ``ng-version=``) to keep false positives
low.
"""

from __future__ import annotations

import concurrent.futures
import logging
import re
import socket
from typing import Callable, Dict, List, Optional, Pattern, Tuple

from .models import Subdomain

logger = logging.getLogger(__name__)

# HTTP(S) ports are excluded from banner grabbing: their banners carry no
# extra information beyond what the HTTP probe already collected.
HTTP_PORTS = {80, 443, 8000, 8008, 8080, 8081, 8443, 8888}

# Probes sent when a service does not greet us immediately.
PROTOCOL_PROBES: Dict[int, bytes] = {
    25: b"EHLO subdomain-recon-tool\r\n",
    110: b"",
    143: b"",
    3306: b"",
    5432: b"",
    6379: b"PING\r\n",
}

# header name -> list of (regex, technology)
HEADER_RULES: Dict[str, List[Tuple[Pattern[str], str]]] = {
    "server": [
        (re.compile(r"nginx", re.I), "Nginx"),
        (re.compile(r"apache", re.I), "Apache"),
        (re.compile(r"microsoft-iis", re.I), "Microsoft IIS"),
        (re.compile(r"openresty", re.I), "OpenResty"),
        (re.compile(r"caddy", re.I), "Caddy"),
        (re.compile(r"cloudflare", re.I), "Cloudflare"),
        (re.compile(r"cloudfront", re.I), "Amazon CloudFront"),
        (re.compile(r"gse", re.I), "Google Frontend"),
        (re.compile(r"lighttpd", re.I), "Lighttpd"),
        (re.compile(r"envoy", re.I), "Envoy"),
        (re.compile(r"traefik", re.I), "Traefik"),
    ],
    "x-powered-by": [
        (re.compile(r"php", re.I), "PHP"),
        (re.compile(r"asp\.net", re.I), "ASP.NET"),
        (re.compile(r"express", re.I), "Express"),
        (re.compile(r"next\.js|nextjs", re.I), "Next.js"),
        (re.compile(r"nginx", re.I), "Nginx"),
        (re.compile(r"plesklin", re.I), "Plesk"),
        (re.compile(r"rocket", re.I), "Rocket"),
    ],
    "x-aspnet-version": [(re.compile(r".*"), "ASP.NET")],
    "x-generator": [(re.compile(r".*"), "Static Site Generator")],
    "x-drupal-cache": [(re.compile(r".*"), "Drupal")],
    "x-joomla": [(re.compile(r".*"), "Joomla")],
    "x-sucuri-id": [(re.compile(r".*"), "Sucuri WAF")],
    "x-cache": [(re.compile(r"varnish", re.I), "Varnish Cache")],
    "x-varnish": [(re.compile(r".*"), "Varnish Cache")],
    "cf-ray": [(re.compile(r".*"), "Cloudflare")],
    "cf-cache-status": [(re.compile(r".*"), "Cloudflare")],
    "x-vercel-id": [(re.compile(r".*"), "Vercel")],
    "x-amz-cf-id": [(re.compile(r".*"), "Amazon CloudFront")],
    "x-amz-server-side-encryption": [(re.compile(r".*"), "AWS S3")],
    "x-runtime": [(re.compile(r".*"), "Ruby on Rails")],
    "x-github-request-id": [(re.compile(r".*"), "GitHub Pages")],
    "x-litespeed-cache": [(re.compile(r".*"), "LiteSpeed")],
    "x-openresty": [(re.compile(r".*"), "OpenResty")],
    "x-shopify-stage": [(re.compile(r".*"), "Shopify")],
    "x-builder": [(re.compile(r".*"), "Webflow")],
}

# (regex, technology) pairs matched against the captured HTML body.
# Rules use strict markers (framework identifiers, unique attributes)
# instead of fuzzy heuristics to keep false positives low.
BODY_RULES: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"<html[^>]*ng-version=|data-ng-app|ng-app=", re.I), "Angular"),
    (re.compile(r"__VUE__|data-v-[a-f0-9]{6,}", re.I), "Vue.js"),
    (re.compile(r"data-reactroot|__NEXT_DATA__|_next/static", re.I), "React"),
    (re.compile(r"data-svelte-", re.I), "Svelte"),
    (re.compile(r"/wp-content/|wp-includes|wp-json|wp-admin", re.I), "WordPress"),
    (re.compile(r"jquery[.-](?:[0-9.]+)?", re.I), "jQuery"),
    (re.compile(r"bootstrap[.-][0-9.]+|bootstrapcdn", re.I), "Bootstrap"),
    (re.compile(r"tailwindcss|(?:^|[\"'])tw-[a-z]", re.I), "Tailwind CSS"),
    (re.compile(r"csrf-token|laravel_session|livewire", re.I), "Laravel"),
    (re.compile(r"csrfmiddlewaretoken|django\.js", re.I), "Django"),
    (re.compile(r"csrf-param|data-remote=[\"']true", re.I), "Ruby on Rails"),
    (re.compile(r"google-analytics\.com/analytics\.js|gtag\(", re.I), "Google Analytics"),
    (re.compile(r"googletagmanager\.com/gtm\.js", re.I), "Google Tag Manager"),
    (re.compile(r"cdn\.shopify\.com|myshopify\.com|shopify\.js", re.I), "Shopify"),
    (re.compile(r"wixstatic\.com|wix\.com", re.I), "Wix"),
    (re.compile(r"drupal\.settings|sites/default/files", re.I), "Drupal"),
    (re.compile(r"com_content|joomla\.js", re.I), "Joomla"),
    (re.compile(r"ghost\.io|ghost-url", re.I), "Ghost"),
    (re.compile(r"webpack|__webpack_require__", re.I), "Webpack"),
    (re.compile(r"/@vite/|data-vite", re.I), "Vite"),
    (re.compile(r"font-awesome|fontawesome", re.I), "Font Awesome"),
    (re.compile(r"material-icons|mdl-js", re.I), "Material Design"),
    (re.compile(r"socket\.io\.js|io\.connect\(", re.I), "Socket.IO"),
    (re.compile(r"js\.stripe\.com|stripe\.js", re.I), "Stripe"),
    (re.compile(r"paypalobjects\.com", re.I), "PayPal"),
    (re.compile(r"www\.google\.com/recaptcha|grecaptcha", re.I), "reCAPTCHA"),
    (re.compile(r"hcaptcha\.com", re.I), "hCaptcha"),
    (re.compile(r"sentry\.io|raven\.js", re.I), "Sentry"),
    (re.compile(r"hotjar\.com", re.I), "Hotjar"),
    (re.compile(r"zendesk\.com|zopim", re.I), "Zendesk"),
    (re.compile(r"intercom\.io|intercomSettings", re.I), "Intercom"),
    (re.compile(r"crisp\.chat|launcher-config", re.I), "Crisp Chat"),
    (re.compile(r"cdn\.cookielaw\.org|onetrust", re.I), "OneTrust"),
    (re.compile(r"hubspot", re.I), "HubSpot"),
    (re.compile(r"segment\.com|analytics\.js", re.I), "Segment"),
    (re.compile(r"mailchimp|list-manage\.com", re.I), "Mailchimp"),
    (re.compile(r"marketo", re.I), "Marketo"),
    (re.compile(r"salesforce|sfdc", re.I), "Salesforce"),
    (re.compile(r"openapi|swagger-ui", re.I), "Swagger/OpenAPI"),
    (re.compile(r"<meta name=\"generator\" content=\"([^\"]+)\"", re.I), "Meta Generator"),
]


class TechnologyFingerprinter:
    """Identifies technologies from captured headers and body samples."""

    def fingerprint(self, subdomain: Subdomain) -> List[str]:
        """Analyze a subdomain and return its sorted technology list.

        Args:
            subdomain: The host to analyze (uses ``response_headers`` and
                ``body_sample``; both may be empty for non-HTTP hosts).

        Returns:
            Sorted, de-duplicated list of detected technologies.
        """
        technologies: set = set()

        for header_name, rules in HEADER_RULES.items():
            value = subdomain.response_headers.get(header_name, "")
            if not value:
                continue
            for pattern, tech in rules:
                if pattern.search(value):
                    technologies.add(tech)

        body = subdomain.body_sample or ""
        for pattern, tech in BODY_RULES:
            if pattern.search(body):
                technologies.add(tech)

        return sorted(technologies)


class BannerGrabber:
    """Reads service banners from open non-HTTP TCP ports.

    Many daemons (SSH, FTP, MySQL, ...) greet clients immediately after
    connection; others only respond after a protocol probe. This class
    handles both cases, then sanitizes the raw bytes into a printable,
    length-capped banner string.
    """

    def __init__(
        self,
        timeout: float = 2.0,
        max_workers: int = 50,
        progress_cb: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        """Initialize the grabber.

        Args:
            timeout: Socket timeout for connect/recv in seconds.
            max_workers: ThreadPoolExecutor size for concurrent grabs.
            progress_cb: Optional ``(done, total)`` progress callback.
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.progress_cb = progress_cb

    @staticmethod
    def _sanitize(raw: bytes, limit: int = 160) -> str:
        """Convert raw banner bytes into a clean, truncated string."""
        text = raw.decode("utf-8", errors="replace")
        text = "".join(ch for ch in text if ch.isprintable() or ch in "\t")
        return " ".join(text.split())[:limit]

    def _grab_one(self, host: str, port: int) -> Optional[str]:
        """Grab the banner from a single host/port.

        Returns:
            Sanitized banner string, or ``None`` when the service sent
            nothing usable.
        """
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                banner = sock.recv(256)
                if not banner and port in PROTOCOL_PROBES:
                    probe = PROTOCOL_PROBES[port]
                    if probe:
                        sock.sendall(probe)
                        banner = sock.recv(256)
        except OSError as exc:
            logger.debug("banner grab failed on %s:%s: %s", host, port, exc)
            return None

        if not banner:
            return None
        return self._sanitize(banner)

    def grab(self, host: str, ports: List[int]) -> Dict[int, str]:
        """Grab banners for multiple ports of one host concurrently.

        Args:
            host: Target IPv4 address (or hostname).
            ports: Open ports to probe; HTTP ports are skipped.

        Returns:
            ``{port: banner}`` for every port that yielded a banner.
        """
        candidates = [p for p in ports if p not in HTTP_PORTS]
        if not candidates:
            return {}

        banners: Dict[int, str] = {}
        done = 0
        total = len(candidates)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers, thread_name_prefix="banner-grab"
        ) as pool:
            futures = {
                pool.submit(self._grab_one, host, port): port
                for port in candidates
            }
            for future in concurrent.futures.as_completed(futures):
                done += 1
                port = futures[future]
                try:
                    banner = future.result()
                except Exception as exc:  # noqa: BLE001 -- keep scanning
                    logger.debug("banner grab worker failed: %s", exc)
                    banner = None
                if banner:
                    banners[port] = banner
                if self.progress_cb is not None:
                    self.progress_cb(done, total)

        return dict(sorted(banners.items()))
