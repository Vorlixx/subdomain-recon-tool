"""Module 2: Live host checking.

Two probes decide whether an enumerated subdomain is actually reachable:

* **HTTP(S) probing** -- each host is requested over HTTPS first with an
  automatic fallback to plain HTTP. Status code, final URL, title, headers
  and a truncated body sample are captured for later fingerprinting.
* **TCP port scanning** -- a fast connect-based scanner checks a curated
  list of common service ports, which also catches hosts that are alive
  but do not run a web server.

DNS resolution is handled here too (with a system-resolver fallback) for
hosts that were discovered passively and never resolved during enumeration.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import re
import socket
from typing import Callable, Dict, List, Optional

import dns.exception
import dns.resolver
import httpx

from .models import Subdomain

logger = logging.getLogger(__name__)

# Common TCP ports worth checking when mapping the attack surface.
DEFAULT_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 1723, 2049, 3306, 3389, 5432, 5900, 5985, 6379, 8000,
    8008, 8080, 8081, 8443, 8888, 9200, 10000, 27017,
]

DEFAULT_RESOLVERS: List[str] = ["8.8.8.8", "1.1.1.1"]
BODY_LIMIT = 200 * 1024  # 200 KB cap on the body sample kept for fingerprinting
TITLE_RE = re.compile(r"<title[^>]*>\s*(.*?)\s*</title>", re.IGNORECASE | re.DOTALL)
USER_AGENT = "Mozilla/5.0 (compatible; subdomain-recon-tool/1.0; +https://github.com/)"  # noqa: E501


def resolve_a_records(hostname: str, timeout: float = 3.0) -> List[str]:
    """Resolve ``hostname`` to IPv4 addresses.

    Uses dnspython against public resolvers first; if that fails, falls
    back to the operating system resolver so scans work in restricted
    environments.

    Args:
        hostname: The name to resolve.
        timeout: Per-query timeout in seconds.

    Returns:
        Sorted unique IPv4 addresses, or an empty list on any failure.
    """
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = DEFAULT_RESOLVERS
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(hostname, "A", search=False)
        return sorted({answer.address for answer in answers})
    except (dns.exception.DNSException, dns.resolver.NXDOMAIN):
        pass

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(socket.gethostbyname_ex, hostname)
            _, _, ips = future.result(timeout=timeout)
        return sorted(set(ips))
    except (OSError, concurrent.futures.TimeoutError):
        return []


class PortScanner:
    """Fast TCP connect-based port scanner with bounded concurrency."""

    def __init__(
        self,
        ports: Optional[List[int]] = None,
        timeout: float = 1.0,
        max_workers: int = 200,
        progress_cb: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        """Initialize the scanner.

        Args:
            ports: Ports to test (defaults to :data:`DEFAULT_PORTS`).
            timeout: Connect timeout per port in seconds.
            max_workers: ThreadPoolExecutor size.
            progress_cb: Optional ``(done, total)`` progress callback.
        """
        self.ports = sorted(set(ports)) if ports else DEFAULT_PORTS
        self.timeout = timeout
        self.max_workers = min(max_workers, len(self.ports))
        self.progress_cb = progress_cb

    def scan(self, host: str) -> List[int]:
        """Scan a single host and return the list of open TCP ports.

        Args:
            host: IPv4 address (or hostname) to scan.

        Returns:
            Sorted list of open ports.
        """
        total = len(self.ports)
        done = 0
        open_ports: List[int] = []

        def check(port: int) -> Optional[int]:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                if sock.connect_ex((host, port)) == 0:
                    return port
            return None

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers, thread_name_prefix="port-scan"
        ) as pool:
            futures = [pool.submit(check, port) for port in self.ports]
            for future in concurrent.futures.as_completed(futures):
                done += 1
                try:
                    port = future.result()
                except Exception as exc:  # noqa: BLE001 -- keep scanning
                    logger.debug("port check failed on %s: %s", host, exc)
                    port = None
                if port is not None:
                    open_ports.append(port)
                if self.progress_cb is not None:
                    self.progress_cb(done, total)

        open_ports.sort()
        return open_ports


class LiveHostChecker:
    """Probes hosts over HTTPS/HTTP concurrently using asyncio.

    HTTPS is attempted first; when it fails (timeout, TLS error, refused
    connection) the checker transparently falls back to plain HTTP, so
    legacy or misconfigured servers are still discovered.
    """

    def __init__(
        self,
        timeout: float = 3.0,
        concurrency: int = 20,
        progress_cb: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        """Initialize the checker.

        Args:
            timeout: Per-request timeout in seconds (connect + read).
            concurrency: Maximum number of simultaneous requests.
            progress_cb: Optional ``(done, total)`` progress callback.
        """
        self.timeout = timeout
        self.concurrency = concurrency
        self.progress_cb = progress_cb

    async def _probe(self, client: httpx.AsyncClient, scheme: str, subdomain: Subdomain) -> bool:  # noqa: E501
        """Probe a single scheme; on success, enrich the subdomain object.

        Returns:
            ``True`` when an HTTP response was received.
        """
        url = f"{scheme}://{subdomain.name}"
        try:
            response = await client.get(url)
        except httpx.TransportError:
            return False

        subdomain.http_status = response.status_code
        subdomain.final_url = str(response.url)
        subdomain.server_header = response.headers.get("server")
        subdomain.response_headers = {k.lower(): v for k, v in response.headers.items()}
        subdomain.body_sample = response.text[:BODY_LIMIT]
        title_match = TITLE_RE.search(subdomain.body_sample)
        if title_match:
            subdomain.page_title = " ".join(title_match.group(1).split())[:200]
        return True

    async def check_many(self, subdomains: List[Subdomain]) -> List[Subdomain]:
        """Probe all subdomains concurrently and enrich them in place.

        Args:
            subdomains: Hosts to check (objects are mutated in place).

        Returns:
            The same list, with live hosts marked and HTTP details filled.
        """
        total = len(subdomains)
        if total == 0:
            return subdomains

        semaphore = asyncio.Semaphore(self.concurrency)
        done = 0
        timeout = httpx.Timeout(self.timeout, connect=self.timeout)
        limits = httpx.Limits(
            max_connections=self.concurrency,
            max_keepalive_connections=self.concurrency,
        )

        async def guarded(subdomain: Subdomain) -> None:
            nonlocal done
            try:
                async with semaphore:
                    ok = await self._probe(client, "https", subdomain)
                    if not ok:
                        ok = await self._probe(client, "http", subdomain)
                    if ok:
                        subdomain.alive = True
            except Exception as exc:  # noqa: BLE001 -- never crash the batch
                logger.debug("probe failed for %s: %s", subdomain.name, exc)
            finally:
                done += 1
                if self.progress_cb is not None:
                    self.progress_cb(done, total)

        async with httpx.AsyncClient(
            # verify=False is a deliberate trade-off: self-signed or expired
            # certificates on internal/staging hosts must not hide live hosts.
            # The checker only reads status/title/headers, never credentials.
            verify=False,
            follow_redirects=True,
            timeout=timeout,
            limits=limits,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            await asyncio.gather(*(guarded(subdomain) for subdomain in subdomains))

        return subdomains
