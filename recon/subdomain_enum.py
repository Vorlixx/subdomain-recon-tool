"""Module 1: Subdomain enumeration.

Two complementary discovery strategies are implemented:

* **Passive (crt.sh)** -- pulls certificate transparency log entries via
  the public crt.sh API. No traffic touches the target's infrastructure,
  which makes it ideal as a first, low-noise pass.
* **Active (DNS brute-force)** -- resolves ``word.domain`` combinations
  against a configurable resolver. A wildcard check runs first so that
  domains with catch-all DNS records do not poison the results.

Both strategies funnel their findings into :class:`recon.models.Subdomain`
objects, de-duplicated by :class:`SubdomainEnumerator`.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import random
import string
from typing import Callable, Dict, List, Optional

import dns.exception
import dns.resolver
import httpx

from .models import Subdomain

logger = logging.getLogger(__name__)

CRTSH_QUERY_URL = "https://crt.sh/?q=%25.{domain}&output=json"
MAX_CRTSH_ENTRIES = 500
CRTSH_TIMEOUT = 20.0
CRTSH_WILDCARD_PREFIX = "*."
CRTSH_RETRIES = 3
CRTSH_BACKOFF = 1.5


class CertificateTransparencyRecon:
    """Passive subdomain discovery through crt.sh certificate transparency logs."""

    def __init__(
        self,
        domain: str,
        timeout: float = CRTSH_TIMEOUT,
        max_entries: int = MAX_CRTSH_ENTRIES,
    ) -> None:
        """Initialize the passive enumerator.

        Args:
            domain: The root domain to enumerate (e.g. ``example.com``).
            timeout: HTTP timeout in seconds for the crt.sh request.
            max_entries: Hard cap on how many names are returned, to keep
                memory and later scanning phases bounded on huge certs.
        """
        self.domain = domain.lower().rstrip(".")
        self.timeout = timeout
        self.max_entries = max_entries

    async def enumerate_async(self) -> List[str]:
        """Query crt.sh and return the list of discovered hostnames.

        The request is retried up to :data:`CRTSH_RETRIES` times with
        exponential backoff because crt.sh is a free public service that
        is frequently slow or rate-limited.

        Returns:
            A de-duplicated list of lower-cased hostnames (with any
            wildcard ``*.`` prefix stripped). Empty on any failure --
            passive discovery must never crash the whole scan.
        """
        url = CRTSH_QUERY_URL.format(domain=self.domain)
        names: set = set()
        payload: Optional[list] = None
        for attempt in range(1, CRTSH_RETRIES + 1):
            try:
                async with httpx.AsyncClient(
                    timeout=self.timeout,
                    follow_redirects=True,
                    headers={"User-Agent": "subdomain-recon-tool/1.0"},
                ) as client:
                    response = await client.get(url)
                    response.raise_for_status()
                    payload = response.json()
                break
            except (httpx.HTTPError, ValueError) as exc:
                logger.warning(
                    "crt.sh query failed for %s (attempt %d/%d): %s",
                    self.domain, attempt, CRTSH_RETRIES, exc,
                )
                if attempt < CRTSH_RETRIES:
                    await asyncio.sleep(CRTSH_BACKOFF * (2 ** (attempt - 1)))
        if payload is None:
            logger.error(
                "crt.sh query failed for %s after %d attempts",
                self.domain, CRTSH_RETRIES,
            )
            return []

        for entry in payload:
            if not isinstance(entry, dict):
                continue
            raw = entry.get("name_value", "")
            for line in str(raw).splitlines():
                name = line.strip().lower().rstrip(".")
                if name.startswith(CRTSH_WILDCARD_PREFIX):
                    name = name[len(CRTSH_WILDCARD_PREFIX):]
                if name.endswith(f".{self.domain}") or name == self.domain:
                    names.add(name)
                if len(names) >= self.max_entries:
                    break
            if len(names) >= self.max_entries:
                break
        return sorted(names)


class DNSBruteForceRecon:
    """Active subdomain discovery by brute-forcing common names via DNS."""

    def __init__(
        self,
        domain: str,
        wordlist: Optional[List[str]] = None,
        resolver_ip: str = "8.8.8.8",
        timeout: float = 3.0,
        max_workers: int = 50,
    ) -> None:
        """Initialize the brute-force enumerator.

        Args:
            domain: The root domain to enumerate.
            wordlist: Candidate labels to try. If omitted, a tiny built-in
                default list is used.
            resolver_ip: DNS server used for all queries.
            timeout: Per-query timeout (both timeout and lifetime).
            max_workers: ThreadPoolExecutor size for concurrent lookups.
        """
        self.domain = domain.lower().rstrip(".")
        self.wordlist = wordlist or ["www", "mail", "ftp", "api", "dev"]
        self.timeout = timeout
        self.max_workers = max_workers

        self._resolver = dns.resolver.Resolver(configure=False)
        self._resolver.nameservers = [resolver_ip]
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout

    def _resolve_a(self, hostname: str) -> List[str]:
        """Resolve ``hostname`` to a list of IPv4 addresses.

        Returns:
            Sorted unique addresses, or an empty list for NXDOMAIN /
            empty answers / server failures / timeouts.
        """
        try:
            answers = self._resolver.resolve(hostname, "A", search=False)
            return sorted({answer.address for answer in answers})
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout,
            dns.exception.Timeout,
            dns.exception.DNSException,
        ):
            return []

    def detect_wildcard(self) -> Optional[str]:
        """Probe a random label to detect catch-all (wildcard) DNS records.

        Returns:
            The IP the wildcard resolves to, or ``None`` when the domain
            has no wildcard record.
        """
        token = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        ips = self._resolve_a(f"{token}.{self.domain}")
        return ips[0] if ips else None

    def brute_force(
        self,
        progress_cb: Optional[Callable[[int, int], None]] = None,
    ) -> List[Subdomain]:
        """Resolve every word in the wordlist against the domain.

        Args:
            progress_cb: Optional callback ``(done, total)`` invoked as
                lookups complete, used to drive CLI progress bars.

        Returns:
            List of :class:`Subdomain` objects for names that resolved,
            excluding names that only matched the wildcard record.
        """
        wildcard_ip = self.detect_wildcard()
        total = len(self.wordlist)
        done = 0
        found: List[Subdomain] = []

        def worker(word: str) -> Optional[Subdomain]:
            hostname = f"{word}.{self.domain}"
            ips = self._resolve_a(hostname)
            if not ips:
                return None
            if wildcard_ip and ips == [wildcard_ip]:
                return None
            return Subdomain(name=hostname, source="bruteforce", resolved_ips=ips)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers, thread_name_prefix="dns-brute"
        ) as pool:
            futures = [pool.submit(worker, word) for word in self.wordlist]
            for future in concurrent.futures.as_completed(futures):
                done += 1
                try:
                    result = future.result()
                except Exception as exc:  # noqa: BLE001 -- keep scanning
                    logger.debug("brute-force worker failed: %s", exc)
                    result = None
                if result is not None:
                    found.append(result)
                if progress_cb is not None:
                    progress_cb(done, total)

        found.sort(key=lambda s: s.name)
        return found


class SubdomainEnumerator:
    """Orchestrates passive + active enumeration and de-duplicates results."""

    def __init__(
        self,
        domain: str,
        wordlist: Optional[List[str]] = None,
        resolver_ip: str = "8.8.8.8",
        timeout: float = 3.0,
        max_workers: int = 50,
    ) -> None:
        """Initialize the orchestrator.

        Args:
            domain: The root domain to enumerate.
            wordlist: Candidate labels for active brute-force.
            resolver_ip: DNS server used for active lookups.
            timeout: Per-query timeout in seconds.
            max_workers: Concurrency for the brute-force phase.
        """
        self.domain = domain.lower().rstrip(".")
        self.passive = CertificateTransparencyRecon(self.domain)
        self.active = DNSBruteForceRecon(
            domain=self.domain,
            wordlist=wordlist,
            resolver_ip=resolver_ip,
            timeout=timeout,
            max_workers=max_workers,
        )

    async def enumerate_passive(self) -> List[Subdomain]:
        """Run the passive crt.sh phase.

        Returns:
            Sorted list of :class:`Subdomain` objects (unresolved).
        """
        names = await self.passive.enumerate_async()
        return [Subdomain(name=name, source="crt.sh") for name in names]

    def brute_force(
        self,
        progress_cb: Optional[Callable[[int, int], None]] = None,
    ) -> List[Subdomain]:
        """Run the active DNS brute-force phase.

        Args:
            progress_cb: Optional ``(done, total)`` progress callback.

        Returns:
            Sorted list of resolved :class:`Subdomain` objects.
        """
        return self.active.brute_force(progress_cb=progress_cb)

    @staticmethod
    def merge(
        passive: List[Subdomain], active: List[Subdomain]
    ) -> List[Subdomain]:
        """Merge both phases, de-duplicating by hostname and merging sources.

        Args:
            passive: Results from the crt.sh phase.
            active: Results from the brute-force phase.

        Returns:
            One :class:`Subdomain` per unique hostname.
        """
        merged: Dict[str, Subdomain] = {}
        for subdomain in passive + active:
            existing = merged.get(subdomain.name)
            if existing is None:
                merged[subdomain.name] = subdomain
            else:
                for source in subdomain.source.split(","):
                    existing.add_source(source.strip())
                if not existing.resolved_ips and subdomain.resolved_ips:
                    existing.resolved_ips = subdomain.resolved_ips
        return sorted(merged.values(), key=lambda s: s.name)

    async def enumerate_all(
        self,
        progress_cb: Optional[Callable[[int, int], None]] = None,
        passive_only: bool = False,
        active_only: bool = False,
    ) -> List[Subdomain]:
        """Run all enabled enumeration phases concurrently.

        Args:
            progress_cb: Optional ``(done, total)`` progress callback for
                the active phase.
            passive_only: Skip the active brute-force phase.
            active_only: Skip the passive crt.sh phase.

        Returns:
            Merged, de-duplicated list of :class:`Subdomain` objects.
        """
        if passive_only:
            return await self.enumerate_passive()
        if active_only:
            return self.brute_force(progress_cb=progress_cb)

        passive_task = asyncio.create_task(self.enumerate_passive())
        active_task = asyncio.to_thread(self.brute_force, progress_cb)
        passive_result, active_result = await asyncio.gather(
            passive_task, active_task
        )
        return self.merge(passive_result, active_result)
