#!/usr/bin/env python3
"""Subdomain & Attack Surface Recon Tool - CLI entry point.

Runs the full reconnaissance pipeline:

1. Subdomain enumeration (passive crt.sh + active DNS brute-force)
2. Live host checking (HTTPS/HTTP probes)
3. TCP port scanning (common service ports)
4. Technology fingerprinting + banner grabbing
5. Reporting (JSON + self-contained HTML dashboard + rich CLI table)

Only ever run this against assets you are authorized to test.
"""

from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
import logging
import re
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from recon import __version__
from recon.fingerprint import BannerGrabber, HTTP_PORTS, TechnologyFingerprinter
from recon.live_check import LiveHostChecker, PortScanner, resolve_a_records
from recon.models import ReconReport, Subdomain
from recon.reporter import ConsolePrinter, HTMLReporter, JSONReporter
from recon.subdomain_enum import SubdomainEnumerator

PHASES = 5
DEFAULT_WORDLIST = Path(__file__).resolve().parent / "wordlists" / "subdomains.txt"
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def normalize_domain(domain: str) -> str:
    """Normalize a user-supplied target into a bare hostname.

    Strips scheme, path, port and trailing dots, then validates the
    result as a syntactically valid domain name.

    Args:
        domain: Raw input, e.g. ``https://api.Example.com:8443/x``.

    Returns:
        The normalized, lower-cased domain (``api.example.com``).

    Raises:
        ValueError: If the input is not a valid domain name.
    """
    domain = domain.strip().lower()
    domain = domain.rstrip(".")
    domain = domain.split("://", 1)[-1]
    domain = domain.split("/", 1)[0]
    domain = domain.split(":", 1)[0]
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError(f"Invalid domain name: {domain!r}")
    return domain


def build_parser() -> argparse.ArgumentParser:
    """Build the command line interface."""
    parser = argparse.ArgumentParser(
        prog="subdomain-recon",
        description=(
            "Subdomain enumeration, live host checking, port scanning, "
            "technology fingerprinting and professional reporting."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog=(
            "Examples:\n"
            "  subdomain-recon -d example.com\n"
            "  subdomain-recon -d example.com -w wordlists/subdomains.txt -o ./out\n"
            "  subdomain-recon -d example.com --passive-only --no-port-scan\n"
            "  subdomain-recon -d example.com -p 80 443 8080 --http-concurrency 50\n"
        ),
    )
    parser.add_argument(
        "-d", "--domain", required=True,
        help="Target root domain, e.g. example.com (use only authorized targets)",
    )
    parser.add_argument(
        "-w", "--wordlist", default=str(DEFAULT_WORDLIST),
        help="Path to the DNS brute-force wordlist (one label per line)",
    )
    parser.add_argument(
        "-o", "--output", default="recon_output",
        help="Output directory for the JSON/HTML reports",
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=50,
        help="Concurrency for DNS brute-force lookups",
    )
    parser.add_argument(
        "--http-concurrency", type=int, default=20,
        help="Maximum concurrent HTTP(S) probes",
    )
    parser.add_argument(
        "--timeout", type=float, default=3.0,
        help="Timeout in seconds for DNS/HTTP/socket operations",
    )
    parser.add_argument(
        "-r", "--resolver", default="8.8.8.8",
        help="DNS resolver IP used for active enumeration",
    )
    parser.add_argument(
        "-p", "--ports", nargs="+", type=int, metavar="PORT",
        help="Ports to scan instead of the built-in common set",
    )
    parser.add_argument(
        "--passive-only", action="store_true",
        help="Only query crt.sh; skip DNS brute-force",
    )
    parser.add_argument(
        "--active-only", action="store_true",
        help="Only run DNS brute-force; skip crt.sh",
    )
    parser.add_argument(
        "--no-port-scan", action="store_true",
        help="Skip the TCP port scanning phase",
    )
    parser.add_argument(
        "--no-fingerprint", action="store_true",
        help="Skip technology fingerprinting and banner grabbing",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI colors in the CLI output",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose/debug logging",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


class ProgressCallback:
    """Thread-safe progress callback bound to a Rich progress bar."""

    def __init__(self, progress, task_id: int) -> None:
        """Initialize the callback.

        Args:
            progress: The Rich Progress instance.
            task_id: Task id of the bar being driven.
        """
        self._progress = progress
        self._task_id = task_id
        self._lock = threading.Lock()

    def __call__(self, done: int, total: int) -> None:
        """Update the bar (safe to call from worker threads)."""
        with self._lock:
            self._progress.update(self._task_id, completed=done)


async def run_scan(args: argparse.Namespace, domain: str, wordlist: List[str]) -> int:
    """Execute the five-phase reconnaissance pipeline.

    Args:
        args: Parsed CLI arguments.
        domain: Normalized target domain.
        wordlist: Candidate labels for the active brute-force phase.

    Returns:
        Exit code (0 on success).
    """
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    start = time.monotonic()
    console = ConsolePrinter(color=not args.no_color, verbose=args.verbose)
    console.banner(domain, __version__)

    # ---------------------------------------------------------------- phase 1
    console.phase(1, PHASES, "Subdomain enumeration")
    enumerator = SubdomainEnumerator(
        domain=domain,
        wordlist=wordlist,
        resolver_ip=args.resolver,
        timeout=args.timeout,
        max_workers=args.threads,
    )
    if args.passive_only:
        console.info("Passive-only mode: querying certificate transparency logs (crt.sh)...")
        subdomains = await enumerator.enumerate_passive()
    else:
        console.info(
            f"Passive crt.sh + active DNS brute-force "
            f"({len(wordlist)} names, {args.threads} threads)"
        )
        progress, task = console.make_progress(
            len(wordlist) if not args.active_only else len(wordlist),
            "DNS brute-force" if not args.active_only else "DNS brute-force (active-only)",
        )
        callback = ProgressCallback(progress, task)
        with progress:
            if args.active_only:
                subdomains = enumerator.brute_force(progress_cb=callback)
            else:
                subdomains = await enumerator.enumerate_all(progress_cb=callback)
    console.info(f"Enumeration finished: {len(subdomains)} unique subdomains")

    # ---------------------------------------------------------------- phase 2
    console.phase(2, PHASES, "Live host checking")
    to_resolve = [s for s in subdomains if not s.resolved_ips]
    if to_resolve:
        console.info(f"Resolving {len(to_resolve)} hosts without A records...")
        progress, task = console.make_progress(len(to_resolve), "DNS resolution")
        callback = ProgressCallback(progress, task)
        done: List[int] = [0]
        lock = threading.Lock()

        def resolve_host(subdomain: Subdomain) -> None:
            subdomain.resolved_ips = resolve_a_records(subdomain.name, timeout=args.timeout)
            with lock:
                done[0] += 1
                callback(done[0], len(to_resolve))

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(32, max(1, len(to_resolve)))
        ) as pool:
            futures = [pool.submit(resolve_host, s) for s in to_resolve]
            with progress:
                for future in concurrent.futures.as_completed(futures):
                    future.result()

    resolved_hosts = [s for s in subdomains if s.resolved_ips]
    console.info(f"{len(resolved_hosts)}/{len(subdomains)} hosts resolved")
    if resolved_hosts:
        checker = LiveHostChecker(
            timeout=args.timeout,
            concurrency=args.http_concurrency,
        )
        progress, task = console.make_progress(
            len(resolved_hosts), "HTTPS/HTTP probes"
        )
        checker.progress_cb = ProgressCallback(progress, task)
        with progress:
            await checker.check_many(resolved_hosts)
    alive_http = sum(1 for s in subdomains if s.alive)
    console.info(f"{alive_http} hosts answered over HTTP/HTTPS")

    # ---------------------------------------------------------------- phase 3
    console.phase(3, PHASES, "TCP port scanning")
    if args.no_port_scan:
        console.info("Skipped (--no-port-scan)")
    else:
        unique_ips = sorted({ip for s in resolved_hosts for ip in s.resolved_ips})
        scanner = PortScanner(ports=args.ports, timeout=args.timeout)
        total_checks = len(unique_ips) * len(scanner.ports)
        progress, task = console.make_progress(total_checks, "TCP port scan")
        cumulative = [0]
        lock = threading.Lock()

        def cumulative_cb(done: int, total: int) -> None:
            with lock:
                cumulative[0] = min(cumulative[0] + 1, total_checks)
                progress.update(task, completed=cumulative[0])

        ip_ports: dict = {}
        with progress:
            for ip in unique_ips:
                scanner.progress_cb = cumulative_cb
                ip_ports[ip] = scanner.scan(ip)

        open_ports_total = 0
        for subdomain in resolved_hosts:
            ports = sorted(
                {port for ip in subdomain.resolved_ips for port in ip_ports.get(ip, [])}
            )
            if ports:
                subdomain.open_ports = ports
                subdomain.alive = True
            open_ports_total += len(subdomain.open_ports)
        console.info(
            f"Scanned {len(unique_ips)} unique IPs, "
            f"{open_ports_total} open service ports assigned"
        )

    # ---------------------------------------------------------------- phase 4
    console.phase(4, PHASES, "Technology fingerprinting")
    tech_count = 0
    if args.no_fingerprint:
        console.info("Skipped (--no-fingerprint)")
    else:
        fingerprinter = TechnologyFingerprinter()
        banner_total = 0
        for subdomain in subdomains:
            subdomain.technologies = fingerprinter.fingerprint(subdomain)
            non_http_ports = [p for p in subdomain.open_ports if p not in HTTP_PORTS]
            if non_http_ports:
                host = subdomain.resolved_ips[0] if subdomain.resolved_ips else subdomain.name
                grabber = BannerGrabber(timeout=args.timeout)
                subdomain.port_banners = grabber.grab(host, non_http_ports)
                banner_total += len(subdomain.port_banners)
        tech_count = len({t for s in subdomains for t in s.technologies})
        console.info(
            f"Fingerprinted {len(subdomains)} hosts ({tech_count} unique technologies), "
            f"{banner_total} service banners grabbed"
        )

    # ---------------------------------------------------------------- phase 5
    console.phase(5, PHASES, "Reporting")
    duration = time.monotonic() - start
    stats = {
        "total_subdomains": len(subdomains),
        "alive_hosts": sum(1 for s in subdomains if s.alive),
        "resolved_hosts": sum(1 for s in subdomains if s.resolved_ips),
        "unique_ips": len({ip for s in subdomains for ip in s.resolved_ips}),
        "open_ports": sum(len(s.open_ports) for s in subdomains),
        "technologies_found": tech_count,
        "passive_findings": sum(1 for s in subdomains if "crt.sh" in s.source),
        "active_findings": sum(1 for s in subdomains if "bruteforce" in s.source),
        "duration_seconds": round(duration, 2),
    }
    report = ReconReport(
        domain=domain,
        scan_started_at=started_at,
        scan_duration_seconds=duration,
        subdomains=subdomains,
        tool={"name": "subdomain-recon-tool", "version": __version__},
        stats=stats,
    )

    output_dir = Path(args.output)
    json_path = JSONReporter(output_dir).write(report)
    html_path = HTMLReporter(output_dir, __version__).write(
        report, generated_at=started_at, duration=duration
    )
    console.info(f"JSON report written to {json_path}")
    console.info(f"HTML report written to {html_path}")

    console.table(subdomains)
    console.summary(stats)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point: parse arguments, validate, run the scan."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.passive_only and args.active_only:
        parser.error("--passive-only and --active-only are mutually exclusive")
    if args.threads < 1:
        parser.error("--threads must be >= 1")
    if args.timeout < 0.5:
        parser.error("--timeout must be >= 0.5")

    try:
        domain = normalize_domain(args.domain)
    except ValueError as exc:
        parser.error(str(exc))

    wordlist: List[str] = []
    if not args.passive_only:
        wordlist_path = Path(args.wordlist)
        if not wordlist_path.is_file():
            parser.error(f"Wordlist not found: {wordlist_path}")
        wordlist = [
            line.strip()
            for line in wordlist_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        if not wordlist:
            parser.error(f"Wordlist is empty: {wordlist_path}")

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    try:
        return asyncio.run(run_scan(args, domain, wordlist))
    except KeyboardInterrupt:
        print("Aborted by user (Ctrl+C).", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001 -- report and exit cleanly
        print(f"Fatal error: {exc}", file=sys.stderr)
        if args.verbose:
            raise
        return 1


if __name__ == "__main__":
    sys.exit(main())
