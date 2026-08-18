"""Module 4: Reporting.

Three output channels are provided:

* :class:`ConsolePrinter` -- human-friendly, colorful CLI output powered
  by Rich (phase headers, progress bars, result tables, summary panel).
* :class:`JSONReporter` -- machine-readable report for further tooling.
* :class:`HTMLReporter` -- a self-contained dark-theme dashboard with
  stat cards, an alive/dead distribution bar and live client-side
  filtering. No internet connection or external assets are required.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeRemainingColumn  # noqa: E501
from rich.table import Table
from rich.text import Text

from .models import ReconReport, Subdomain

STATUS_COLORS = {
    "2": "green",
    "3": "yellow",
    "4": "red",
    "5": "magenta",
}


class ConsolePrinter:
    """Wraps Rich primitives into a small, consistent CLI vocabulary."""

    def __init__(self, color: bool = True, verbose: bool = False) -> None:
        """Initialize the printer.

        Args:
            color: Enable ANSI colors (disable for CI/log capture).
            verbose: Print debug-level detail where applicable.
        """
        self.console = Console(no_color=not color)
        self.verbose = verbose

    def banner(self, domain: str, version: str) -> None:
        """Print the startup banner with tool version and target domain."""
        panel = Panel.fit(
            Text.assemble(
                ("Subdomain & Attack Surface Recon Tool", "bold cyan"),
                ("  v" + version, "dim"),
                ("\nTarget: ", "bold"),
                (domain, "bold yellow"),
            ),
            border_style="cyan",
        )
        self.console.print(panel)

    def phase(self, number: int, total: int, title: str) -> None:
        """Print a phase header rule."""
        self.console.rule(f"[bold]Phase {number}/{total}[/] [cyan]{title}[/]")

    def info(self, message: str) -> None:
        """Print an informational line."""
        self.console.print(f"[dim][i]info[/i][/dim] {message}")

    def warn(self, message: str) -> None:
        """Print a warning line."""
        self.console.print(f"[bold yellow]![/] {message}")

    def error(self, message: str) -> None:
        """Print an error line."""
        self.console.print(f"[bold red]x[/] {message}")

    def debug(self, message: str) -> None:
        """Print a debug line when verbose mode is enabled."""
        if self.verbose:
            self.console.print(f"[dim]{message}[/dim]")

    def make_progress(self, total: int, description: str):
        """Create a single progress bar and its task id.

        Returns:
            ``(progress, task_id)`` -- wrap ``progress`` in a ``with``
            block and feed completions via ``progress.update(task_id,
            completed=done)``.
        """
        progress, task_ids = self.make_progress_multi([(total, description)])
        return progress, task_ids[0]

    def make_progress_multi(self, tasks: List[Tuple[int, str]]):
        """Create one Rich progress instance with several independent bars.

        Args:
            tasks: ``(total, description)`` pairs, one bar per pair.

        Returns:
            ``(progress, task_ids)`` -- wrap ``progress`` in a ``with``
            block and feed completions via ``progress.update(task_id,
            completed=done)`` using the matching task id.
        """
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold]{task.description}[/]"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=self.console,
        )
        task_ids = [
            progress.add_task(description, total=total)
            for total, description in tasks
        ]
        return progress, task_ids

    def table(self, subdomains: List[Subdomain]) -> None:
        """Print the results table for all discovered subdomains."""
        table = Table(
            title=f"Discovered subdomains ({len(subdomains)})",
            header_style="bold cyan",
            show_lines=False,
        )
        table.add_column("#", style="dim", justify="right")
        table.add_column("Hostname", style="bold")
        table.add_column("Source", style="dim")
        table.add_column("IPs", style="yellow")
        table.add_column("HTTP", justify="center")
        table.add_column("Title", max_width=38, overflow="ellipsis")
        table.add_column("Technologies", max_width=36, overflow="ellipsis")
        table.add_column("Ports", max_width=24, overflow="ellipsis")

        for index, subdomain in enumerate(subdomains, start=1):
            status = "—"
            if subdomain.http_status:
                color = STATUS_COLORS.get(str(subdomain.http_status)[0], "white")
                status = f"[{color}]{subdomain.http_status}[/]"
            elif subdomain.alive:
                status = "[green]alive[/]"
            table.add_row(
                str(index),
                subdomain.name,
                subdomain.source,
                ", ".join(subdomain.resolved_ips[:4]) or "—",
                status,
                subdomain.page_title or "—",
                ", ".join(subdomain.technologies[:6]) or "—",
                ", ".join(map(str, subdomain.open_ports[:12])) or "—",
            )
        self.console.print(table)

    def summary(self, stats: Dict[str, Any]) -> None:
        """Print the final scan summary panel."""
        lines = Text()
        for key, value in stats.items():
            lines.append(f"{key.replace('_', ' ').title():<28}", "bold")
            lines.append(f"{value}\n")
        self.console.print(Panel(lines, title="Scan summary", border_style="green"))


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TOOL_TITLE__ - __DOMAIN__</title>
<style>
  :root {
    --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #e6edf3;
    --muted: #8b949e; --accent: #58a6ff; --green: #3fb950; --red: #f85149;
    --yellow: #d29922; --purple: #bc8cff; --cyan: #39c5cf;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font: 14px/1.5 "Segoe UI", system-ui, sans-serif; padding: 24px; }
  .wrap { max-width: 1200px; margin: 0 auto; }
  header { display: flex; justify-content: space-between; align-items: baseline; flex-wrap: wrap; gap: 8px; border-bottom: 1px solid var(--border); padding-bottom: 12px; margin-bottom: 20px; }
  header h1 { font-size: 20px; color: var(--accent); }
  header .sub { color: var(--muted); font-size: 13px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; margin-bottom: 20px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; }
  .card .num { font-size: 26px; font-weight: 700; }
  .card .lbl { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .5px; }
  .bar { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; margin-bottom: 20px; }
  .bar .track { display: flex; height: 10px; border-radius: 5px; overflow: hidden; background: var(--red); margin: 8px 0 6px; }
  .bar .alive { background: var(--green); }
  .bar .legend { color: var(--muted); font-size: 12px; }
  .filters { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 14px; }
  .filters input, .filters select { background: var(--card); color: var(--text); border: 1px solid var(--border); border-radius: 6px; padding: 8px 12px; font-size: 14px; }
  .filters input { flex: 1; min-width: 220px; }
  .result-info { color: var(--muted); font-size: 13px; margin: -6px 0 14px; }
  .result-info.warn { color: var(--yellow); }
  table { width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
  th { text-align: left; padding: 10px 12px; background: #1c2128; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .5px; position: sticky; top: 0; }
  td { padding: 10px 12px; border-top: 1px solid var(--border); vertical-align: top; }
  tr:hover td { background: rgba(88, 166, 255, .06); }
  .host { font-family: "Cascadia Code", Consolas, monospace; color: var(--accent); }
  .ip { font-family: Consolas, monospace; color: var(--yellow); font-size: 12px; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 12px; font-weight: 600; }
  .b-ok { background: rgba(63, 185, 80, .15); color: var(--green); }
  .b-red { background: rgba(248, 81, 73, .15); color: var(--red); }
  .b-alive { background: rgba(63, 185, 80, .15); color: var(--green); }
  .b-dead { background: rgba(139, 148, 158, .12); color: var(--muted); }
  .b-none { background: rgba(139, 148, 158, .12); color: var(--muted); }
  .tag { display: inline-block; background: rgba(188, 140, 255, .12); color: var(--purple); border-radius: 4px; padding: 1px 6px; font-size: 12px; margin: 1px 2px 1px 0; }
  .ports { font-family: Consolas, monospace; font-size: 12px; color: var(--cyan); }
  .banner { color: var(--muted); font-size: 12px; max-width: 220px; }
  .muted { color: var(--muted); }
  .empty { padding: 40px; text-align: center; color: var(--muted); }
  footer { margin-top: 22px; color: var(--muted); font-size: 12px; text-align: center; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>__TOOL_TITLE__</h1>
    <div class="sub">Target: <b>__DOMAIN__</b> &middot; Generated: __GENERATED_AT__ &middot; Duration: __DURATION__</div>
  </header>
  <div class="cards">__STAT_CARDS__</div>
  <div class="bar">__DISTRIBUTION__</div>
  <div class="filters">
    <input id="search" type="search" placeholder="Filter by hostname, IP, title or technology...">
    <select id="status">
      <option value="all">All hosts</option>
      <option value="alive">Alive only</option>
      <option value="dead">Dead only</option>
    </select>
    <select id="source">
      <option value="all">All sources</option>
      <option value="crt.sh">crt.sh</option>
      <option value="bruteforce">bruteforce</option>
    </select>
  </div>
  <div id="result-info" class="result-info"></div>
  <table>
    <thead><tr><th>#</th><th>Hostname</th><th>IPs</th><th>HTTP</th><th>Source</th><th>Title</th><th>Technologies</th><th>Ports</th><th>Banner</th></tr></thead>
    <tbody>__ROWS__</tbody>
  </table>
  <footer>Generated by __TOOL_TITLE__ v__VERSION__ &middot; Authorized security assessment only</footer>
</div>
<script>
  var search = document.getElementById('search');
  var status = document.getElementById('status');
  var source = document.getElementById('source');
  var resultInfo = document.getElementById('result-info');
  function applyFilters() {
    var q = (search.value || '').toLowerCase();
    var s = status.value;
    var src = source.value;
    var rows = document.querySelectorAll('tbody tr');
    var anyFilter = q !== '' || s !== 'all' || src !== 'all';
    var visible = 0;
    var hasRows = false;
    rows.forEach(function (row) {
      if (row.getAttribute('data-alive') === null) {
        row.style.display = anyFilter ? 'none' : '';
        return;
      }
      hasRows = true;
      var hay = (row.getAttribute('data-search') || '').toLowerCase();
      var alive = row.getAttribute('data-alive') === 'true';
      var show = hay.indexOf(q) !== -1;
      if (s === 'alive' && !alive) show = false;
      if (s === 'dead' && alive) show = false;
      if (src !== 'all' && (row.getAttribute('data-source') || '').indexOf(src) === -1) show = false;
      row.style.display = show ? '' : 'none';
      if (show) visible += 1;
    });
    if (!hasRows) {
      resultInfo.textContent = '';
      resultInfo.className = 'result-info';
    } else if (visible === 0) {
      resultInfo.textContent = 'No hosts match the current filters.';
      resultInfo.className = 'result-info warn';
    } else {
      resultInfo.textContent = visible + (visible === 1 ? ' result' : ' results') + ' found';
      resultInfo.className = 'result-info';
    }
  }
  search.addEventListener('input', applyFilters);
  status.addEventListener('change', applyFilters);
  source.addEventListener('change', applyFilters);
  applyFilters();
</script>
</body>
</html>
"""


class JSONReporter:
    """Writes the full scan report as pretty-printed JSON."""

    FILENAME = "report.json"

    def __init__(self, output_dir: Path) -> None:
        """Initialize the reporter.

        Args:
            output_dir: Directory the report is written into.
        """
        self.output_dir = output_dir

    def write(self, report: ReconReport) -> Path:
        """Serialize and persist the report.

        Args:
            report: The report to write.

        Returns:
            Path of the written file.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)
        path = self.output_dir / self.FILENAME
        payload = json.dumps(
            report.to_dict(), indent=2, ensure_ascii=False, default=str
        )
        path.write_text(payload, encoding="utf-8")
        return path


class HTMLReporter:
    """Builds a self-contained, filterable dark-theme HTML dashboard."""

    FILENAME = "report.html"

    def __init__(self, output_dir: Path, version: str) -> None:
        """Initialize the reporter.

        Args:
            output_dir: Directory the dashboard is written into.
            version: Tool version shown in the footer.
        """
        self.output_dir = output_dir
        self.version = version

    @staticmethod
    def _escape(value: Any) -> str:
        """HTML-escape any value for safe embedding."""
        return html.escape(str(value if value is not None else ""), quote=True)

    @staticmethod
    def _status_badge(subdomain: Subdomain) -> str:
        """Render the HTTP status badge for one host."""
        if subdomain.http_status is not None:
            color = "b-ok" if subdomain.http_status < 400 else "b-red"
            return f'<span class="badge {color}">{subdomain.http_status}</span>'
        if subdomain.alive:
            return '<span class="badge b-alive">alive</span>'
        return '<span class="badge b-dead">none</span>'

    @staticmethod
    def _stat_card(value: Any, label: str, color: str = "accent") -> str:
        """Render one stat card."""
        return (
            '<div class="card"><div class="num" style="color:var('
            f'{color})">{value}</div><div class="lbl">{label}</div></div>'
        )

    @staticmethod
    def _distribution(alive: int, total: int) -> str:
        """Render the alive/dead distribution bar."""
        alive_pct = round((alive / total) * 100) if total else 0
        dead_pct = 100 - alive_pct
        legend = (
            f'<span style="color:var(--green)">&#9679; Alive: {alive}</span>'
            f' &nbsp; <span style="color:var(--red)">&#9679; Dead: {total - alive}</span>'
            f' &nbsp; ({alive_pct}% live)'
        )
        return (
            '<div class="lbl">Host status distribution</div>'
            f'<div class="track"><div class="alive" style="width:{alive_pct}%"></div></div>'
            f'<div class="legend">{legend}</div>'
        )

    def _row(self, index: int, subdomain: Subdomain) -> str:
        """Render one table row with data attributes for filtering."""
        searchable = " ".join(
            [
                subdomain.name,
                " ".join(subdomain.resolved_ips),
                subdomain.page_title or "",
                " ".join(subdomain.technologies),
                " ".join(map(str, subdomain.open_ports)),
            ]
        )
        banner = "; ".join(
            f"{port}: {text}"
            for port, text in sorted(subdomain.port_banners.items())
        )
        techs = "".join(
            f'<span class="tag">{self._escape(t)}</span>'
            for t in subdomain.technologies
        )
        return (
            "<tr "
            f'data-alive="{"true" if subdomain.alive else "false"}" '
            f'data-source="{self._escape(subdomain.source)}" '
            f'data-search="{self._escape(searchable)}">'
            f"<td class=\"muted\">{index}</td>"
            f'<td class="host">{self._escape(subdomain.name)}</td>'
            f'<td class="ip">{self._escape(", ".join(subdomain.resolved_ips)) or "—"}</td>'
            f"<td>{self._status_badge(subdomain)}</td>"
            f'<td class="muted">{self._escape(subdomain.source)}</td>'
            f'<td>{self._escape(subdomain.page_title) or "—"}</td>'
            f"<td>{techs or '<span class=\"muted\">—</span>'}</td>"
            f'<td class="ports">{self._escape(", ".join(map(str, subdomain.open_ports))) or "—"}</td>'
            f'<td class="banner">{self._escape(banner) or "—"}</td>'
            "</tr>"
        )

    def write(
        self,
        report: ReconReport,
        generated_at: str,
        duration: float,
    ) -> Path:
        """Build and persist the HTML dashboard.

        Args:
            report: The scan results.
            generated_at: ISO timestamp shown in the header.
            duration: Scan duration in seconds, shown in the header.

        Returns:
            Path of the written file.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)
        path = self.output_dir / self.FILENAME

        subdomains = report.subdomains
        alive = sum(1 for s in subdomains if s.alive)
        resolved = sum(1 for s in subdomains if s.resolved_ips)
        unique_ips = {ip for s in subdomains for ip in s.resolved_ips}
        total_ports = sum(len(s.open_ports) for s in subdomains)
        tech_set = {t for s in subdomains for t in s.technologies}

        cards = "".join(
            [
                self._stat_card(len(subdomains), "Subdomains"),
                self._stat_card(alive, "Alive hosts", "green"),
                self._stat_card(resolved, "Resolved", "yellow"),
                self._stat_card(len(unique_ips), "Unique IPs", "purple"),
                self._stat_card(total_ports, "Open ports", "cyan"),
                self._stat_card(len(tech_set), "Technologies", "green"),
            ]
        )
        rows = "".join(
            self._row(index, subdomain)
            for index, subdomain in enumerate(subdomains, start=1)
        )
        if not rows:
            rows = '<tr><td colspan="9" class="empty">No subdomains found</td></tr>'

        page = (
            _HTML_TEMPLATE.replace("__TOOL_TITLE__", "Subdomain Recon Tool")
            .replace("__DOMAIN__", self._escape(report.domain))
            .replace("__GENERATED_AT__", self._escape(generated_at))
            .replace("__DURATION__", self._escape(f"{duration:.1f}s"))
            .replace("__VERSION__", self._escape(self.version))
            .replace("__STAT_CARDS__", cards)
            .replace("__DISTRIBUTION__", self._distribution(alive, len(subdomains)))
            .replace("__ROWS__", rows)
        )
        path.write_text(page, encoding="utf-8")
        return path
