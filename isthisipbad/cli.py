"""Modern CLI for Is This IP Bad using Typer and Rich."""

from __future__ import annotations

import asyncio
import csv
import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from .checker import IPChecker, IPReport, ThreatLevel

app = typer.Typer(
    name="isthisipbad",
    help="Check IP addresses against popular blacklists and threat intelligence feeds.",
    add_completion=False,
)
console = Console()


def get_threat_color(level: ThreatLevel) -> str:
    """Get color for threat level."""
    colors = {
        ThreatLevel.CLEAN: "green",
        ThreatLevel.LOW: "yellow",
        ThreatLevel.MEDIUM: "orange3",
        ThreatLevel.HIGH: "red",
        ThreatLevel.CRITICAL: "bold red",
    }
    return colors.get(level, "white")


def format_report_table(report: IPReport, show_clean: bool = False) -> Table:
    """Format an IP report as a Rich table."""
    table = Table(
        title=f"Results for {report.ip}",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )
    
    table.add_column("Source", style="cyan")
    table.add_column("Type", style="dim")
    table.add_column("Status", justify="center")
    table.add_column("Details", style="dim")
    
    for result in report.results:
        if result.error:
            status = Text("⚠ Error", style="yellow")
            details = result.error
        elif result.listed:
            status = Text("✗ Listed", style="red bold")
            details = result.details or ""
        else:
            if not show_clean:
                continue
            status = Text("✓ Clean", style="green")
            details = ""
        
        table.add_row(
            result.source,
            result.source_type.replace("_", " ").title(),
            status,
            details[:60] + "..." if len(details or "") > 60 else details,
        )
    
    return table


def format_summary_panel(report: IPReport) -> Panel:
    """Format IP info and summary as a Rich panel."""
    threat_color = get_threat_color(report.threat_level)
    
    lines = []
    lines.append(f"[bold]IP:[/bold] {report.ip}")
    
    if report.fqdn:
        lines.append(f"[bold]FQDN:[/bold] {report.fqdn}")
    
    if report.geo_info:
        geo = report.geo_info
        location_parts = [
            geo.get("city"),
            geo.get("region"),
            geo.get("country"),
        ]
        location = ", ".join(p for p in location_parts if p)
        if location:
            lines.append(f"[bold]Location:[/bold] {location}")
        if geo.get("isp"):
            lines.append(f"[bold]ISP:[/bold] {geo['isp']}")
        if geo.get("org"):
            lines.append(f"[bold]Organization:[/bold] {geo['org']}")
    
    lines.append("")
    lines.append(f"[bold]Blacklists:[/bold] [{threat_color}]{report.blacklist_count}[/] / {report.total_checks}")
    lines.append(f"[bold]Threat Level:[/bold] [{threat_color}]{report.threat_level.value.upper()}[/]")
    
    if report.error_count > 0:
        lines.append(f"[yellow]Errors: {report.error_count}[/]")
    
    return Panel(
        "\n".join(lines),
        title="[bold]IP Information[/]",
        border_style="blue",
    )


def write_json_output(reports: list[IPReport], output_path: Path) -> None:
    """Write reports to JSON file."""
    data = [r.to_dict() for r in reports]
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)
    console.print(f"[green]Results written to {output_path}[/]")


def write_csv_output(reports: list[IPReport], output_path: Path) -> None:
    """Write reports to CSV file."""
    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "ip", "fqdn", "country", "city", "isp",
            "blacklist_count", "total_checks", "threat_level",
            "source", "source_type", "listed", "details", "error"
        ])
        
        for report in reports:
            geo = report.geo_info or {}
            for result in report.results:
                writer.writerow([
                    report.ip,
                    report.fqdn or "",
                    geo.get("country", ""),
                    geo.get("city", ""),
                    geo.get("isp", ""),
                    report.blacklist_count,
                    report.total_checks,
                    report.threat_level.value,
                    result.source,
                    result.source_type,
                    result.listed,
                    result.details or "",
                    result.error or "",
                ])
    
    console.print(f"[green]Results written to {output_path}[/]")


async def check_single_ip(
    ip: str,
    checker: IPChecker,
    show_clean: bool = False,
) -> IPReport:
    """Check a single IP with progress display."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        progress.add_task(f"Checking {ip}...", total=None)
        report = await checker.check_ip(ip)
    
    return report


async def check_multiple_ips(
    ips: list[str],
    checker: IPChecker,
) -> list[IPReport]:
    """Check multiple IPs with progress display."""
    reports = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Checking IPs...", total=len(ips))
        
        for ip in ips:
            progress.update(task, description=f"Checking {ip}...")
            report = await checker.check_ip(ip)
            reports.append(report)
            progress.advance(task)
    
    return reports


@app.command()
def check(
    ip: Optional[str] = typer.Argument(
        None,
        help="IP address to check. If not provided, uses your public IP.",
    ),
    file: Optional[Path] = typer.Option(
        None,
        "--file", "-f",
        help="File containing IP addresses (one per line).",
        exists=True,
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Output file path (supports .json and .csv).",
    ),
    format: str = typer.Option(
        "table",
        "--format",
        help="Output format: table, json, csv.",
    ),
    show_clean: bool = typer.Option(
        False,
        "--show-clean", "-a",
        help="Show clean (not listed) results.",
    ),
    timeout: float = typer.Option(
        10.0,
        "--timeout", "-t",
        help="HTTP timeout in seconds.",
    ),
    dns_timeout: float = typer.Option(
        5.0,
        "--dns-timeout",
        help="DNS timeout in seconds.",
    ),
    no_info: bool = typer.Option(
        False,
        "--no-info",
        help="Skip FQDN and GeoIP lookup.",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet", "-q",
        help="Minimal output, just the summary.",
    ),
):
    """
    Check IP addresses against blacklists and threat intelligence feeds.
    
    Examples:
    
        isthisipbad check 8.8.8.8
        
        isthisipbad check --file ips.txt --output results.json
        
        isthisipbad check 1.2.3.4 --show-clean
    """
    async def _run():
        async with IPChecker(
            timeout=timeout,
            dns_timeout=dns_timeout,
        ) as checker:
            # Collect IPs to check
            ips_to_check = []
            
            if file:
                # Read IPs from file
                content = file.read_text()
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        ips_to_check.append(line)
                
                if not ips_to_check:
                    console.print("[red]No valid IPs found in file.[/]")
                    raise typer.Exit(1)
            elif ip:
                ips_to_check = [ip]
            else:
                # Get public IP
                import httpx
                try:
                    async with httpx.AsyncClient() as client:
                        response = await client.get("https://api.ipify.org")
                        public_ip = response.text.strip()
                        console.print(f"[cyan]Your public IP: {public_ip}[/]")
                        
                        if not typer.confirm("Check this IP?"):
                            public_ip = typer.prompt("Enter IP to check")
                        ips_to_check = [public_ip]
                except Exception:
                    console.print("[red]Could not determine public IP.[/]")
                    raise typer.Exit(1)
            
            # Perform checks
            if len(ips_to_check) == 1:
                reports = [await check_single_ip(ips_to_check[0], checker, show_clean)]
            else:
                reports = await check_multiple_ips(ips_to_check, checker)
            
            # Output results
            if output:
                suffix = output.suffix.lower()
                if suffix == ".json" or format == "json":
                    write_json_output(reports, output)
                elif suffix == ".csv" or format == "csv":
                    write_csv_output(reports, output)
                else:
                    write_json_output(reports, output)
            
            if format == "json" and not output:
                # Print JSON to stdout
                data = [r.to_dict() for r in reports]
                console.print_json(json.dumps(data, indent=2))
            elif format == "csv" and not output:
                # Print CSV to stdout
                import io
                buffer = io.StringIO()
                writer = csv.writer(buffer)
                writer.writerow(["ip", "blacklist_count", "total_checks", "threat_level"])
                for report in reports:
                    writer.writerow([
                        report.ip,
                        report.blacklist_count,
                        report.total_checks,
                        report.threat_level.value,
                    ])
                console.print(buffer.getvalue())
            else:
                # Table output
                for report in reports:
                    if not quiet:
                        console.print()
                        console.print(format_summary_panel(report))
                        console.print()
                        console.print(format_report_table(report, show_clean))
                    
                    # Always show final summary
                    threat_color = get_threat_color(report.threat_level)
                    console.print()
                    console.print(
                        f"[bold]{report.ip}[/] is on "
                        f"[{threat_color}]{report.blacklist_count}[/]/"
                        f"{report.total_checks} blacklists "
                        f"([{threat_color}]{report.threat_level.value.upper()}[/])"
                    )
            
            # Return exit code based on threat level
            max_threat = max((r.threat_level for r in reports), key=lambda x: list(ThreatLevel).index(x))
            if max_threat in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
                raise typer.Exit(2)
            elif max_threat in (ThreatLevel.LOW, ThreatLevel.MEDIUM):
                raise typer.Exit(1)
    
    asyncio.run(_run())


@app.command()
def version():
    """Show version information."""
    from . import __version__
    console.print(f"[bold]isthisipbad[/] version {__version__}")


@app.command()
def sources():
    """List all threat intelligence sources."""
    from .config import DNSBLS, THREAT_FEEDS
    
    table = Table(title="Threat Intelligence Sources", box=box.ROUNDED)
    table.add_column("Name", style="cyan")
    table.add_column("Type", style="dim")
    table.add_column("URL/Domain")
    
    for dnsbl, name in DNSBLS:
        table.add_row(name, "DNSBL", dnsbl)
    
    for feed in THREAT_FEEDS:
        table.add_row(feed["name"], "HTTP Feed", feed["url"][:50] + "...")
    
    console.print(table)


def main():
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
