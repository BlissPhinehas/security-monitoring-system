"""
Main CLI interface for Threat Intelligence System
"""

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint
import json
from pathlib import Path

from .config import Config
from .ip_analyzer import IPAnalyzer
from .hash_checker import HashChecker
from .report_generator import ReportGenerator

console = Console()


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """
    🔒 Threat Intelligence Analysis System
    
    Multi-source threat intelligence aggregation and analysis tool.
    """
    pass


@cli.command()
@click.argument('ip_address')
@click.option('--report', '-r', type=click.Choice(['json', 'html', 'txt']), 
              help='Generate report in specified format')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def check_ip(ip_address, report, verbose):
    """
    Check IP address reputation against threat databases
    
    Example: python -m src.main check-ip 8.8.8.8
    """
    console.print(f"\n[bold cyan]🔍 Analyzing IP Address: {ip_address}[/bold cyan]\n")
    
    analyzer = IPAnalyzer()
    
    # Perform analysis
    with console.status("[bold green]Querying threat intelligence sources..."):
        result = analyzer.analyze_ip(ip_address)
    
    # Display results
    if result.get("error"):
        console.print(f"[bold red]❌ Error: {result['error']}[/bold red]")
        return
    
    # Summary
    summary = result.get("summary", {})
    threat_level = summary.get("threat_level", "UNKNOWN")
    confidence = summary.get("confidence_score", 0)
    
    # Color code threat level
    level_colors = {
        "CRITICAL": "red",
        "HIGH": "orange1",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "MINIMAL": "green"
    }
    color = level_colors.get(threat_level, "white")
    
    # Display summary panel
    summary_text = f"""
    [bold]Threat Level:[/bold] [{color}]{threat_level}[/{color}]
    [bold]Confidence Score:[/bold] {confidence}%
    [bold]Is Threat:[/bold] {'⚠️  YES' if summary.get('is_threat') else '✅ NO'}
    
    [bold]Recommendation:[/bold]
    {summary.get('recommendation', 'N/A')}
    """
    
    console.print(Panel(summary_text, title="📊 Analysis Summary", border_style=color))
    
    # Detailed results
    if verbose or summary.get("is_threat"):
        console.print("\n[bold]Detailed Results:[/bold]\n")
        
        # AbuseIPDB
        abuseipdb = result.get("sources", {}).get("abuseipdb", {})
        if not abuseipdb.get("error"):
            table = Table(title="AbuseIPDB Results", show_header=True, header_style="bold magenta")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="green")
            
            table.add_row("Abuse Score", f"{abuseipdb.get('abuse_confidence_score', 0)}%")
            table.add_row("Country", abuseipdb.get('country', 'Unknown'))
            table.add_row("ISP", abuseipdb.get('isp', 'Unknown'))
            table.add_row("Total Reports", str(abuseipdb.get('total_reports', 0)))
            table.add_row("Is Whitelisted", str(abuseipdb.get('is_whitelisted', False)))
            
            console.print(table)
            console.print()
        
        # VirusTotal
        virustotal = result.get("sources", {}).get("virustotal", {})
        if not virustotal.get("error"):
            table = Table(title="VirusTotal Results", show_header=True, header_style="bold magenta")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="green")
            
            table.add_row("Malicious Votes", str(virustotal.get('malicious_votes', 0)))
            table.add_row("Suspicious Votes", str(virustotal.get('suspicious_votes', 0)))
            table.add_row("Harmless Votes", str(virustotal.get('harmless_votes', 0)))
            table.add_row("Total Scanners", str(virustotal.get('total_scanners', 0)))
            table.add_row("Detection Rate", f"{virustotal.get('malicious_percentage', 0):.1f}%")
            
            console.print(table)
    
    # Generate report if requested
    if report:
        generator = ReportGenerator()
        report_path = generator.generate_report(result, report)
        console.print(f"\n[bold green]✅ Report saved: {report_path}[/bold green]")


@cli.command()
@click.argument('file_hash')
@click.option('--report', '-r', type=click.Choice(['json', 'html', 'txt']), 
              help='Generate report in specified format')
def check_hash(file_hash, report):
    """
    Check file hash against malware databases
    
    Example: python -m src.main check-hash <sha256_hash>
    """
    console.print(f"\n[bold cyan]🔍 Checking File Hash: {file_hash}[/bold cyan]\n")
    
    checker = HashChecker()
    
    with console.status("[bold green]Querying malware databases..."):
        result = checker.check_hash_virustotal(file_hash)
    
    # Display results
    if result.get("error"):
        console.print(f"[bold red]❌ Error: {result['error']}[/bold red]")
        return
    
    if result.get("message"):
        console.print(f"[bold yellow]ℹ️  {result['message']}[/bold yellow]")
        return
    
    # Summary
    is_malware = result.get("is_malware", False)
    threat_level = result.get("threat_level", "UNKNOWN")
    detection_rate = result.get("detection_rate", "0/0")
    
    color = "red" if is_malware else "green"
    
    summary_text = f"""
    [bold]File Name:[/bold] {result.get('file_name', 'Unknown')}
    [bold]Hash Type:[/bold] {result.get('hash_type', 'Unknown')}
    [bold]Threat Level:[/bold] [{color}]{threat_level}[/{color}]
    [bold]Detection Rate:[/bold] {detection_rate}
    [bold]Is Malware:[/bold] {'⚠️  YES' if is_malware else '✅ NO'}
    """
    
    console.print(Panel(summary_text, title="📊 Hash Analysis", border_style=color))
    
    # Generate report if requested
    if report:
        generator = ReportGenerator()
        report_path = generator.generate_report(result, report)
        console.print(f"\n[bold green]✅ Report saved: {report_path}[/bold green]")


@cli.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--report', '-r', type=click.Choice(['json', 'html', 'txt']), 
              help='Generate report in specified format')
def scan_file(file_path, report):
    """
    Scan a file: calculate hash and check against malware databases
    
    Example: python -m src.main scan-file suspicious_file.exe
    """
    console.print(f"\n[bold cyan]🔍 Scanning File: {file_path}[/bold cyan]\n")
    
    checker = HashChecker()
    
    with console.status("[bold green]Calculating hashes and checking databases..."):
        result = checker.analyze_file(file_path)
    
    if result.get("error"):
        console.print(f"[bold red]❌ Error: {result['error']}[/bold red]")
        return
    
    # Display hashes
    hashes = result.get("hashes", {})
    console.print("[bold]File Hashes:[/bold]")
    console.print(f"  SHA256: {hashes.get('sha256', 'N/A')}")
    console.print(f"  SHA1:   {hashes.get('sha1', 'N/A')}")
    console.print(f"  MD5:    {hashes.get('md5', 'N/A')}\n")
    
    # Display analysis
    analysis = result.get("analysis", {})
    if analysis.get("message"):
        console.print(f"[bold yellow]ℹ️  {analysis['message']}[/bold yellow]")
    elif not analysis.get("error"):
        is_malware = analysis.get("is_malware", False)
        threat_level = analysis.get("threat_level", "UNKNOWN")
        color = "red" if is_malware else "green"
        
        summary_text = f"""
        [bold]Threat Level:[/bold] [{color}]{threat_level}[/{color}]
        [bold]Detection Rate:[/bold] {analysis.get('detection_rate', '0/0')}
        [bold]Is Malware:[/bold] {'⚠️  YES' if is_malware else '✅ NO'}
        """
        
        console.print(Panel(summary_text, title="📊 Scan Results", border_style=color))
    
    # Generate report if requested
    if report:
        generator = ReportGenerator()
        report_path = generator.generate_report(result, report)
        console.print(f"\n[bold green]✅ Report saved: {report_path}[/bold green]")


@cli.command()
def info():
    """Display system information and configuration"""
    config = Config()
    
    info_text = f"""
    [bold cyan]🔒 Threat Intelligence System v1.0.0[/bold cyan]
    
    [bold]Configuration:[/bold]
    • Data Directory: {config.DATA_DIR}
    • Reports Directory: {config.REPORTS_DIR}
    • IP Reputation Threshold: {config.IP_REPUTATION_THRESHOLD}%
    • Cache Duration: {config.CACHE_DURATION}s
    
    [bold]API Status:[/bold]
    • AbuseIPDB: {'✅ Configured' if config.ABUSEIPDB_API_KEY else '❌ Not configured'}
    • VirusTotal: {'✅ Configured' if config.VIRUSTOTAL_API_KEY else '❌ Not configured'}
    
    [bold]Commands:[/bold]
    • check-ip <ip>       - Analyze IP address
    • check-hash <hash>   - Check file hash
    • scan-file <path>    - Scan a file
    • info                - Show this information
    """
    
    console.print(Panel(info_text, title="System Information", border_style="cyan"))


if __name__ == "__main__":
    cli()