#!/usr/bin/env python3
"""
Password Strength Auditor - Main CLI Entry Point

A comprehensive password security tool that evaluates password strength,
checks breach status via HaveIBeenPwned API, and generates secure passwords.

Enhanced with Rich for beautiful terminal output.
"""

import argparse
import asyncio
import getpass
import json
import sys
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, track
from rich.text import Text
from rich.layout import Layout
from rich import box

from breach_checker import (
    check_pwned,
    format_breach_result,
    check_pwned_batch,
    DEFAULT_MAX_CONCURRENT
)
from password_evaluator import (
    evaluate_password_strength,
    format_strength_result,
    is_password_strong,
    MIN_LENGTH,
    PasswordStrengthResult
)
from password_generator import (
    generate_secure_password,
    generate_passphrase,
    calculate_entropy,
    get_password_strength_rating
)


console = Console()


def print_banner():
    """Print beautiful application banner."""
    banner = Text()
    banner.append("╔═══════════════════════════════════════════════════════════╗\n", style="cyan")
    banner.append("║           🔐 PASSWORD STRENGTH AUDITOR 🔐                ║\n", style="bold cyan")
    banner.append("║                                                           ║\n", style="cyan")
    banner.append("║   ", style="cyan")
    banner.append("Evaluate", style="bold green")
    banner.append(" • ", style="cyan")
    banner.append("Generate", style="bold yellow")
    banner.append(" • ", style="cyan")
    banner.append("Secure", style="bold red")
    banner.append("                            ║\n", style="cyan")
    banner.append("╚═══════════════════════════════════════════════════════════╝", style="cyan")
    console.print(banner)
    console.print()


def display_strength_panel(result: PasswordStrengthResult):
    """Display password strength in a rich panel."""
    # Determine color based on score
    colors = {
        0: "red",
        1: "red",
        2: "yellow",
        3: "green",
        4: "bright_green"
    }
    color = colors.get(result.score, "white")
    
    # Create strength table
    table = Table(show_header=False, box=box.ROUNDED, border_style=color)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("Strength", f"[bold {color}]{result.strength_label}[/] (Score: {result.score}/4)")
    table.add_row("Entropy", f"{result.entropy:.1f} bits")
    table.add_row("Crack Time", result.crack_time_display)
    
    if result.warning:
        table.add_row("Warning", f"[bold red]{result.warning}[/]")
    
    panel = Panel(
        table,
        title="[bold]Password Analysis[/]",
        border_style=color,
        padding=(1, 2)
    )
    console.print(panel)


def display_suggestions(result: PasswordStrengthResult):
    """Display suggestions in a rich panel."""
    if not result.feedback:
        return
    
    suggestions_text = "\n".join(f"• {s}" for s in result.feedback)
    
    panel = Panel(
        suggestions_text,
        title="[bold yellow]💡 Improvement Suggestions[/]",
        border_style="yellow",
        padding=(1, 2)
    )
    console.print(panel)


def display_breach_panel(count: Optional[int]):
    """Display breach check results in a rich panel."""
    if count is None:
        content = "[yellow]⚠️ Could not check breaches at this time.[/]"
        border_color = "yellow"
        title = "Breach Check - Unknown"
    elif count > 0:
        content = f"[bold red]🚨 DANGER![/] This password appeared in [bold red]{count:,}[/] known breaches.\n\n[red]NEVER use this password![/]"
        border_color = "red"
        title = "Breach Check - COMPROMISED"
    else:
        content = "[bold green]✅ This password has NOT been found in known public breaches.[/]"
        border_color = "green"
        title = "Breach Check - Safe"
    
    panel = Panel(
        content,
        title=f"[bold]{title}[/]",
        border_style=border_color,
        padding=(1, 2)
    )
    console.print(panel)


def display_final_status(is_strong: bool, is_safe: bool):
    """Display final status panel."""
    if is_strong and is_safe:
        content = "[bold green]✅ PASSWORD STATUS: SECURE[/]\n\nThis password is strong and has not been breached."
        border_color = "green"
    elif is_strong and not is_safe:
        content = "[bold red]❌ PASSWORD STATUS: COMPROMISED[/]\n\nPassword is strong but has been leaked. Do not use!"
        border_color = "red"
    elif not is_strong and is_safe:
        content = "[bold yellow]⚠️ PASSWORD STATUS: WEAK[/]\n\nPassword has not been breached but is too weak."
        border_color = "yellow"
    else:
        content = "[bold red]❌ PASSWORD STATUS: INSECURE[/]\n\nPassword is weak AND has been compromised!"
        border_color = "red"
    
    panel = Panel(
        content,
        border_style=border_color,
        padding=(1, 2)
    )
    console.print(panel)


def check_single_password(password: str, verbose: bool = True) -> bool:
    """
    Check a single password for strength and breaches.
    
    Args:
        password: Password to check
        verbose: Whether to print detailed output
    
    Returns:
        True if password is strong and not breached
    """
    # Evaluate strength
    result = evaluate_password_strength(password)
    
    if verbose:
        console.print()
        display_strength_panel(result)
        
        if result.feedback:
            display_suggestions(result)
    
    # Check breach status with spinner
    if verbose:
        console.print()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True
        ) as progress:
            progress.add_task(description="Checking breach databases...", total=None)
            pwned_count = check_pwned(password)
    else:
        pwned_count = check_pwned(password)
    
    if verbose:
        display_breach_panel(pwned_count)
    
    # Determine overall status
    is_strong = result.score >= 3
    is_safe = pwned_count == 0
    
    if verbose:
        console.print()
        display_final_status(is_strong, is_safe)
    
    return is_strong and is_safe


def interactive_mode():
    """Run interactive password checking loop."""
    print_banner()
    console.print("[dim]Enter passwords to check (press Enter without input to exit):[/]\n")
    
    while True:
        try:
            password = getpass.getpass("Password: ")
            
            if not password:
                console.print("\n[green]Exiting. Stay secure! 🔒[/]")
                break
            
            check_single_password(password, verbose=True)
            console.print()  # Empty line for readability
            
        except KeyboardInterrupt:
            console.print("\n\n[green]Exiting. Stay secure! 🔒[/]")
            break
        except EOFError:
            console.print("\n\n[green]Exiting. Stay secure! 🔒[/]")
            break


def generate_password_cli(
    length: int = 16,
    use_special: bool = True,
    passphrase_mode: bool = False
):
    """
    Generate and display a secure password with rich formatting.
    
    Args:
        length: Password length (or word count for passphrase)
        use_special: Include special characters
        passphrase_mode: Generate passphrase instead of random password
    """
    print_banner()
    
    # Create generation table
    table = Table(show_header=False, box=box.DOUBLE_EDGE, border_style="cyan")
    table.add_column("Type", style="cyan")
    table.add_column("Value", style="white")
    
    if passphrase_mode:
        # Generate passphrase
        password = generate_passphrase(
            num_words=length,
            separator="-",
            capitalize=True,
            add_number=True
        )
        table.add_row("Type", f"[bold]Passphrase[/] ({length} words)")
    else:
        # Generate random password
        password = generate_secure_password(
            length=length,
            use_uppercase=True,
            use_lowercase=True,
            use_digits=True,
            use_special=use_special,
            avoid_ambiguous=True,
            min_each_type=1
        )
        table.add_row("Type", f"[bold]Password[/] ({length} chars)")
    
    table.add_row("Generated", f"[bold green]{password}[/]")
    
    # Calculate entropy
    entropy = calculate_entropy(password)
    rating = get_password_strength_rating(entropy)
    
    table.add_row("Entropy", f"{entropy:.1f} bits")
    table.add_row("Rating", f"[bold green]{rating}[/]")
    
    if not passphrase_mode:
        result = evaluate_password_strength(password)
        table.add_row("zxcvbn Score", f"[bold]{result.score}/4[/] ({result.strength_label})")
        table.add_row("Crack Time", result.crack_time_display)
    
    panel = Panel(
        table,
        title="[bold cyan]🔐 Secure Password Generator[/]",
        border_style="cyan",
        padding=(1, 2)
    )
    console.print(panel)
    
    # Security tips
    tips = Table(show_header=False, box=box.ROUNDED, border_style="yellow")
    tips.add_column("Tips", style="yellow")
    tips.add_row("💡 Copy this password to a secure password manager!")
    tips.add_row("⚠️  Never share or store passwords in plain text.")
    
    console.print(tips)


def batch_check_passwords(
    file_path: Path,
    verbose: bool = True,
    export_path: Optional[Path] = None,
    export_format: str = "json",
    max_concurrent: int = DEFAULT_MAX_CONCURRENT
) -> List[dict]:
    """
    Check multiple passwords from a file.
    
    Uses asynchronous API calls to check passwords concurrently for
    significantly improved performance on large-scale audits.
    
    Args:
        file_path: Path to file containing passwords (one per line)
        verbose: Whether to display progress
        export_path: Optional path to export results
        export_format: Export format ("json" or "csv")
        max_concurrent: Maximum concurrent API calls (default: 10)
    
    Returns:
        List of result dictionaries
    
    Raises:
        FileNotFoundError: If file doesn't exist
        PermissionError: If file cannot be read
    """
    # Read passwords from file
    if not file_path.exists():
        console.print(f"[red]❌ Error: File '{file_path}' not found.[/]")
        sys.exit(1)
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            passwords = [line.strip() for line in f if line.strip()]
    except PermissionError:
        console.print(f"[red]❌ Error: Cannot read file '{file_path}'.[/]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]❌ Error reading file: {e}[/]")
        sys.exit(1)
    
    if not passwords:
        console.print("[yellow]⚠️  No passwords found in file.[/]")
        return []
    
    print_banner()
    console.print(f"[cyan]📁 Checking {len(passwords)} password(s) from '{file_path}'...[/]")
    console.print(f"[dim]Using async processing with max {max_concurrent} concurrent requests[/]\n")
    
    # Step 1: Evaluate strength (CPU-bound, synchronous)
    strength_results = {}
    for password in track(
        passwords,
        description="Evaluating strength...",
        console=console
    ):
        strength_results[password] = evaluate_password_strength(password)
    
    # Step 2: Check breaches asynchronously (IO-bound)
    console.print()
    
    async def run_async_checks():
        """Run async breach checks with progress."""
        results = {}
        
        def update_progress(current, total):
            """Update progress display."""
            if verbose:
                console.print(
                    f"[dim]Checking breaches... {current}/{total} complete[/]",
                    end="\r"
                )
        
        breach_results = await check_pwned_batch(
            passwords,
            max_concurrent=max_concurrent
        )
        
        for pwd, count in breach_results:
            results[pwd] = count
        
        if verbose:
            console.print(" " * 50, end="\r")  # Clear progress line
        
        return results
    
    # Run async breach checking
    breach_results = asyncio.run(run_async_checks())
    
    # Compile final results
    results = []
    for password in passwords:
        strength_result = strength_results[password]
        pwned_count = breach_results.get(password)
        
        # Determine status
        is_strong = strength_result.score >= 3
        is_safe = pwned_count == 0
        is_secure = is_strong and is_safe
        
        result = {
            "password": password,
            "strength_score": strength_result.score,
            "strength_label": strength_result.strength_label,
            "entropy": round(strength_result.entropy, 1),
            "crack_time": strength_result.crack_time_display,
            "breach_count": pwned_count,
            "is_strong": is_strong,
            "is_safe": is_safe,
            "is_secure": is_secure,
            "warning": strength_result.warning,
            "feedback": strength_result.feedback
        }
        results.append(result)
    
    # Display summary table
    if verbose:
        display_batch_results(results)
    
    # Export results if requested
    if export_path:
        export_results(results, export_path, export_format)
    
    return results


def display_batch_results(results: List[dict]):
    """Display batch processing results in a summary table."""
    # Summary table
    secure_count = sum(1 for r in results if r["is_secure"])
    strong_count = sum(1 for r in results if r["is_strong"])
    safe_count = sum(1 for r in results if r["is_safe"])
    breached_count = sum(1 for r in results if r["breach_count"] and r["breach_count"] > 0)
    
    console.print()
    
    # Create summary panel
    summary = Table(show_header=False, box=box.ROUNDED, border_style="cyan")
    summary.add_column("Metric", style="cyan")
    summary.add_column("Value", style="white")
    
    summary.add_row("Total Checked", str(len(results)))
    summary.add_row("✅ Secure", f"[green]{secure_count}[/]")
    summary.add_row("💪 Strong (score ≥3)", f"[green]{strong_count}[/]")
    summary.add_row("🔒 Not Breached", f"[green]{safe_count}[/]")
    summary.add_row("🚨 Breached", f"[red]{breached_count}[/]")
    
    panel = Panel(
        summary,
        title="[bold cyan]📊 Batch Analysis Summary[/]",
        border_style="cyan",
        padding=(1, 2)
    )
    console.print(panel)
    
    # Detailed results table
    console.print("\n[bold]Detailed Results:[/]")
    
    details = Table(
        show_header=True,
        header_style="bold cyan",
        box=box.SIMPLE_HEAVY,
        border_style="cyan"
    )
    details.add_column("#", style="dim", justify="right")
    details.add_column("Password", style="yellow", max_width=30, no_wrap=True)
    details.add_column("Score", justify="center")
    details.add_column("Strength", min_width=10)
    details.add_column("Breaches", justify="right")
    details.add_column("Status", justify="center")
    
    for i, result in enumerate(results, 1):
        # Truncate password for display
        pwd_display = result["password"][:25] + "..." if len(result["password"]) > 28 else result["password"]
        
        # Score with color
        score_color = {
            0: "red",
            1: "red",
            2: "yellow",
            3: "green",
            4: "bright_green"
        }.get(result["strength_score"], "white")
        
        score_display = f"[{score_color}]{result['strength_score']}/4[/]"
        
        # Status indicator
        if result["is_secure"]:
            status = "[green]✅ SECURE[/]"
        elif not result["is_strong"] and not result["is_safe"]:
            status = "[red]❌ INSECURE[/]"
        elif not result["is_strong"]:
            status = "[yellow]⚠️ WEAK[/]"
        else:
            status = "[red]🚨 BREACHED[/]"
        
        # Breach count
        if result["breach_count"] is None:
            breach_display = "[yellow]?[/]"
        elif result["breach_count"] > 0:
            breach_display = f"[red]{result['breach_count']:,}[/]"
        else:
            breach_display = "[green]0[/]"
        
        details.add_row(
            str(i),
            pwd_display,
            score_display,
            result["strength_label"],
            breach_display,
            status
        )
    
    console.print(details)
    
    # Recommendations
    insecure_passwords = [r for r in results if not r["is_secure"]]
    if insecure_passwords:
        console.print("\n[bold yellow]⚠️  Recommendations:[/]")
        for r in insecure_passwords:
            pwd = r["password"][:20] + "..." if len(r["password"]) > 23 else r["password"]
            if r["breach_count"] and r["breach_count"] > 0:
                console.print(f"  • [yellow]{pwd}[/] - {r['strength_label']} (Breached {r['breach_count']:,} times)")
            else:
                console.print(f"  • [yellow]{pwd}[/] - {r['strength_label']}")


def export_results(results: List[dict], export_path: Path, format_type: str):
    """
    Export batch results to file.
    
    Args:
        results: List of result dictionaries
        export_path: Path to export file
        format_type: "json" or "csv"
    """
    try:
        if format_type.lower() == "json":
            # Export as JSON (exclude actual passwords for security)
            export_data = {
                "summary": {
                    "total_checked": len(results),
                    "secure_count": sum(1 for r in results if r["is_secure"]),
                    "strong_count": sum(1 for r in results if r["is_strong"]),
                    "safe_count": sum(1 for r in results if r["is_safe"])
                },
                "results": [
                    {
                        "password_id": i + 1,
                        "password_length": len(r["password"]),
                        "strength_score": r["strength_score"],
                        "strength_label": r["strength_label"],
                        "entropy": r["entropy"],
                        "crack_time": r["crack_time"],
                        "breach_count": r["breach_count"],
                        "is_secure": r["is_secure"],
                        "feedback": r["feedback"]
                    }
                    for i, r in enumerate(results)
                ]
            }
            
            with open(export_path, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            console.print(f"\n[green]✅ Results exported to: {export_path}[/]")
            
        elif format_type.lower() == "csv":
            # Export as CSV
            import csv
            
            with open(export_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "ID", "Password Length", "Strength Score", "Strength Label",
                    "Entropy (bits)", "Crack Time", "Breach Count", "Is Secure"
                ])
                
                for i, r in enumerate(results, 1):
                    writer.writerow([
                        i,
                        len(r["password"]),
                        r["strength_score"],
                        r["strength_label"],
                        r["entropy"],
                        r["crack_time"],
                        r["breach_count"] if r["breach_count"] is not None else "N/A",
                        "Yes" if r["is_secure"] else "No"
                    ])
            
            console.print(f"\n[green]✅ Results exported to: {export_path}[/]")
            
        else:
            console.print(f"[yellow]⚠️  Unknown export format: {format_type}[/]")
            
    except Exception as e:
        console.print(f"[red]❌ Error exporting results: {e}[/]")


def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(
        description="Password Strength Auditor - Evaluate and generate secure passwords",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          Run interactive mode
  %(prog)s -p "myPassword123!"      Check a specific password
  %(prog)s --generate               Generate a secure 16-char password
  %(prog)s --generate --length 20   Generate a 20-character password
  %(prog)s --passphrase             Generate a 4-word passphrase
  %(prog)s --passphrase -l 6        Generate a 6-word passphrase
  %(prog)s --batch passwords.txt    Check multiple passwords from file
  %(prog)s --batch passwords.txt --export results.json
        """
    )
    
    parser.add_argument(
        "-p", "--password",
        help="Password to check (if not provided, enters interactive mode)"
    )
    
    parser.add_argument(
        "-g", "--generate",
        action="store_true",
        help="Generate a secure password instead of checking"
    )
    
    parser.add_argument(
        "--passphrase",
        action="store_true",
        help="Generate a passphrase (word-based password)"
    )
    
    parser.add_argument(
        "-l", "--length",
        type=int,
        default=16,
        help="Password length or word count (default: 16 chars / 4 words)"
    )
    
    parser.add_argument(
        "--no-special",
        action="store_true",
        help="Exclude special characters from generated password"
    )
    
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Minimal output (useful for scripts)"
    )
    
    parser.add_argument(
        "-b", "--batch",
        type=Path,
        metavar="FILE",
        help="Check multiple passwords from file (one per line)"
    )
    
    parser.add_argument(
        "--export",
        type=Path,
        metavar="FILE",
        help="Export batch results to file (JSON or CSV format)"
    )
    
    parser.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        help="Export format for batch results (default: json)"
    )
    
    parser.add_argument(
        "--max-concurrent",
        type=int,
        default=DEFAULT_MAX_CONCURRENT,
        metavar="N",
        help=f"Maximum concurrent API calls for batch processing (default: {DEFAULT_MAX_CONCURRENT})"
    )
    
    args = parser.parse_args()
    
    # Handle batch processing first
    if args.batch:
        results = batch_check_passwords(
            file_path=args.batch,
            verbose=not args.quiet,
            export_path=args.export,
            export_format=args.format,
            max_concurrent=args.max_concurrent
        )
        # Exit with error code if any password is not secure
        all_secure = all(r["is_secure"] for r in results) if results else True
        sys.exit(0 if all_secure else 1)
    
    # Handle password generation
    if args.generate or args.passphrase:
        generate_password_cli(
            length=args.length,
            use_special=not args.no_special,
            passphrase_mode=args.passphrase
        )
        return
    
    # Handle single password check
    if args.password:
        is_secure = check_single_password(args.password, verbose=not args.quiet)
        sys.exit(0 if is_secure else 1)
    
    # Default: interactive mode
    interactive_mode()


if __name__ == "__main__":
    main()