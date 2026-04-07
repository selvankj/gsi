#!/usr/bin/env python3
"""
gsi — GitHub Security Intelligence
A personal security gate for repos.

  gsi check .                    # scan local repo before pushing
  gsi check https://github.com/… # scan remote repo before using
  gsi install-hook               # install git pre-commit hook
  gsi remove-hook                # remove the hook
"""

import sys
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

app = typer.Typer(
    name="gsi",
    help="Personal security gate for GitHub repos.",
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()

# ── Lazy imports so CLI stays snappy ─────────────────────────────────────────
def _get_scanners():
    from gsi.modules.secret_scanner import SecretScanner
    from gsi.modules.dependency_scanner import DependencyScanner
    from gsi.modules.risk_scorer import RiskScorer
    from gsi.config.settings import Settings
    s = Settings()
    return SecretScanner(s.secrets), DependencyScanner(s.deps), RiskScorer(s.risk)


# ═══════════════════════════════════════════════════════════════════════════
# gsi check
# ═══════════════════════════════════════════════════════════════════════════

@app.command()
def check(
    target: str = typer.Argument(..., help="Local path (.) or GitHub URL/owner/repo"),
    token: Optional[str] = typer.Option(None, "--token", "-t", envvar="GITHUB_TOKEN",
                                         help="GitHub token (or set GITHUB_TOKEN)"),
    modules: Optional[str] = typer.Option("all", "--modules", "-m",
                                           help="Comma-separated: secrets,deps,risk"),
    min_severity: str = typer.Option("low", "--min-severity",
                                      help="Filter: low | medium | high | critical"),
    report: Optional[str] = typer.Option(None, "--report",
                                          help="Save HTML report to this path"),
    no_clone: bool = typer.Option(False, "--no-clone",
                                   help="Use GitHub API only, skip cloning"),
    quiet: bool = typer.Option(False, "--quiet", "-q",
                                help="Only show verdict and counts"),
):
    """
    Scan a repo for secrets, vulnerabilities, and risk signals.

    \b
    Examples:
      gsi check .                              # local mode
      gsi check https://github.com/org/repo   # remote mode
      gsi check org/repo --token ghp_XXXX
      gsi check . --modules secrets
      gsi check . --report out.html
    """
    enabled = _parse_modules(modules)
    is_remote = _is_remote(target)

    _print_header(target, is_remote, enabled)

    if is_remote:
        result = _run_remote(target, token, enabled, no_clone, quiet)
    else:
        result = _run_local(Path(target).resolve(), enabled, quiet)

    if result is None:
        raise typer.Exit(2)

    _print_result(result, min_severity, quiet)

    if report:
        _write_html_report(result, report)
        console.print(f"\n[dim]📄 HTML report saved to[/dim] [cyan]{report}[/cyan]")

    # Exit code 1 = high/critical findings
    findings = result.get("findings", {})
    all_finds = (
        findings.get("secrets", []) +
        findings.get("vulnerabilities", []) +
        findings.get("patterns", [])
    )
    critical_or_high = any(
        f.get("severity") in ("critical", "high") for f in all_finds
    )
    raise typer.Exit(1 if critical_or_high else 0)


# ═══════════════════════════════════════════════════════════════════════════
# gsi install-hook / remove-hook
# ═══════════════════════════════════════════════════════════════════════════

@app.command("install-hook")
def install_hook(
    path: str = typer.Argument(".", help="Path to the git repo"),
):
    """Install a git pre-commit hook that blocks commits when secrets are found."""
    repo_path = Path(path).resolve()
    git_dir = repo_path / ".git"
    if not git_dir.exists():
        console.print("[red]✗ Not a git repository.[/red]")
        raise typer.Exit(1)

    hook_path = git_dir / "hooks" / "pre-commit"
    gsi_path = Path(sys.argv[0]).resolve()  # path to gsi itself

    hook_script = f"""#!/bin/sh
# gsi pre-commit hook — installed by `gsi install-hook`
echo "🔍 gsi: scanning for secrets before commit..."
{sys.executable} "{gsi_path}" check . --modules secrets --quiet --min-severity medium
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
  echo ""
  echo "❌  gsi: Commit BLOCKED — secrets or high-risk findings detected."
  echo "    Fix the issues above, or run:  git commit --no-verify  to skip."
  echo ""
  exit 1
fi
echo "✅  gsi: No secrets found — commit allowed."
exit 0
"""

    hook_path.parent.mkdir(exist_ok=True)
    hook_path.write_text(hook_script)
    hook_path.chmod(0o755)

    console.print(Panel(
        f"[green bold]✅ Pre-commit hook installed![/green bold]\n\n"
        f"Hook location: [cyan]{hook_path}[/cyan]\n\n"
        f"Every [bold]git commit[/bold] will now scan for secrets.\n"
        f"Commits with [red]medium+[/red] severity findings will be [bold]blocked[/bold].\n\n"
        f"To skip: [dim]git commit --no-verify[/dim]\n"
        f"To remove: [dim]gsi remove-hook[/dim]",
        title="[bold]gsi hook[/bold]",
        border_style="green"
    ))


@app.command("remove-hook")
def remove_hook(
    path: str = typer.Argument(".", help="Path to the git repo"),
):
    """Remove the gsi pre-commit hook."""
    hook_path = Path(path).resolve() / ".git" / "hooks" / "pre-commit"
    if not hook_path.exists():
        console.print("[yellow]No hook found.[/yellow]")
        raise typer.Exit(0)

    content = hook_path.read_text()
    if "gsi" not in content:
        console.print("[yellow]⚠ Hook exists but wasn't installed by gsi — not removing.[/yellow]")
        raise typer.Exit(1)

    hook_path.unlink()
    console.print("[green]✅ gsi pre-commit hook removed.[/green]")


# ═══════════════════════════════════════════════════════════════════════════
# Scan runners
# ═══════════════════════════════════════════════════════════════════════════

def _run_local(path: Path, enabled: set, quiet: bool) -> Optional[dict]:
    if not path.exists():
        console.print(f"[red]✗ Path not found: {path}[/red]")
        return None

    secret_scanner, dep_scanner, risk_scorer = _get_scanners()
    findings = {}

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console, transient=True) as progress:
        if "secrets" in enabled:
            task = progress.add_task("Scanning for secrets…", total=None)
            findings["secrets"] = secret_scanner.scan(local_path=path)
            progress.remove_task(task)

        if "deps" in enabled:
            task = progress.add_task("Checking dependencies…", total=None)
            findings["vulnerabilities"] = dep_scanner.scan(local_path=path)
            progress.remove_task(task)

    risk_result = None
    if "risk" in enabled:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=console, transient=True) as progress:
            task = progress.add_task("Scoring risk…", total=None)
            risk_result = risk_scorer.score(findings=findings)
            progress.remove_task(task)

    return {
        "repo": str(path),
        "mode": "local",
        "findings": findings,
        "risk_score": risk_result,
    }


def _run_remote(target: str, token: Optional[str], enabled: set, no_clone: bool, quiet: bool) -> Optional[dict]:
    from gsi.scanner.github_client import GitHubClient

    repo_name = _parse_repo_name(target)
    if not repo_name:
        console.print(f"[red]✗ Could not parse repo from: {target}[/red]")
        return None

    if not token:
        console.print("[yellow]⚠  No GitHub token — rate limits apply. Set GITHUB_TOKEN or use --token.[/yellow]")

    client = GitHubClient(token=token)
    secret_scanner, dep_scanner, risk_scorer = _get_scanners()
    findings = {}
    meta = None

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console, transient=True) as progress:

        task = progress.add_task("Fetching repo metadata…", total=None)
        try:
            meta = client.get_repo_meta(repo_name)
        except Exception as e:
            console.print(f"[red]✗ Could not fetch repo: {e}[/red]")
            return None
        progress.remove_task(task)

        local_path = None
        if not no_clone and ("secrets" in enabled):
            task = progress.add_task(f"Cloning {repo_name}…", total=None)
            local_path = client.clone_repo(repo_name)
            progress.remove_task(task)

        if "secrets" in enabled:
            task = progress.add_task("Scanning for secrets…", total=None)
            findings["secrets"] = secret_scanner.scan(
                local_path=local_path,
                github_client=client,
                repo_name=repo_name,
                meta=meta
            )
            progress.remove_task(task)

        if "deps" in enabled:
            task = progress.add_task("Checking dependencies…", total=None)
            findings["vulnerabilities"] = dep_scanner.scan(
                local_path=local_path,
                repo_name=repo_name,
                meta=meta
            )
            progress.remove_task(task)

    risk_result = None
    if "risk" in enabled:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=console, transient=True) as progress:
            task = progress.add_task("Scoring risk…", total=None)
            risk_result = risk_scorer.score(
                meta=_safe_meta(meta),
                findings=findings,
                repo_name=repo_name
            )
            progress.remove_task(task)

    return {
        "repo": repo_name,
        "mode": "remote",
        "meta": _safe_meta(meta),
        "findings": findings,
        "risk_score": risk_result,
    }


# ═══════════════════════════════════════════════════════════════════════════
# Output / display
# ═══════════════════════════════════════════════════════════════════════════

SEV_STYLE = {
    "critical": "bold red",
    "high":     "bold yellow",
    "medium":   "bold blue",
    "low":      "dim",
}
SEV_ICON = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "⚪",
}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _print_header(target: str, is_remote: bool, enabled: set):
    mode = "remote" if is_remote else "local"
    icon = "🌐" if is_remote else "📁"
    modules_str = " · ".join(sorted(enabled))
    console.print()
    console.rule("[bold]gsi[/bold] [dim]security scan[/dim]")
    console.print(f"  {icon} [bold]{target}[/bold]  [dim]({mode} · {modules_str})[/dim]")
    console.print()


def _print_result(result: dict, min_severity: str, quiet: bool):
    findings = result.get("findings", {})
    secrets  = _filter_sev(findings.get("secrets", []), min_severity)
    vulns    = _filter_sev(findings.get("vulnerabilities", []), min_severity)
    patterns = _filter_sev(findings.get("patterns", []), min_severity)
    risk     = result.get("risk_score") or {}


    # ── Secrets ───────────────────────────────────────────────────────────
    if secrets:
        console.print(f"[bold red]🔑 Secrets[/bold red]  ({len(secrets)} found)\n")
        t = Table(box=box.SIMPLE, show_header=True, header_style="bold dim",
                  show_edge=False, padding=(0, 1))
        t.add_column("Sev", width=10)
        t.add_column("Type", min_width=28)
        t.add_column("File", min_width=24)
        t.add_column("Line", width=6)
        t.add_column("Match", min_width=16)

        for s in sorted(secrets, key=lambda x: SEV_ORDER.get(x.get("severity","low"), 3)):
            sev = s.get("severity", "low")
            t.add_row(
                Text(f"{SEV_ICON[sev]} {sev.upper()}", style=SEV_STYLE[sev]),
                s.get("description", ""),
                _trim(s.get("file", ""), 30),
                str(s.get("line") or "?"),
                Text(s.get("match", ""), style="dim cyan"),
            )
        console.print(t)
    else:
        console.print("[green]🔑 Secrets[/green]  [dim]none found[/dim]\n")

    # ── Vulnerabilities ───────────────────────────────────────────────────
    if vulns:
        console.print(f"[bold yellow]⚠️  Vulnerabilities[/bold yellow]  ({len(vulns)} found)\n")
        t = Table(box=box.SIMPLE, show_header=True, header_style="bold dim",
                  show_edge=False, padding=(0, 1))
        t.add_column("Sev", width=10)
        t.add_column("Package", min_width=22)
        t.add_column("Version", width=12)
        t.add_column("CVE", width=18)
        t.add_column("Fix", min_width=12)

        for v in sorted(vulns, key=lambda x: SEV_ORDER.get(x.get("severity","low"), 3)):
            sev = v.get("severity", "low")
            fixed = v.get("fixed_in") or "—"
            t.add_row(
                Text(f"{SEV_ICON[sev]} {sev.upper()}", style=SEV_STYLE[sev]),
                v.get("package", ""),
                v.get("version", ""),
                v.get("cve") or v.get("vuln_id", ""),
                Text(f"→ {fixed}", style="green" if fixed != "—" else "dim"),
            )
        console.print(t)
    else:
        console.print("[green]⚠️  Vulnerabilities[/green]  [dim]none found[/dim]\n")

    # ── Code Patterns (only show if local and not quiet) ──────────────────
    if patterns and not quiet:
        console.print(f"[bold blue]🐛 Code Patterns[/bold blue]  ({len(patterns)} found)\n")
        t = Table(box=box.SIMPLE, show_header=True, header_style="bold dim",
                  show_edge=False, padding=(0, 1))
        t.add_column("Sev", width=10)
        t.add_column("Issue", min_width=40)
        t.add_column("File", min_width=24)
        t.add_column("Line", width=6)

        for p in sorted(patterns, key=lambda x: SEV_ORDER.get(x.get("severity","low"), 3))[:20]:
            sev = p.get("severity", "low")
            t.add_row(
                Text(f"{SEV_ICON[sev]} {sev.upper()}", style=SEV_STYLE[sev]),
                p.get("description", ""),
                _trim(p.get("file", ""), 30),
                str(p.get("line") or "?"),
            )
        if len(patterns) > 20:
            console.print(f"  [dim]… and {len(patterns)-20} more[/dim]")
        console.print(t)

    # ── Risk score ────────────────────────────────────────────────────────
    if risk:
        score = risk.get("score", 0)
        grade = risk.get("grade", "?")
        label = risk.get("label", "")
        bar   = _risk_bar(score)
        score_style = "red bold" if score >= 50 else "yellow bold" if score >= 25 else "green bold"
        console.print(f"\n[bold]📊 Risk Score[/bold]  {bar}  [{score_style}]{score}/100[/{score_style}]  [dim][{grade}] {label}[/dim]\n")

        signals = risk.get("signals", [])
        if signals and not quiet:
            for sig in signals:
                detail = f" [dim]({sig.get('detail','')})[/dim]" if sig.get("detail") else ""
                console.print(f"   [dim]+{sig.get('score',0):2d}pts[/dim]  {sig.get('label','')}{detail}")
            console.print()

    # ── Verdict ───────────────────────────────────────────────────────────
    console.rule()
    _print_verdict(secrets, vulns, patterns, risk, result.get("mode","local"))


def _print_verdict(secrets, vulns, patterns, risk, mode):
    critical_secrets  = [s for s in secrets  if s.get("severity") == "critical"]
    high_secrets      = [s for s in secrets  if s.get("severity") == "high"]
    critical_vulns    = [v for v in vulns    if v.get("severity") == "critical"]
    high_vulns        = [v for v in vulns    if v.get("severity") == "high"]
    critical_patterns = [p for p in patterns if p.get("severity") == "critical"]

    score = (risk or {}).get("score", 0)

    if critical_secrets or critical_vulns or critical_patterns:
        icon, colour, label = "🚨", "red",    "UNSAFE"
        if mode == "local":
            advice = "Fix the issues above before pushing — your secrets [bold]will[/bold] be exposed."
        else:
            advice = "Do NOT use this repository — it contains critical security issues."
    elif high_secrets or high_vulns or score >= 50:
        icon, colour, label = "⚠️ ", "yellow", "CAUTION"
        if mode == "local":
            advice = "Resolve high-severity issues before publishing."
        else:
            advice = "Review carefully before using — high-risk signals detected."
    else:
        icon, colour, label = "✅", "green",  "SAFE"
        if mode == "local":
            advice = "No critical issues found. Safe to commit and push."
        else:
            advice = "No critical issues detected. Looks safe to use."

    console.print(
        Panel(
            f"[{colour} bold]{icon}  {label}[/{colour} bold]\n[dim]{advice}[/dim]",
            border_style=colour,
            padding=(0, 2),
        )
    )
    console.print()


# ═══════════════════════════════════════════════════════════════════════════
# HTML report
# ═══════════════════════════════════════════════════════════════════════════

def _write_html_report(result: dict, path: str):
    from gsi.reports.report_generator import ReportGenerator
    gen = ReportGenerator([result])
    html = gen.generate(fmt="html")
    Path(path).write_text(html)


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _is_remote(target: str) -> bool:
    return target.startswith("http") or ("/" in target and not target.startswith(".") and not Path(target).exists())


def _parse_repo_name(target: str) -> Optional[str]:
    """Extract owner/repo from a URL or short form."""
    if target.startswith("http"):
        parsed = urlparse(target)
        parts = parsed.path.strip("/").split("/")
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
    elif "/" in target:
        parts = target.strip("/").split("/")
        if len(parts) == 2:
            return target
    return None


def _parse_modules(modules_str: str) -> set:
    if modules_str == "all":
        return {"secrets", "deps", "risk", "patterns"}
    return set(m.strip() for m in modules_str.split(",") if m.strip())


def _filter_sev(findings: list, min_sev: str) -> list:
    order = ["low", "medium", "high", "critical"]
    threshold = order.index(min_sev) if min_sev in order else 0
    return [f for f in findings if order.index(f.get("severity", "low")) >= threshold]


def _risk_bar(score: int) -> str:
    filled = round(score / 5)
    empty  = 20 - filled
    colour = "red" if score >= 50 else "yellow" if score >= 25 else "green"
    bar    = "█" * filled + "░" * empty
    return f"[{colour}]{bar}[/{colour}]"


def _trim(s: str, max_len: int) -> str:
    return ("…" + s[-(max_len-1):]) if len(s) > max_len else s


def _safe_meta(meta: Optional[dict]) -> Optional[dict]:
    if not meta:
        return None
    return {
        "full_name": meta.get("full_name"),
        "private":   meta.get("private"),
        "archived":  meta.get("archived"),
        "pushed_at": meta.get("pushed_at"),
        "stars":     meta.get("stargazers_count"),
        "language":  meta.get("language"),
        "html_url":  meta.get("html_url"),
    }


# ═══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    # Allow running as: python gsi.py check .
    app()
