"""
Report Generator — formats scan results into console/JSON/HTML/Markdown output.
"""

import json
from datetime import datetime
from typing import List, Dict, Any


SEVERITY_COLORS = {
    "critical": "\033[91m",  # Red
    "high":     "\033[93m",  # Yellow
    "medium":   "\033[94m",  # Blue
    "low":      "\033[37m",  # Gray
}
RESET = "\033[0m"
BOLD  = "\033[1m"


class ReportGenerator:
    def __init__(self, results: List[Dict[str, Any]]):
        self.results = results
        self.generated_at = datetime.utcnow().isoformat() + "Z"

    def generate(self, fmt: str = "console") -> str:
        if fmt == "json":
            return self._json()
        elif fmt == "html":
            return self._html()
        elif fmt == "markdown":
            return self._markdown()
        else:
            return self._console()

    # ── Console ───────────────────────────────────────────────────────────────

    def _console(self) -> str:
        lines = []
        lines.append(f"\n{BOLD}{'='*70}{RESET}")
        lines.append(f"{BOLD}  GitHub Security Intelligence Report{RESET}")
        lines.append(f"  Generated: {self.generated_at}")
        lines.append(f"{'='*70}{RESET}\n")

        total_secrets = total_vulns = total_patterns = 0

        for result in self.results:
            repo = result.get("repo", "unknown")
            error = result.get("error")
            findings = result.get("findings", {})
            risk = result.get("risk_score") or {}

            secrets   = findings.get("secrets", [])
            vulns     = findings.get("vulnerabilities", [])
            patterns  = findings.get("patterns", [])
            total_secrets  += len(secrets)
            total_vulns    += len(vulns)
            total_patterns += len(patterns)

            score = risk.get("score", "N/A")
            grade = risk.get("grade", "?")
            label = risk.get("label", "")

            lines.append(f"{BOLD}┌─ {repo}{RESET}")
            if error:
                lines.append(f"│  ❌ Error: {error}")
            else:
                lines.append(f"│  Risk Score: {BOLD}{score}/100{RESET} [{grade}] {label}")

                # Secrets
                if secrets:
                    lines.append("│")
                    lines.append(f"│  {BOLD}🔑 Secrets ({len(secrets)}){RESET}")
                    for s in secrets[:10]:
                        sev = s.get("severity", "low")
                        col = SEVERITY_COLORS.get(sev, "")
                        lines.append(f"│    {col}[{sev.upper()}]{RESET} {s.get('description')} — {s.get('file')}:{s.get('line') or '?'}")
                        lines.append(f"│           Match: {s.get('match')}")
                    if len(secrets) > 10:
                        lines.append(f"│    ... and {len(secrets)-10} more")

                # Vulnerabilities
                if vulns:
                    lines.append("│")
                    lines.append(f"│  {BOLD}⚠️  Vulnerabilities ({len(vulns)}){RESET}")
                    for v in sorted(vulns, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3}.get(x.get("severity","low"),3))[:10]:
                        sev = v.get("severity", "low")
                        col = SEVERITY_COLORS.get(sev, "")
                        cve = v.get("cve") or v.get("vuln_id", "")
                        fixed = v.get("fixed_in")
                        fix_str = f" → fix: {fixed}" if fixed else ""
                        lines.append(f"│    {col}[{sev.upper()}]{RESET} {v.get('package')}@{v.get('version')} — {cve}{fix_str}")
                        lines.append(f"│           {v.get('title','')[:80]}")
                    if len(vulns) > 10:
                        lines.append(f"│    ... and {len(vulns)-10} more")

                # Patterns
                if patterns:
                    lines.append("│")
                    lines.append(f"│  {BOLD}🐛 Code Patterns ({len(patterns)}){RESET}")
                    for p in sorted(patterns, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3}.get(x.get("severity","low"),3))[:10]:
                        sev = p.get("severity", "low")
                        col = SEVERITY_COLORS.get(sev, "")
                        lines.append(f"│    {col}[{sev.upper()}]{RESET} {p.get('description')} — {p.get('file')}:{p.get('line')}")
                    if len(patterns) > 10:
                        lines.append(f"│    ... and {len(patterns)-10} more")

                # Risk signals
                signals = risk.get("signals", [])
                if signals:
                    lines.append("│")
                    lines.append(f"│  {BOLD}📊 Risk Signals{RESET}")
                    for sig in signals:
                        detail = sig.get("detail", "")
                        detail_str = f" ({detail})" if detail else ""
                        lines.append(f"│    +{sig.get('score',0):2d}pts  {sig.get('label')}{detail_str}")

                if not secrets and not vulns and not patterns:
                    lines.append("│  ✅ No findings — looks clean!")

            lines.append(f"└{'─'*68}\n")

        # Summary
        lines.append(f"{BOLD}Summary{RESET}")
        lines.append(f"  Repos scanned:   {len(self.results)}")
        lines.append(f"  Total secrets:   {total_secrets}")
        lines.append(f"  Total vulns:     {total_vulns}")
        lines.append(f"  Total patterns:  {total_patterns}")
        lines.append("")

        return "\n".join(lines)

    # ── JSON ──────────────────────────────────────────────────────────────────

    def _json(self) -> str:
        return json.dumps({
            "generated_at": self.generated_at,
            "summary": self._summary(),
            "results": self.results
        }, indent=2, default=str)

    # ── Markdown ──────────────────────────────────────────────────────────────

    def _markdown(self) -> str:
        lines = []
        lines.append("# GitHub Security Intelligence Report")
        lines.append(f"_Generated: {self.generated_at}_\n")

        summary = self._summary()
        lines.append("## Summary")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Repos scanned | {summary['total_repos']} |")
        lines.append(f"| Total secrets | {summary['total_secrets']} |")
        lines.append(f"| Total vulnerabilities | {summary['total_vulns']} |")
        lines.append(f"| Total code patterns | {summary['total_patterns']} |")
        lines.append(f"| Critical findings | {summary['critical_count']} |")
        lines.append("")

        for result in self.results:
            repo = result.get("repo", "unknown")
            risk = result.get("risk_score") or {}
            findings = result.get("findings", {})

            lines.append(f"## {repo}")
            lines.append(f"**Risk Score:** {risk.get('score','N/A')}/100 [{risk.get('grade','?')}] {risk.get('label','')}\n")

            secrets = findings.get("secrets", [])
            if secrets:
                lines.append(f"### 🔑 Secrets ({len(secrets)})")
                lines.append("| Severity | Type | File | Line |")
                lines.append("|----------|------|------|------|")
                for s in secrets[:20]:
                    lines.append(f"| {s.get('severity','').upper()} | {s.get('description','')} | `{s.get('file','')}` | {s.get('line') or '?'} |")
                lines.append("")

            vulns = findings.get("vulnerabilities", [])
            if vulns:
                lines.append(f"### ⚠️ Vulnerabilities ({len(vulns)})")
                lines.append("| Severity | Package | Version | CVE | Fix |")
                lines.append("|----------|---------|---------|-----|-----|")
                for v in sorted(vulns, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3}.get(x.get("severity","low"),3))[:20]:
                    lines.append(f"| {v.get('severity','').upper()} | {v.get('package','')} | {v.get('version','')} | {v.get('cve') or ''} | {v.get('fixed_in') or 'N/A'} |")
                lines.append("")

            patterns = findings.get("patterns", [])
            if patterns:
                lines.append(f"### 🐛 Code Patterns ({len(patterns)})")
                lines.append("| Severity | Check | File | Line |")
                lines.append("|----------|-------|------|------|")
                for p in patterns[:20]:
                    lines.append(f"| {p.get('severity','').upper()} | {p.get('description','')} | `{p.get('file','')}` | {p.get('line') or '?'} |")
                lines.append("")

        return "\n".join(lines)

    # ── HTML ──────────────────────────────────────────────────────────────────

    def _html(self) -> str:
        summary = self._summary()
        repo_sections = ""
        for result in self.results:
            repo_sections += self._html_repo(result)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Security Intelligence Report</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; }}
    .header {{ background: linear-gradient(135deg, #161b22, #21262d); padding: 2rem; border-bottom: 1px solid #30363d; }}
    h1 {{ color: #f0f6fc; font-size: 1.8rem; }}
    .subtitle {{ color: #8b949e; margin-top: 0.3rem; }}
    .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; padding: 1.5rem; }}
    .stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; text-align: center; }}
    .stat-card .value {{ font-size: 2rem; font-weight: bold; }}
    .stat-card .label {{ color: #8b949e; font-size: 0.85rem; }}
    .critical {{ color: #f85149; }}
    .high     {{ color: #d29922; }}
    .medium   {{ color: #58a6ff; }}
    .low      {{ color: #8b949e; }}
    .repo {{ margin: 1rem; background: #161b22; border: 1px solid #30363d; border-radius: 10px; overflow: hidden; }}
    .repo-header {{ padding: 1rem 1.5rem; background: #21262d; display: flex; justify-content: space-between; align-items: center; }}
    .repo-name {{ font-size: 1.1rem; font-weight: bold; color: #58a6ff; }}
    .risk-badge {{ padding: 0.3rem 0.8rem; border-radius: 20px; font-weight: bold; font-size: 0.85rem; }}
    .badge-A {{ background: #1a4731; color: #3fb950; }}
    .badge-B {{ background: #2d4a1e; color: #7ee787; }}
    .badge-C {{ background: #3d2b00; color: #d29922; }}
    .badge-D {{ background: #3d1a00; color: #ff7b72; }}
    .badge-F {{ background: #3d0000; color: #f85149; }}
    .section {{ padding: 1rem 1.5rem; border-top: 1px solid #30363d; }}
    .section-title {{ font-weight: bold; margin-bottom: 0.75rem; color: #f0f6fc; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; }}
    th {{ text-align: left; padding: 0.5rem; color: #8b949e; border-bottom: 1px solid #30363d; }}
    td {{ padding: 0.5rem; border-bottom: 1px solid #21262d; }}
    .sev-badge {{ padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; }}
    .sev-critical {{ background: #3d0000; color: #f85149; }}
    .sev-high     {{ background: #3d2500; color: #d29922; }}
    .sev-medium   {{ background: #0d2237; color: #58a6ff; }}
    .sev-low      {{ background: #1c2128; color: #8b949e; }}
    code {{ background: #0d1117; padding: 0.1rem 0.3rem; border-radius: 3px; font-family: monospace; font-size: 0.85rem; }}
    .clean {{ color: #3fb950; padding: 1rem 1.5rem; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>🔍 GitHub Security Intelligence Report</h1>
    <div class="subtitle">Generated {self.generated_at}</div>
  </div>
  <div class="summary">
    <div class="stat-card"><div class="value">{summary['total_repos']}</div><div class="label">Repos Scanned</div></div>
    <div class="stat-card"><div class="value critical">{summary['total_secrets']}</div><div class="label">Secrets Found</div></div>
    <div class="stat-card"><div class="value high">{summary['total_vulns']}</div><div class="label">Vulnerabilities</div></div>
    <div class="stat-card"><div class="value medium">{summary['total_patterns']}</div><div class="label">Code Patterns</div></div>
    <div class="stat-card"><div class="value critical">{summary['critical_count']}</div><div class="label">Critical Findings</div></div>
  </div>
  {repo_sections}
</body>
</html>"""

    def _html_repo(self, result: Dict) -> str:
        repo = result.get("repo", "unknown")
        risk = result.get("risk_score") or {}
        findings = result.get("findings", {})
        grade = risk.get("grade", "?")
        score = risk.get("score", "N/A")
        label = risk.get("label", "")

        secrets_html = self._html_secrets(findings.get("secrets", []))
        vulns_html = self._html_vulns(findings.get("vulnerabilities", []))
        patterns_html = self._html_patterns(findings.get("patterns", []))
        content = secrets_html + vulns_html + patterns_html

        if not content.strip():
            content = '<div class="clean">✅ No findings detected</div>'

        return f"""
  <div class="repo">
    <div class="repo-header">
      <div class="repo-name">📁 {repo}</div>
      <div><span class="risk-badge badge-{grade}">{grade} — {score}/100 — {label}</span></div>
    </div>
    {content}
  </div>"""

    def _html_secrets(self, secrets: List[Dict]) -> str:
        if not secrets:
            return ""
        rows = "".join(
            f"<tr><td><span class='sev-badge sev-{s.get('severity','low')}'>{s.get('severity','').upper()}</span></td>"
            f"<td>{s.get('description','')}</td><td><code>{s.get('file','')}</code></td>"
            f"<td>{s.get('line') or '?'}</td><td><code>{s.get('match','')}</code></td></tr>"
            for s in secrets[:30]
        )
        return f"""<div class="section">
      <div class="section-title">🔑 Secrets ({len(secrets)})</div>
      <table><tr><th>Severity</th><th>Type</th><th>File</th><th>Line</th><th>Match</th></tr>{rows}</table>
    </div>"""

    def _html_vulns(self, vulns: List[Dict]) -> str:
        if not vulns:
            return ""
        sorted_vulns = sorted(vulns, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3}.get(x.get("severity","low"),3))
        rows = "".join(
            f"<tr><td><span class='sev-badge sev-{v.get('severity','low')}'>{v.get('severity','').upper()}</span></td>"
            f"<td>{v.get('package','')}</td><td><code>{v.get('version','')}</code></td>"
            f"<td>{v.get('cve') or v.get('vuln_id','')}</td><td>{v.get('fixed_in') or '—'}</td></tr>"
            for v in sorted_vulns[:30]
        )
        return f"""<div class="section">
      <div class="section-title">⚠️ Vulnerabilities ({len(vulns)})</div>
      <table><tr><th>Severity</th><th>Package</th><th>Version</th><th>CVE</th><th>Fix</th></tr>{rows}</table>
    </div>"""

    def _html_patterns(self, patterns: List[Dict]) -> str:
        if not patterns:
            return ""
        sorted_pats = sorted(patterns, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3}.get(x.get("severity","low"),3))
        rows = "".join(
            f"<tr><td><span class='sev-badge sev-{p.get('severity','low')}'>{p.get('severity','').upper()}</span></td>"
            f"<td>{p.get('description','')}</td><td><code>{p.get('file','')}</code></td>"
            f"<td>{p.get('line') or '?'}</td></tr>"
            for p in sorted_pats[:30]
        )
        return f"""<div class="section">
      <div class="section-title">🐛 Code Patterns ({len(patterns)})</div>
      <table><tr><th>Severity</th><th>Issue</th><th>File</th><th>Line</th></tr>{rows}</table>
    </div>"""

    def _summary(self) -> Dict[str, Any]:
        total_secrets = total_vulns = total_patterns = critical_count = 0
        for r in self.results:
            f = r.get("findings", {})
            secrets  = f.get("secrets", [])
            vulns    = f.get("vulnerabilities", [])
            patterns = f.get("patterns", [])
            total_secrets  += len(secrets)
            total_vulns    += len(vulns)
            total_patterns += len(patterns)
            critical_count += sum(1 for x in (secrets + vulns + patterns) if x.get("severity") == "critical")
        return {
            "total_repos": len(self.results),
            "total_secrets": total_secrets,
            "total_vulns": total_vulns,
            "total_patterns": total_patterns,
            "critical_count": critical_count
        }
