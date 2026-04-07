"""
Risk Scorer — produces a 0–100 risk score for a repo based on:
  - Repo health signals (archived, stale, no security policy)
  - Branch protection configuration
  - Secrets found
  - CVE counts and severity
  - Maintainability signals
"""

from datetime import datetime, timezone
from typing import Dict, Any, Optional

from gsi.config.settings import RiskScoringConfig


# Individual risk signal definitions
RISK_SIGNALS = {
    "is_archived": {
        "label": "Repository is archived",
        "description": "Archived repos receive no security patches",
        "max_score": 15,
    },
    "is_public_with_secrets": {
        "label": "Secrets found in a public repo",
        "description": "Leaked credentials in a public repository",
        "max_score": 30,
    },
    "has_critical_vulns": {
        "label": "Critical CVEs in dependencies",
        "description": "One or more critical CVSS vulnerabilities",
        "max_score": 25,
    },
    "has_high_vulns": {
        "label": "High-severity CVEs",
        "description": "High-severity vulnerabilities detected",
        "max_score": 15,
    },
    "no_branch_protection": {
        "label": "Default branch unprotected",
        "description": "No branch protection rules on the default branch",
        "max_score": 10,
    },
    "no_security_policy": {
        "label": "No SECURITY.md",
        "description": "No responsible disclosure policy found",
        "max_score": 5,
    },
    "stale_repo": {
        "label": "Stale repository",
        "description": "No commits in the past 180 days",
        "max_score": 10,
    },
    "no_dependabot": {
        "label": "No Dependabot / automated updates",
        "description": "No automated dependency update tooling detected",
        "max_score": 5,
    },
    "many_secrets": {
        "label": "Multiple secrets detected",
        "description": "More than 3 distinct secrets found",
        "max_score": 15,
    },
    "secret_in_private": {
        "label": "Secrets in private repo",
        "description": "Secrets committed even in a private repo pose insider risk",
        "max_score": 10,
    },
    "critical_pattern_findings": {
        "label": "Critical code patterns detected",
        "description": "High-risk code patterns like SQL injection or command injection",
        "max_score": 15,
    },
}


class RiskScorer:
    def __init__(self, config: RiskScoringConfig, github_client=None):
        self.config = config
        self.github_client = github_client

    def score(
        self,
        meta: Optional[Dict] = None,
        findings: Optional[Dict] = None,
        repo_name: Optional[str] = None
    ) -> Dict[str, Any]:
        findings = findings or {}
        signals_triggered = []
        total_score = 0

        secrets = findings.get("secrets", [])
        vulns = findings.get("vulnerabilities", [])
        patterns = findings.get("patterns", [])

        is_public = not (meta or {}).get("private", True) if meta else False

        # ── Check each signal ─────────────────────────────────────────────────

        # Archived repo
        if meta and meta.get("archived"):
            pts = RISK_SIGNALS["is_archived"]["max_score"]
            total_score += pts
            signals_triggered.append({**RISK_SIGNALS["is_archived"], "score": pts, "key": "is_archived"})

        # Secrets in public repo
        critical_secrets = [s for s in secrets if s.get("severity") in ("critical", "high")]
        if critical_secrets and is_public:
            pts = RISK_SIGNALS["is_public_with_secrets"]["max_score"]
            total_score += pts
            signals_triggered.append({
                **RISK_SIGNALS["is_public_with_secrets"],
                "score": pts,
                "key": "is_public_with_secrets",
                "detail": f"{len(critical_secrets)} critical/high secrets"
            })
        elif secrets and not is_public:
            pts = RISK_SIGNALS["secret_in_private"]["max_score"]
            total_score += pts
            signals_triggered.append({
                **RISK_SIGNALS["secret_in_private"],
                "score": pts,
                "key": "secret_in_private",
                "detail": f"{len(secrets)} secret(s) found"
            })

        # Multiple secrets
        if len(secrets) > 3:
            pts = min(RISK_SIGNALS["many_secrets"]["max_score"], len(secrets) * 3)
            total_score += pts
            signals_triggered.append({
                **RISK_SIGNALS["many_secrets"],
                "score": pts,
                "key": "many_secrets",
                "detail": f"{len(secrets)} secrets found"
            })

        # Critical CVEs
        critical_vulns = [v for v in vulns if v.get("severity") == "critical"]
        if critical_vulns:
            pts = min(RISK_SIGNALS["has_critical_vulns"]["max_score"], len(critical_vulns) * 5)
            total_score += pts
            signals_triggered.append({
                **RISK_SIGNALS["has_critical_vulns"],
                "score": pts,
                "key": "has_critical_vulns",
                "detail": f"{len(critical_vulns)} critical CVE(s)"
            })

        # High CVEs
        high_vulns = [v for v in vulns if v.get("severity") == "high"]
        if high_vulns:
            pts = min(RISK_SIGNALS["has_high_vulns"]["max_score"], len(high_vulns) * 3)
            total_score += pts
            signals_triggered.append({
                **RISK_SIGNALS["has_high_vulns"],
                "score": pts,
                "key": "has_high_vulns",
                "detail": f"{len(high_vulns)} high CVE(s)"
            })

        # Branch protection
        if meta and self.github_client and repo_name:
            protection = self.github_client.get_branch_protection(repo_name)
            if not protection:
                pts = RISK_SIGNALS["no_branch_protection"]["max_score"]
                total_score += pts
                signals_triggered.append({
                    **RISK_SIGNALS["no_branch_protection"],
                    "score": pts,
                    "key": "no_branch_protection"
                })

        # Security policy
        if meta and self.github_client and repo_name:
            if not self.github_client.has_security_policy(repo_name):
                pts = RISK_SIGNALS["no_security_policy"]["max_score"]
                total_score += pts
                signals_triggered.append({
                    **RISK_SIGNALS["no_security_policy"],
                    "score": pts,
                    "key": "no_security_policy"
                })

        # Stale repo
        if meta and meta.get("pushed_at"):
            try:
                pushed = datetime.fromisoformat(meta["pushed_at"].replace("Z", "+00:00"))
                days_stale = (datetime.now(timezone.utc) - pushed).days
                if days_stale > self.config.stale_days_threshold:
                    pts = RISK_SIGNALS["stale_repo"]["max_score"]
                    total_score += pts
                    signals_triggered.append({
                        **RISK_SIGNALS["stale_repo"],
                        "score": pts,
                        "key": "stale_repo",
                        "detail": f"Last commit {days_stale} days ago"
                    })
            except Exception:
                pass

        # Code pattern signals
        critical_patterns = [p for p in patterns if p.get("severity") in ("critical", "high")]
        if critical_patterns:
            pts = min(RISK_SIGNALS["critical_pattern_findings"]["max_score"], len(critical_patterns) * 3)
            total_score += pts
            signals_triggered.append({
                **RISK_SIGNALS["critical_pattern_findings"],
                "score": pts,
                "key": "critical_pattern_findings",
                "detail": f"{len(critical_patterns)} critical/high pattern(s)"
            })

        # Cap at 100
        final_score = min(100, total_score)
        grade = self._grade(final_score)

        return {
            "score": final_score,
            "grade": grade,
            "label": self._label(grade),
            "signals": signals_triggered,
            "summary": {
                "secret_count": len(secrets),
                "vuln_count": len(vulns),
                "critical_vuln_count": len(critical_vulns),
                "pattern_count": len(patterns),
                "is_public": is_public,
            }
        }

    @staticmethod
    def _grade(score: int) -> str:
        if score >= 75:
            return "F"
        if score >= 50:
            return "D"
        if score >= 30:
            return "C"
        if score >= 15:
            return "B"
        return "A"

    @staticmethod
    def _label(grade: str) -> str:
        return {
            "A": "Low Risk",
            "B": "Moderate Risk",
            "C": "Elevated Risk",
            "D": "High Risk",
            "F": "Critical Risk"
        }.get(grade, "Unknown")
