"""
Pattern Scanner — detects security anti-patterns in source code.

Covers:
  - SQL injection risks
  - Command injection
  - Weak/broken cryptography
  - Insecure HTTP usage
  - Debug code left in production
  - eval() usage
  - Path traversal risks
  - Insecure deserialization
  - SSRF / XSRF risks
"""

import re
import fnmatch
from pathlib import Path
from typing import List, Dict, Any

from gsi.config.settings import PatternScanConfig


# ── Pattern library ───────────────────────────────────────────────────────────
# Each check: pattern (regex), severity, description, fix advice, languages

PATTERN_CHECKS = {
    "sql_injection_risk": {
        "patterns": [
            r'(?i)(execute|query|cursor\.execute)\s*\(\s*[f"\'](.*?)(SELECT|INSERT|UPDATE|DELETE|DROP)',
            r'(?i)"SELECT.+\+\s*\w+',
            r'(?i)f"(SELECT|INSERT|UPDATE|DELETE).+\{',
            r'(?i)\.format\(.*\)\s*#.*sql',
            r'(?i)raw\s*\(.*%\s*',  # Django raw() with string format
        ],
        "severity": "high",
        "description": "Potential SQL injection — user input concatenated into query",
        "fix": "Use parameterized queries or ORM methods instead of string concatenation",
        "extensions": {".py", ".php", ".rb", ".java", ".js", ".ts"}
    },
    "command_injection_risk": {
        "patterns": [
            r'(?i)(os\.system|subprocess\.call|subprocess\.run|shell=True.*\+)',
            r'(?i)exec\s*\(\s*[f"\'].*\{',
            r'(?i)(popen|shell_exec|exec|system)\s*\(\s*\$',  # PHP
            r'(?i)`[^`]*\$\{',  # Template literal with shell
        ],
        "severity": "critical",
        "description": "Potential command injection — user input passed to shell",
        "fix": "Use subprocess with a list of arguments, never shell=True with user input",
        "extensions": {".py", ".php", ".rb", ".js", ".sh"}
    },
    "weak_crypto": {
        "patterns": [
            r'(?i)(MD5|md5)\s*[\(\.]',
            r'(?i)(SHA1|sha1|sha-1)\s*[\(\.]',
            r'(?i)(DES|3DES|RC4)\s*[\(\.]',
            r'(?i)hashlib\.(md5|sha1)\(',
            r'(?i)Cipher\.DES\b',
            r'(?i)createHash\([\'"]md5[\'"]',
            r'(?i)createHash\([\'"]sha1[\'"]',
        ],
        "severity": "medium",
        "description": "Weak or broken cryptographic algorithm used",
        "fix": "Use SHA-256 or stronger; use bcrypt/argon2 for passwords",
        "extensions": {".py", ".js", ".ts", ".java", ".rb", ".go", ".php"}
    },
    "insecure_http": {
        "patterns": [
            r'http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|example\.com)',
            r'(?i)verify\s*=\s*False',  # SSL verification disabled
            r'(?i)ssl\._create_unverified_context',
            r'(?i)InsecureRequestWarning',
            r'(?i)check_hostname\s*=\s*False',
        ],
        "severity": "medium",
        "description": "Insecure HTTP or disabled SSL/TLS verification",
        "fix": "Use HTTPS; never disable certificate verification in production",
        "extensions": {".py", ".js", ".ts", ".rb", ".go", ".java", ".php"}
    },
    "debug_code_left": {
        "patterns": [
            r'(?i)(pdb\.set_trace|breakpoint\(\)|ipdb\.set_trace)',
            r'(?i)console\.log\(.*(password|token|secret|key|auth)',
            r'(?i)print\(.*(password|token|secret|key|auth)',
            r'(?i)DEBUG\s*=\s*True',
            r'(?i)app\.run\(debug=True\)',
        ],
        "severity": "medium",
        "description": "Debug code or logging of sensitive data detected",
        "fix": "Remove debug statements; never log sensitive values",
        "extensions": {".py", ".js", ".ts", ".rb"}
    },
    "eval_usage": {
        "patterns": [
            r'\beval\s*\(',
            r'(?i)exec\s*\(',
            r'(?i)Function\s*\(',  # JS: new Function(...)
            r'(?i)__import__\s*\(',
        ],
        "severity": "high",
        "description": "Use of eval() / exec() with potentially untrusted input",
        "fix": "Avoid eval(); use safe alternatives like ast.literal_eval() for data",
        "extensions": {".py", ".js", ".ts", ".rb", ".php"}
    },
    "hardcoded_credentials": {
        "patterns": [
            r'(?i)(username|user|login)\s*=\s*[\'"][a-zA-Z0-9_@\.]+[\'"].*\n.*(password|passwd|pwd)\s*=\s*[\'"][^\'"]+[\'"]',
            r'(?i)const\s+(API_KEY|SECRET|TOKEN)\s*=\s*[\'"][a-zA-Z0-9\-_]{10,}[\'"]',
            r'(?i)(PASS|PWD|SECRET)\s*=\s*[\'"][^\'"\s]{6,}[\'"]',
        ],
        "severity": "high",
        "description": "Hardcoded credentials in source code",
        "fix": "Use environment variables or secrets management systems",
        "extensions": {".py", ".js", ".ts", ".java", ".go", ".rb", ".php"}
    },
    "path_traversal_risk": {
        "patterns": [
            r'(?i)(open|read_file|send_file|render_template)\s*\(.*\.\.',
            r'(?i)(open|read_file)\s*\(.*\+.*request\.(args|form|params)',
            r'(?i)\.\./',
        ],
        "severity": "high",
        "description": "Potential path traversal — user input used in file path",
        "fix": "Validate and sanitize file paths; use os.path.realpath() and check prefix",
        "extensions": {".py", ".php", ".rb", ".js", ".java"}
    },
    "insecure_deserialization": {
        "patterns": [
            r'(?i)pickle\.loads?\(',
            r'(?i)yaml\.load\(',   # Should be yaml.safe_load
            r'(?i)marshal\.loads?\(',
            r'(?i)unserialize\(',  # PHP
            r'(?i)ObjectInputStream',  # Java
        ],
        "severity": "high",
        "description": "Insecure deserialization of untrusted data",
        "fix": "Use yaml.safe_load(); avoid pickle for untrusted data; use JSON instead",
        "extensions": {".py", ".php", ".java", ".rb"}
    },
    "ssrf_risk": {
        "patterns": [
            r'(?i)(requests\.get|requests\.post|urllib|httpx\.get)\s*\(.*request\.(args|form|params|GET|POST)',
            r'(?i)(fetch|axios\.get)\s*\(.*req\.(query|body|params)',
        ],
        "severity": "high",
        "description": "Potential SSRF — user input used as URL for server-side request",
        "fix": "Validate URLs against an allowlist; block internal IP ranges",
        "extensions": {".py", ".js", ".ts", ".php", ".rb"}
    },
    "todo_fixme_security": {
        "patterns": [
            r'(?i)#\s*(TODO|FIXME|HACK|XXX).*(auth|security|token|password|secret|vuln|inject|xss|csrf)',
            r'(?i)//\s*(TODO|FIXME|HACK).*(auth|security|token|password|secret)',
        ],
        "severity": "low",
        "description": "Security-related TODO/FIXME left in code",
        "fix": "Address pending security issues before production deployment",
        "extensions": {".py", ".js", ".ts", ".java", ".go", ".rb", ".php"}
    },
    "xxe_risk": {
        "patterns": [
            r'(?i)(etree|ElementTree|lxml).*parse',
            r'(?i)SAXParser',
            r'(?i)DocumentBuilderFactory(?!.*setFeature)',
            r'(?i)XMLReader',
        ],
        "severity": "medium",
        "description": "XML parsing without XXE protection",
        "fix": "Disable external entity processing in XML parsers",
        "extensions": {".py", ".java", ".php", ".rb"}
    }
}

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".mp3", ".zip", ".gz", ".tar", ".pdf",
    ".pyc", ".class", ".so", ".dylib", ".dll", ".exe", ".bin",
    ".min.js", ".min.css"
}


class PatternScanner:
    def __init__(self, config: PatternScanConfig):
        self.config = config
        self._compiled_checks = {}
        for check_name, check in PATTERN_CHECKS.items():
            if check_name in config.checks:
                self._compiled_checks[check_name] = {
                    **check,
                    "regexes": [re.compile(p) for p in check["patterns"]]
                }

    def scan(self, root: Path) -> List[Dict[str, Any]]:
        findings = []
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if self._should_skip(path, root):
                continue
            findings.extend(self._scan_file(path, root))
        return findings

    def _scan_file(self, path: Path, root: Path) -> List[Dict]:
        rel = str(path.relative_to(root))
        ext = path.suffix.lower()
        findings = []

        try:
            content = path.read_text(errors="ignore")
        except Exception:
            return []

        lines = content.splitlines()

        for check_name, check in self._compiled_checks.items():
            # Only scan relevant file types
            if check.get("extensions") and ext not in check["extensions"]:
                continue

            for lineno, line in enumerate(lines, start=1):
                stripped = line.strip()
                # Skip comment-only lines for most checks (except debug/todo)
                if check_name not in ("todo_fixme_security", "debug_code_left"):
                    if stripped.startswith(("#", "//", "/*", "*", "<!--")):
                        continue

                for regex in check["regexes"]:
                    if regex.search(line):
                        findings.append({
                            "type": "pattern",
                            "check": check_name,
                            "severity": check["severity"],
                            "description": check["description"],
                            "fix": check.get("fix", ""),
                            "file": rel,
                            "line": lineno,
                            "context": stripped[:150]
                        })
                        break  # one finding per line per check

        return findings

    def _should_skip(self, path: Path, root: Path) -> bool:
        rel = str(path.relative_to(root))
        # Skip excluded dirs
        for excluded in self.config.exclude_paths:
            if excluded in rel.split("/"):
                return True
            if fnmatch.fnmatch(rel, excluded):
                return True
        # Skip binary/generated files
        if path.suffix.lower() in SKIP_EXTENSIONS:
            return True
        if path.name.endswith(".min.js") or path.name.endswith(".min.css"):
            return True
        # Skip large files
        try:
            if path.stat().st_size > 500_000:
                return True
        except Exception:
            pass
        return False
