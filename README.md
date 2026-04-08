# gsi — GitHub Security Intelligence

> A personal security gate. Scan before you use. Scan before you push.

[![CI](https://github.com/selvankj/gsi/actions/workflows/ci.yml/badge.svg)](https://github.com/selvankj/gsi/actions)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

```
gsi check .                              # 🔵 scan your repo before pushing
gsi check https://github.com/org/repo   # 🟢 evaluate an external repo
gsi install-hook                         # 🔐 auto-block commits containing secrets
```

---

## Table of Contents

- [Why gsi?](#why-gsi)
- [Install & Quickstart](#install--quickstart)
- [Two Modes](#two-modes)
- [Example Output](#example-output)
- [Git Pre-commit Hook](#git-pre-commit-hook)
- [All CLI Options](#all-cli-options)
- [Suppressing False Positives](#suppressing-false-positives)
- [What Gets Detected](#what-gets-detected)
- [Risk Scoring](#risk-scoring)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

---

## Why gsi?

Two moments where security matters most — and where most developers have no tooling:

1. **Before you push** — Did you accidentally commit an `.env` file, a hardcoded API key, or a token?
2. **Before you use** — Does that open-source dependency have unpatched CVEs? Has it been abandoned?

`gsi` is a single CLI that catches both. Think of it as `npm audit` + `git-secrets` + a trust score, in one command.

---

## Install & Quickstart

**Requires Python 3.9+**

```bash
# Clone your repo (or cd into the unzipped folder)
git clone https://github.com/selvankj/gsi
cd gsi

# Install
pip install -e .

# Verify
gsi --help
```

**No GitHub token needed for local scans.** For scanning remote repos, a token removes rate limits:

```bash
export GITHUB_TOKEN=ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

Generate a token at [github.com/settings/tokens](https://github.com/settings/tokens) — only `public_repo` scope is needed.

---

## Two Modes

### 🔵 Mode 1 — Pre-publish (local)

Scan your own project before `git push`:

```bash
gsi check .
gsi check /path/to/myproject
```

Catches:
- API keys, tokens, passwords, private keys in source files
- `.env` files or credential configs accidentally staged
- Dependencies with known CVEs (checks `requirements.txt`, `package.json`, `go.mod`, and more)
- Insecure code patterns: SQL injection, `eval()`, weak crypto, command injection, SSRF, path traversal…

### 🟢 Mode 2 — Pre-use (remote)

Evaluate an open-source repo before depending on it:

```bash
gsi check https://github.com/some/repo
gsi check owner/repo
gsi check owner/repo --token ghp_XXXX
```

Checks:
- Known CVEs in all declared dependencies (via [OSV.dev](https://osv.dev) — free, no API key needed)
- Secrets accidentally committed to the repo
- Risk signals: archived, stale, no security policy, no branch protection

---

## Example Output

```
──────────────────── gsi security scan ────────────────────
  📁 /Users/me/myproject  (local · secrets · deps · risk)

🔑 Secrets  (2 found)

  Sev         Type                            File             Line
  ──────────  ──────────────────────────────  ───────────────  ────
  🔴 CRIT     Database connection string      .env.local       3
  🟠 HIGH     AWS Access Key ID               config/aws.py    12

⚠️  Vulnerabilities  (1 found)

  Sev         Package    Version    CVE               Fix
  ──────────  ─────────  ─────────  ────────────────  ──────────
  🟠 HIGH     requests   2.18.0     CVE-2018-18074    → 2.20.0

📊 Risk Score  ████████████░░░░░░░░  42/100  [C] Elevated Risk

   +30pts  Secrets found in a public repo (2 critical/high secrets)
   +12pts  High-severity CVEs (4 high CVEs)

───────────────────────────────────────────────────────────
╭──────────────────────────────────────────────────────────╮
│  🚨  UNSAFE                                              │
│  Fix the issues above before pushing — your secrets      │
│  will be exposed.                                        │
╰──────────────────────────────────────────────────────────╯
```

**Verdict levels:**

| Verdict | Meaning |
|---------|---------|
| ✅ **SAFE** | No critical or high findings |
| ⚠️ **CAUTION** | High-severity findings or risk score ≥ 50 |
| 🚨 **UNSAFE** | Critical findings — action required before pushing/using |

---

## Git Pre-commit Hook

Install once per project — every `git commit` will automatically scan for secrets:

```bash
cd my-project
gsi install-hook
```

Now when you commit:

```
$ git commit -m "add payment integration"
🔍 gsi: scanning for secrets before commit...

❌  gsi: Commit BLOCKED — secrets or high-risk findings detected.
    Fix the issues above, or run:  git commit --no-verify  to skip.
```

If the scan is clean:

```
$ git commit -m "fix: update config"
🔍 gsi: scanning for secrets before commit...
✅  gsi: No secrets found — commit allowed.
[main 3a1b2c] fix: update config
```

**Remove the hook at any time:**

```bash
gsi remove-hook
```

**Bypass once** (use sparingly):

```bash
git commit --no-verify -m "your message"
```

---

## All CLI Options

```bash
# ── Targets ────────────────────────────────────────────────────────────────
gsi check .                              # current directory
gsi check /path/to/project               # specific local path
gsi check owner/repo                     # GitHub repo (short form)
gsi check https://github.com/owner/repo  # GitHub repo (full URL)

# ── Modules ────────────────────────────────────────────────────────────────
gsi check . --modules secrets            # secrets only (fastest)
gsi check . --modules deps               # dependency CVEs only
gsi check . --modules secrets,deps       # combine modules
gsi check . --modules all                # everything — default

# ── Filtering ──────────────────────────────────────────────────────────────
gsi check . --min-severity medium        # hide low-severity findings
gsi check . --min-severity high          # only show high + critical

# ── Output ─────────────────────────────────────────────────────────────────
gsi check . --report report.html         # save a full HTML report
gsi check . --quiet                      # verdict + counts only (good for CI)

# ── Remote-specific ────────────────────────────────────────────────────────
gsi check owner/repo --token ghp_XXXX    # provide token explicitly
gsi check owner/repo --no-clone          # use GitHub API only, skip cloning

# ── Hook management ────────────────────────────────────────────────────────
gsi install-hook                         # install in current repo
gsi install-hook /path/to/other/repo     # install in a specific repo
gsi remove-hook                          # remove from current repo
```

**Exit codes** — useful for CI/CD:

| Code | Meaning |
|------|---------|
| `0` | Clean — safe to use or publish |
| `1` | High or critical findings detected |
| `2` | Scan error (bad path, auth failure, etc.) |

**Use in GitHub Actions:**

```yaml
# .github/workflows/security.yml
name: Security Gate
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install -e .
      - run: gsi check . --modules secrets --min-severity medium --quiet
```

---

## Suppressing False Positives

Create a `.gsiignore` file in your project root. A template is included — copy it to get started:

```bash
cp .gsiignore.example .gsiignore
```

**Syntax:**

```
# Ignore an entire file
tests/fixtures/fake_credentials.py

# Ignore a specific line
config/local.py:10

# Ignore a pattern type for paths matching a glob
[secrets] tests/**
[generic_api_key] docs/**
[high_entropy_string] **/*_test.py
```

**Common suppressions to copy-paste:**

```
# Test fixtures with fake/example credentials
[secrets] tests/fixtures/**
[secrets] tests/data/**

# Documentation examples
[secrets] docs/**
[generic_api_key] README.md

# Vendored third-party code
vendor/**
```

---

## What Gets Detected

### 🔑 Secrets

| Category | What's detected |
|----------|----------------|
| **AWS** | Access Key ID (`AKIA…`), Secret Access Key |
| **GCP** | API Key (`AIza…`), Service Account JSON |
| **Azure** | Client secrets |
| **GitHub** | Personal Access Tokens (`ghp_`, `ghs_`, fine-grained PATs) |
| **Payments** | Stripe secret + publishable keys |
| **Comms** | Slack tokens + webhooks, Twilio, SendGrid, Mailgun |
| **Dev tools** | NPM tokens, Heroku API keys, Docker Hub credentials |
| **Crypto** | RSA/EC/SSH private keys, JWTs |
| **Generic** | Database URLs with credentials, high-entropy strings, hardcoded passwords |

Detection uses two methods:
- **Regex patterns** — high-precision matching per credential type
- **Shannon entropy analysis** — catches high-entropy strings that don't match any known pattern

### ⚠️ Dependencies

Powered by [OSV.dev](https://osv.dev) — Google's open CVE database. No API key required.

| Language | Files scanned |
|----------|---------------|
| Python | `requirements.txt`, `Pipfile`, `Pipfile.lock`, `pyproject.toml` |
| Node.js | `package.json`, `package-lock.json`, `yarn.lock` |
| Go | `go.mod`, `go.sum` |
| Ruby | `Gemfile`, `Gemfile.lock` |
| Rust | `Cargo.toml`, `Cargo.lock` |
| Java | `pom.xml` (basic) |

### 🐛 Code Patterns

| Check | What it catches | Severity |
|-------|----------------|----------|
| `command_injection_risk` | `shell=True` + user input, `os.system()` | Critical |
| `sql_injection_risk` | String-concatenated SQL queries | High |
| `eval_usage` | `eval()` / `exec()` with dynamic input | High |
| `insecure_deserialization` | `pickle.loads()`, unsafe `yaml.load()` | High |
| `path_traversal_risk` | User input in file paths | High |
| `ssrf_risk` | User-controlled URLs in HTTP calls | High |
| `weak_crypto` | MD5, SHA1, DES, RC4 | Medium |
| `insecure_http` | Plain HTTP, disabled SSL verification | Medium |
| `debug_code_left` | `pdb`, `console.log(password)`, `DEBUG=True` | Medium |
| `hardcoded_credentials` | Inline username/password assignments | High |
| `xxe_risk` | XML parsers without entity protection | Medium |
| `todo_fixme_security` | Security-related `TODO`/`FIXME` comments | Low |

---

## Risk Scoring

Every scan produces a 0–100 risk score built from weighted signals:

| Signal | Max points |
|--------|-----------|
| Critical secrets in a public repo | 30 |
| Critical CVEs in dependencies | 25 |
| Repository is archived | 15 |
| High-severity CVEs | 15 |
| More than 3 secrets found | 15 |
| Critical code patterns | 15 |
| No branch protection on default branch | 10 |
| Stale repo (no commits in 180+ days) | 10 |
| Secrets found in a private repo | 10 |
| No `SECURITY.md` present | 5 |

**Grade scale:**

| Grade | Score | Label |
|-------|-------|-------|
| A | 0 – 14 | Low Risk |
| B | 15 – 29 | Moderate Risk |
| C | 30 – 49 | Elevated Risk |
| D | 50 – 74 | High Risk |
| F | 75 – 100 | Critical Risk |

---

## Project Structure

```
gsi/
├── gsi/                              # Main Python package
│   ├── __init__.py
│   ├── __main__.py                   # CLI entry point (Typer + Rich)
│   ├── gsiignore.py                  # .gsiignore file parser
│   ├── config/
│   │   └── settings.py               # Configuration dataclasses
│   ├── modules/
│   │   ├── secret_scanner.py         # Regex + entropy secret detection
│   │   ├── dependency_scanner.py     # Manifest parsing + OSV.dev CVE lookup
│   │   ├── risk_scorer.py            # Signal-based risk scoring
│   │   └── pattern_scanner.py        # Code anti-pattern detection
│   ├── scanner/
│   │   └── github_client.py          # GitHub API + git clone helper
│   └── reports/
│       └── report_generator.py       # Console / JSON / HTML / Markdown output
│
├── tests/
│   ├── test_secret_scanner.py        # 20 tests
│   ├── test_risk_scorer.py           # 14 tests
│   └── test_pattern_scanner.py       # 12 tests
│
├── .github/
│   └── workflows/
│       └── ci.yml                    # CI: tests + self-scan on every push
│
├── .gitignore
├── .gsiignore.example                # Copy to .gsiignore to suppress false positives
├── pyproject.toml                    # Package metadata and dependencies
├── CONTRIBUTING.md
└── LICENSE                           # MIT
```

---

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for full details.

The most impactful things to contribute:
- **New secret patterns** — add an entry to `SECRET_PATTERNS` in `gsi/modules/secret_scanner.py`
- **New code checks** — add an entry to `PATTERN_CHECKS` in `gsi/modules/pattern_scanner.py`
- **False positive fixes** — open an issue with the pattern name and a reproduction case
- **New dependency ecosystems** — add a parser to `DependencyScanner._parse_content()`

**Dev setup:**

```bash
git clone https://github.com/selvankj/gsi
cd gsi
pip install -e ".[dev]"
pytest                         # must show 47 passed
gsi check . --modules secrets  # must return SAFE
```

---

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">
  <sub>Built to keep your secrets secret.</sub>
</div>
