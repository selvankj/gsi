# gsi Setup Guide

Step-by-step instructions to upload this project to GitHub and get it running.

---

## Prerequisites

- Python 3.9 or later — check with `python --version`
- Git installed — check with `git --version`
- A GitHub account

---

## Part 1 — Upload to GitHub

### 1. Create an empty repo on GitHub

Go to **https://github.com/new** and fill in:

| Field | Value |
|-------|-------|
| Repository name | `gsi` |
| Visibility | Public or Private (your choice) |
| Initialize with README | ❌ Leave unticked |
| Add .gitignore | ❌ Leave unticked |
| Choose a license | ❌ Leave unticked |

Click **Create repository**. Copy the URL shown — e.g. `https://github.com/yourname/gsi.git`

---

### 2. Replace selvankj in the project files

Open a text editor and make two changes:

**File: `pyproject.toml`** (lines near the bottom)
```toml
# Change this:
Homepage = "https://github.com/selvankj/gsi"
Issues   = "https://github.com/selvankj/gsi/issues"

# To this (use your actual GitHub username):
Homepage = "https://github.com/yourname/gsi"
Issues   = "https://github.com/yourname/gsi/issues"
```

**File: `README.md`** (the badge line near the top)
```markdown
# Change this:
[![CI](https://github.com/selvankj/gsi/actions/workflows/ci.yml/badge.svg)](...)

# To this:
[![CI](https://github.com/yourname/gsi/actions/workflows/ci.yml/badge.svg)](...)
```

---

### 3. Open a terminal and push

```bash
# Navigate into the project folder
cd path/to/gsi

# Initialise git
git init

# Stage everything
git add .

# Make the first commit
git commit -m "feat: initial release of gsi security scanner"

# Connect to your GitHub repo (replace yourname)
git remote add origin https://github.com/yourname/gsi.git

# Push
git branch -M main
git push -u origin main
```

If prompted, enter your GitHub username and password (or a personal access token — GitHub no longer accepts plain passwords for pushes; use a token from https://github.com/settings/tokens).

✅ Your repo is now live at `https://github.com/yourname/gsi`

---

### 4. Add a description and topics

On your repo page, click the ⚙️ gear icon next to **About**:

- **Description:** `Personal security gate — scan for secrets, CVEs, and risk signals before you push or use a repo`
- **Topics:** `security`, `cli`, `python`, `secrets`, `devtools`, `vulnerability-scanner`, `github`

---

## Part 2 — Install and Run

### 5. Install gsi

```bash
cd path/to/gsi
pip install -e .
```

Verify it works:

```bash
gsi --help
```

You should see the help menu listing `check`, `install-hook`, and `remove-hook`.

---

### 6. Run your first scan

**Scan the gsi project itself:**

```bash
gsi check .
```

Expected result: `✅ SAFE` — the project has no secrets or vulnerabilities.

**Scan a remote repo (optional — needs internet):**

```bash
gsi check https://github.com/psf/requests
```

---

### 7. Install the pre-commit hook (optional but recommended)

Run this inside any git repo you work on:

```bash
cd /path/to/your-other-project
gsi install-hook
```

From now on, every `git commit` in that project will automatically scan for secrets. Commits with critical/high findings will be blocked.

To remove it:

```bash
gsi remove-hook
```

---

## Part 3 — Get a GitHub Token (optional)

A token isn't required for local scans. It's only needed for scanning remote repos without hitting GitHub's rate limits.

1. Go to **https://github.com/settings/tokens**
2. Click **Generate new token (classic)**
3. Give it a name like `gsi-scanner`
4. Tick only: `public_repo`
5. Click **Generate token** and copy it

Set it in your terminal:

```bash
# Add to your shell profile (~/.zshrc or ~/.bashrc) to make it permanent:
export GITHUB_TOKEN=ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

Then remote scans work without passing `--token` every time:

```bash
gsi check owner/repo
```

---

## Part 4 — Verify CI is Working

After pushing, go to your repo on GitHub and click the **Actions** tab.

You should see a workflow called **CI** running. It runs:
1. All 46 tests across Python 3.9, 3.10, 3.11, 3.12
2. A self-scan of the gsi repo for secrets
3. A lint check

Once all jobs go green, the badge in the README will update automatically.

If the CI badge shows failing, click into the run to see the error — the most common cause is a missing dependency.

---

## Troubleshooting

**`gsi: command not found`**
- Make sure you ran `pip install -e .` from inside the `gsi/` folder
- Try `python -m gsi check .` as an alternative

**`ModuleNotFoundError: No module named 'gsi'`**
- Run `pip install -e .` again from the project root

**`git push` asks for credentials**
- GitHub requires a personal access token for HTTPS pushes
- Generate one at https://github.com/settings/tokens (needs `repo` scope)
- Use it as the password when prompted

**Remote scan returns `403 Forbidden`**
- Set `GITHUB_TOKEN` in your environment (see Part 3 above)

**High number of false positive low-severity findings**
- Create a `.gsiignore` file: `cp .gsiignore.example .gsiignore`
- Add rules to suppress findings in test fixtures and documentation
- Use `--min-severity medium` to hide low-severity results

---

## Quick Reference

```bash
# Scan current directory
gsi check .

# Scan with only secrets module (fastest)
gsi check . --modules secrets

# Scan and hide low-severity noise
gsi check . --min-severity medium

# Scan and save HTML report
gsi check . --report report.html

# Scan a GitHub repo
gsi check owner/repo

# Install pre-commit hook
gsi install-hook

# Run tests
pytest

# Check everything is working
gsi check . --modules secrets && echo "All good"
```
