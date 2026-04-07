# Contributing to gsi

Thanks for your interest! Here's how to get set up and what we're looking for.

## Setup

```bash
git clone https://github.com/selvankj/gsi
cd gsi
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Running tests

```bash
pytest
pytest tests/test_secret_scanner.py -v   # single module
```

## Areas where contributions are welcome

- **New secret patterns** — add to `gsi/modules/secret_scanner.py` in `SECRET_PATTERNS`
- **New code pattern checks** — add to `gsi/modules/pattern_scanner.py` in `PATTERN_CHECKS`
- **New dependency ecosystems** — add a parser in `DependencyScanner._parse_content()`
- **Bug fixes** — especially false positives in secret/pattern detection
- **Tests** — more coverage is always welcome

## Adding a new secret pattern

In `gsi/modules/secret_scanner.py`, add an entry to `SECRET_PATTERNS`:

```python
"my_service_token": {
    "pattern": r"mst_[0-9a-zA-Z]{32}",
    "severity": "high",           # critical / high / medium / low
    "description": "My Service API Token"
},
```

Then add the key to `pattern_groups` in `gsi/config/settings.py`.

## Adding a new code pattern check

In `gsi/modules/pattern_scanner.py`, add an entry to `PATTERN_CHECKS`:

```python
"my_check": {
    "patterns": [r"(?i)dangerous_function\("],
    "severity": "high",
    "description": "Use of dangerous_function()",
    "fix": "Replace with safe_function() instead",
    "extensions": {".py", ".js"}
},
```

Add the key to `checks` in `gsi/config/settings.py`.

## Pull request checklist

- [ ] Tests pass (`pytest`)
- [ ] New patterns include at least one test case
- [ ] No real secrets committed (run `gsi check .` before pushing!)
- [ ] Docstring added for new public functions
