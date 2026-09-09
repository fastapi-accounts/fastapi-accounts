# Development, Testing & PyPI Release Guide 🚀

This document serves as the standard operating playbook for running tests, verifying code formatting, building distribution artifacts, and publishing `fastapi-accounts` to PyPI.

---

## 📋 Table of Contents
1. [Pre-Flight Verification (Ruff & Pytest)](#1-pre-flight-verification-ruff--pytest)
2. [Version Bumping](#2-version-bumping)
3. [Building Distribution Packages](#3-building-distribution-packages)
4. [Publishing to PyPI](#4-publishing-to-pypi)
5. [Post-Publish Smoke Testing](#5-post-publish-smoke-testing)
6. [Git Tagging & GitHub Release](#6-git-tagging--github-release)

---

## 1. Pre-Flight Verification (Ruff & Pytest)

Always run these quality assurance commands before committing or releasing any new feature:

### A. Auto-Format Code (Ruff)
Formats all Python files according to project style standards:
```bash
.venv/bin/ruff format src tests
```

### B. Lint & Auto-Fix Issues (Ruff)
Runs the linter and automatically resolves fixable lint rules:
```bash
.venv/bin/ruff check --fix src tests
```

### C. Verify Clean Lint Status
Confirms 0 warnings and 0 errors:
```bash
.venv/bin/ruff check src tests
```

### D. Run Automated Test Suite (Pytest)
Executes all unit and integration tests with detailed progress:
```bash
PYTHONPATH=src .venv/bin/pytest -v
```

> **Target Standard:** All tests must pass (100% pass rate) with 0 lint errors before building a release.

---

## 2. Version Bumping

Update the version number in **both** locations:

1. **`pyproject.toml`**:
   ```toml
   [project]
   name = "fastapi-accounts"
   version = "0.1.0a2"   # <-- Update version string
   ```

2. **`src/fastapi_accounts/__init__.py`**:
   ```python
   __version__ = "0.1.0a2"  # <-- Match version string
   ```

---

## 3. Building Distribution Packages

### A. Clean Previous Build Artifacts
Ensure old `.whl` and `.tar.gz` files do not accidentally get republished:
```bash
rm -rf dist/ build/ *.egg-info src/*.egg-info
```

### B. Ensure Build Tooling is Installed
```bash
.venv/bin/python3 -m pip install --upgrade build twine
```

### C. Build Wheels & Source Tarball
```bash
.venv/bin/python3 -m build
```
*(Or with `uv`: `uv build`)*

Verify that `dist/` contains the fresh archive files:
```bash
ls -la dist/
```
Expected output:
* `fastapi_accounts-<version>-py3-none-any.whl`
* `fastapi_accounts-<version>.tar.gz`

---

## 4. Publishing to PyPI

### A. (Optional) Test on TestPyPI
To test the packaging on TestPyPI first without touching production:
```bash
.venv/bin/python3 -m twine upload --repository testpypi dist/*
```

### B. Publish to Production PyPI
Upload the distribution files to official PyPI:
```bash
.venv/bin/python3 -m twine upload dist/*
```

**Credentials Prompt:**
* **Username:** `__token__`
* **Password:** `pypi-AgEIcHlwaS5vcmc...` *(Your PyPI API token)*

---

## 5. Post-Publish Smoke Testing

Verify that end users can install and use the freshly published package from scratch.

### Step 1: Create an Isolated Temporary Environment
```bash
python3 -m venv /tmp/fastapi-accounts-smoke-test
source /tmp/fastapi-accounts-smoke-test/bin/activate
```

### Step 2: Install from PyPI

* **For Alpha / Pre-Releases (`a1`, `a2`, `b1`, `rc1`):**
  ```bash
  pip install fastapi-accounts --pre
  # Or with uv:
  # uv add fastapi-accounts --prerelease=allow
  ```

* **For Stable Releases:**
  ```bash
  pip install fastapi-accounts
  ```

### Step 3: Run Smoke Test Script
Verify that imports, version, and schemas work out-of-the-box:
```bash
python -c "
import fastapi_accounts
print(f'✅ Installed fastapi-accounts version: {fastapi_accounts.__version__}')

from fastapi_accounts import (
    FastAPIAccounts,
    SQLAlchemyAdapter,
    User,
    RegisterRequest,
    ChangePasswordRequest,
    ResetPasswordRequest,
)
print('✅ Successfully imported all core adapters, models, and schemas!')
"
```

### Step 4: Clean Up Temporary Environment
```bash
deactivate
rm -rf /tmp/fastapi-accounts-smoke-test
```

---

## 6. Git Tagging & GitHub Release

Once verified on PyPI, tag the release commit in git:

```bash
# 1. Create annotated tag
git tag -a v0.1.0a2 -m "Release v0.1.0a2: Password reset and change password workflows"

# 2. Push tag to GitHub
git push origin v0.1.0a2
```

Then, visit [GitHub Releases](https://github.com/fastapi-accounts/fastapi-accounts/releases/new) to create a release pointing to the new tag with change highlights.
