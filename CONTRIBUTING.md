# Contributing to the DevSecOps Platform

Thank you for your interest in contributing to the DevSecOps container platform.

---

## 1. Development Environment Setup

Ensure you have the required toolchain installed locally:
- Python 3.10+
- ShellCheck (`shellcheck --version`)
- Docker / Podman (`docker version`)
- Git (`git --version`)

---

## 2. Pre-Commit Validation

Before submitting any code changes, ensure all static analysis and unit tests pass cleanly:

```bash
# 1. Shell script static analysis
find scripts/ -type f -name "*.sh" -exec shellcheck {} +

# 2. Python syntax compilation check
python3 -m compileall -q scripts/

# 3. YARA rule integrity verification
python3 scripts/twu_yara_vet.py verify

# 4. Execute unit test suites
python3 -m unittest discover -s scripts/ -p "test_*.py"
```

---

## 3. Pull Request Guidelines

1. **Branch Naming**: Use descriptive branch names (`feature/add-sbom-format`, `fix/shellcheck-quoting`).
2. **Commit Hygiene**: Write clear, imperative commit messages (`feat: add Bandit AST analysis step`).
3. **CI Status**: Pull requests cannot be merged unless all status checks in GitHub Actions pass with 100% green status.
4. **Code Comments**: All additions to shell scripts, Dockerfiles, and workflows must include educational explanatory comments detailing the security rationale.
