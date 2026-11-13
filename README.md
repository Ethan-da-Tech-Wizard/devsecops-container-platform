# DevSecOps Container and CI Experiments

This repository contains a multi-stage Dockerfile, a GitHub Actions workflow, and Python tooling for vetting YARA rules. It is an example project for exploring container builds, security checks, and software supply-chain workflows.

## What's in the repository

- [Dockerfile](Dockerfile): a Python-based multi-stage image configured to run as a non-root user.
- [GitHub Actions workflow](.github/workflows/devsecops-ci.yml): runs static analysis and unit-test jobs, builds a container image, and configures a Trivy scan and a Python version matrix.
- [YARA vetting script](scripts/twu_yara_vet.py): includes commands for building and verifying a local rule manifest.
- [YARA tests](scripts/test_twu_yara_vet.py): unit tests for the vetting script.

The workflow configures Trivy to report HIGH and CRITICAL findings with `exit-code: 0`; those findings do **not** fail that scan step. Its Bandit command also ends with `|| true`, so Bandit findings do not fail that step. A workflow definition or passing run does not establish that an image is vulnerability-free, production-ready, or compliant with a particular standard.

## Local checks

From the repository root, with Python and any required tools installed:

```sh
python3 -m compileall -q scripts/
python3 -m unittest discover -s scripts/ -p "test_*.py" -v
python3 scripts/twu_yara_vet.py --help
```

For shell scripts, the existing workflow uses ShellCheck:

```sh
find scripts/ -type f -name "*.sh" -exec shellcheck {} +
```

Review the [workflow](.github/workflows/devsecops-ci.yml), [Dockerfile](Dockerfile), and dependencies before building or running them. YARA commands that compile or scan rules require the relevant YARA utilities. Historical whitepapers and source comments may contain claims that have not been independently verified; check them against the actual implementation and current test results.

## License

[MIT License](LICENSE).

