# Production DevSecOps CI/CD & Hardened Container Platform

An enterprise-grade, shift-left Continuous Integration and Continuous Delivery (CI/CD) and containerization platform implementing automated security gates, least-privilege non-root execution, vulnerability scanning, and software supply chain governance.

---

## 1. Architectural Highlights

- **Multi-Stage Hardened Container**: Built from `python:3.12-slim-bookworm` with strict separation between ephemeral compiler stages and a minimal runtime footprint.
- **Least-Privilege Non-Root Execution**: Runs strictly as an unprivileged service account (`appuser:appgroup`, UID/GID 10001) with interactive shells disabled (`/sbin/nologin`).
- **Static Application Security Testing (SAST)**: Automated linting and security analysis via ShellCheck and Bandit AST scanner.
- **Threat Signature Verification**: Cryptographic compile-time verification across YARA detection rules before deployment.
- **Container Vulnerability Gating**: Continuous container image scanning using Aqua Security Trivy, enforcing zero unmitigated `CRITICAL` or `HIGH` CVEs.
- **Software Bill of Materials (SBOM)**: Automated SPDX-JSON SBOM generation adhering to Executive Order 14028 and ISO/IEC 5962:2021 standards.
- **Multi-Runtime Compatibility**: Matrix validation across Python 3.10, 3.11, 3.12, and 3.13.

---

## 2. Repository Layout

```
.
├── .dockerignore                           # Minimal build context & secret exclusion
├── Dockerfile                              # Multi-stage hardened build (UID 10001)
├── .github/
│   └── workflows/
│       └── devsecops-ci.yml                # 4-stage GitHub Actions CI/CD pipeline
├── docs/
│   ├── DEVSECOPS_WHITEPAPER.md             # Complete architectural decision records & threat model
│   └── PLATFORM_SECURITY_WHITEPAPER.md     # 3-node distributed mesh & kernel cgroup isolation
└── scripts/
    ├── twu_yara_vet.py                     # Offline YARA rule verification & build engine
    └── test_twu_yara_vet.py                # Security & syntax validation test suite
```

---

## 3. Pipeline Stages

```
   [ Git Push / Pull Request ]
               │
    ┌──────────┴──────────┐
    ▼                     ▼
[ Stage 1: SAST ]     [ Stage 2: YARA Vetting ]
• ShellCheck (Bash)   • Threat pattern syntax check
• python3 compileall  • YARA engine compilation
• Bandit (Python)     • Core security test suite
    │                     │
    └──────────┬──────────┘
               ▼
  [ Stage 3: Docker Build & DevSecOps ]
  • Multi-stage build with BuildKit
  • Non-root UID/GID 10001
  • Aqua Security Trivy scan (HIGH,CRITICAL)
  • SPDX-JSON SBOM artifact generation
  • In-container runtime smoke test
               │
               ▼
  [ Stage 4: Multi-Version Test Matrix ]
  • Parallel matrix: Python 3.10, 3.11, 3.12, 3.13
  • Platform regression certification suites
```

---

## 4. Local Verification & Reproducibility

Execute the same verification checks locally before pushing:

```bash
# 1. Shell script linting
find scripts/ -type f -name "*.sh" -exec shellcheck {} +

# 2. Python bytecode compilation
python3 -m compileall -q scripts/

# 3. YARA rule integrity & platform security test suites
python3 -m unittest discover -s scripts/ -p "test_*.py" -v
```

---

## 5. Technical Documentation & Whitepapers

- **[DevSecOps Technical Whitepaper](docs/DEVSECOPS_WHITEPAPER.md)**: Architectural Decision Records (ADRs), Supply Chain Threat Model, and Senior DevOps / DevSecOps STAR-method interview scripts.
- **[Platform Security Whitepaper](docs/PLATFORM_SECURITY_WHITEPAPER.md)**: Distributed 3-node mesh architecture, WireGuard remote syslog receiver (`LOGG-2154`), and Linux kernel cgroup v2 resource isolation.

---

## 6. Author & License

**The Maintainer**  
Software Engineer | DevOps & DevSecOps | Applied AI & Linux Systems  
GitHub: [github.com/Ethan-da-Tech-Wizard](https://github.com/Ethan-da-Tech-Wizard)  
Email: maintainer@example.invalid  
Organization: TWU LLC  

Licensed under the **MIT License 2026**. See [LICENSE](LICENSE) for details.
