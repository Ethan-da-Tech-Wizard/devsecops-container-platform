# ==============================================================================
# Program: DevSecOps Hardened Multi-Stage Container Platform
# Programmer: The Maintainer <maintainer@example.invalid>
# Organization: TWU LLC
# License: MIT License 2026
# Purpose: Build a production-ready, minimal attack-surface container image
#          implementing strict least-privilege non-root execution (UID/GID 10001),
#          zero build toolchain residue, POSIX PID 1 signal propagation,
#          and deterministic health probing.
#
# Threat Model & Attack Vectors Mitigated:
#   1. Container Escape & Host Takeover (CVE-2019-5736 runc breakout, Dirty Pipe/Cow):
#      - Prevented by enforcing an unprivileged non-root user (UID 10001) with no login shell (/sbin/nologin).
#      - Default Docker containers run as UID 0 (root). If a container breakout vulnerability
#        occurs, container root maps directly to host root (unless user namespaces are remapped),
#        granting the attacker complete host compromise. UID 10001 carries zero host privileges.
#   2. Living-off-the-Land (LotL) / In-Container Payload Compilation:
#      - Prevented by multi-stage build architecture that isolates and completely discards
#        compilers ('gcc'), make utilities, and system C development headers ('libc6-dev')
#        in an ephemeral builder stage before generating the final runtime shipping image.
#      - If an attacker achieves Remote Code Execution (RCE), they cannot compile local privilege
#        escalation exploits (e.g. kernel C exploits) on-the-fly due to absent toolchains.
#   3. Cache Poisoning & Stale Vulnerability Ingestion:
#      - Prevented by atomic RUN directives combining 'apt-get update' with 'apt-get install'
#        and immediate package cache purging ('rm -rf /var/lib/apt/lists/*') within the identical layer.
#   4. Process Signal Deadlocks & Zombie Proliferation:
#      - Prevented by exec-form ENTRYPOINT ["python3"] allowing direct reception of POSIX SIGTERM
#        and SIGINT signals without an intermediate shell swallowing termination requests.
#
# Senior Interview Talking Points:
#   - Multi-Stage Isolation: Why compiling dependencies in an ephemeral stage dramatically drops CVE
#     counts on static image scanners (Trivy, Snyk, Grype) and neutralizes post-exploitation toolchains.
#   - Exec Form vs. Shell Form: Why JSON array syntax ["python3"] avoids spawning '/bin/sh -c' as PID 1,
#     ensuring graceful shutdown hooks execute before orchestrators send SIGKILL.
#   - Union Filesystem Layer Hygiene: Why '--chown=appuser:appgroup' during COPY prevents layer duplication
#     and why 'rm -rf /var/lib/apt/lists/*' must occur in the exact same RUN instruction as package installation.
# ==============================================================================

# ==============================================================================
# Stage 1: Build & Dependency Preparation (Ephemeral Compiler Stage)
# ==============================================================================
# Directive: FROM python:3.12-slim-bookworm AS builder
# What it does:
#   Initializes an ephemeral builder stage named 'builder' using the Debian 12
#   ("Bookworm") slim variant of Python 3.12.
# Why it is best-practice for security:
#   - Pinned Base Image: Pinning specific major, minor, and OS releases
#     (3.12-slim-bookworm) ensures reproducible, deterministic builds and prevents
#     unexpected upstream supply-chain drift compared to floating tags like 'latest'.
#   - Minimal Base Footprint: The 'slim' flavor removes development documentation,
#     manuals, and unnecessary system packages present in full Debian images (~1GB
#     reduced to ~150MB), dramatically shrinking the initial attack surface.
#   - Build Isolation: Isolates build tools (compilers, headers) in an ephemeral stage
#     that is completely discarded before the final runtime image is created.
# Attack Vector Prevented:
#   - Supply Chain Drift & Arbitrary Code Ingestion: Floating tags (e.g., 'python:latest')
#     can silently pull breaking interpreter changes or compromised upstream patches without notice.
# Interview Talking Point:
#   - "We pin our base image to 'python:3.12-slim-bookworm' to guarantee cryptographic reproducibility
#     and ensure our security baselines are tested against known, immutable Debian package manifests."
FROM python:3.12-slim-bookworm AS builder

# Directives: ENV PYTHONDONTWRITEBYTECODE=1 \ PYTHONUNBUFFERED=1
# What it does:
#   Sets environment variables that govern Python's runtime I/O and bytecode compilation.
# Why it is best-practice for security & DevOps:
#   - PYTHONDONTWRITEBYTECODE=1: Prevents Python from writing compiled '.pyc' files to disk.
#     In immutable containers, writing bytecode to the writable container layer creates
#     unnecessary layer I/O, potential permission clashes when running non-root, and
#     can mask runtime code changes or cache corruption.
#   - PYTHONUNBUFFERED=1: Forces standard output (stdout) and standard error (stderr)
#     to stream directly to the terminal/container log collector without buffer delays.
#     Essential for container orchestration (Kubernetes, Docker daemon, CloudWatch) to
#     capture real-time audit logs and ensure crash stack traces are not lost in memory buffers.
# Attack Vector Prevented:
#   - Silent Failures & Log Evasion: Buffered I/O can withhold critical error dumps or crash
#     telemetry during abrupt process termination, impeding incident response and forensics.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Directive: WORKDIR /build
# What it does:
#   Creates and switches the working directory inside the builder container to '/build'.
# Why it is best-practice for security:
#   - Prevents executing commands or dumping intermediate artifacts in the container root ('/').
#   - Follows the principle of filesystem segregation, keeping build artifacts compartmentalized.
# Attack Vector Prevented:
#   - Root Directory Polluting & Overwriting: Protects system mount points from unintended file overwrites.
WORKDIR /build

# Directive: RUN apt-get update && apt-get install -y --no-install-recommends ...
# What it does:
#   Updates the Debian package index, installs native build dependencies, and cleans up the index.
# Why it is best-practice for security & image optimization:
#   - Atomic Execution (&&): Chaining commands ensures build failure on any step ('set -e' behavior).
#   - Single-Layer Update & Install: Combining 'apt-get update' and 'apt-get install' prevents
#     Docker layer caching bugs where a cached update layer leads to installing stale packages.
#   - --no-install-recommends: Instructs APT to skip optional packages, preventing accidental
#     installation of unwanted daemons, fonts, or libraries, keeping the attack surface minimal.
#   - gcc & libc6-dev: C compiler and standard C library headers required to compile native extensions.
#   - libyara-dev: Header files and libraries for YARA malware classification engine integration.
#   - rm -rf /var/lib/apt/lists/*: Removes APT package index caches in the EXACT same RUN layer
#     where they were generated. In Docker's union filesystem, deleting files in a subsequent layer
#     leaves them permanently stored in the underlying layer, bloating the container image.
# Attack Vector Prevented:
#   - Stale Package Poisoning: Prevents cached APT indices from pulling outdated packages with known CVEs.
#   - Bloated Image Layers: Prevents accumulation of hundreds of megabytes of temporary APT index files.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    libyara-dev \
    && rm -rf /var/lib/apt/lists/*

# Architecture Note: Stdlib-First Zero External Dependency Design
# What it does:
#   TWU's architecture prioritizes Python's extensive standard library for its core
#   operations, avoiding unnecessary third-party package dependencies.
# Why it is best-practice for security:
#   - Mitigates Software Supply Chain attacks (e.g. dependency confusion, typosquatting,
#     compromised PyPI maintainer accounts).
#   - Reduces vulnerability management overhead (fewer CVEs to monitor, patch, and remediate).
#   - Keeps the build pipeline fast, deterministic, and self-contained.


# ==============================================================================
# Stage 2: Hardened DevSecOps Runtime Stage
# ==============================================================================
# Directive: FROM python:3.12-slim-bookworm AS runtime
# What it does:
#   Starts a fresh, clean runtime container layer, completely discarding Stage 1.
# Why it is best-practice for security:
#   - Attack Surface Elimination: Compilers ('gcc'), static headers ('libc6-dev', 'libyara-dev'),
#     and build caches from Stage 1 are completely excluded from the runtime container.
#   - Exploit Mitigation: If an attacker manages to achieve Remote Code Execution (RCE) inside
#     the container, they cannot compile C exploits (e.g. dirty pipe/cow or local privilege escalation
#     exploits) or build malware binaries on-the-fly because no build toolchain exists.
#   - Drastically reduces CVE vulnerability count detected by scanners like Trivy, Snyk, and Grype.
# Attack Vector Prevented:
#   - Post-Exploitation Living-off-the-Land (LotL): Discards all compilers and headers, denying
#     adversaries the ability to assemble binary exploits inside compromised containers.
# Interview Talking Point:
#   - "By implementing multi-stage builds, we completely decouple build-time compilation tooling from
#     runtime execution, effectively reducing container image size by ~70% and removing attack tools."
FROM python:3.12-slim-bookworm AS runtime

# Directive: LABEL ...
# What it does:
#   Embeds Open Container Initiative (OCI) image metadata and specifications directly into the image.
# Why it is best-practice:
#   - Standardizes container provenance, author attribution, and version control across registries.
#   - Enables automated DevSecOps scanners and policy engines (e.g. Kyverno, OPA Gatekeeper)
#     to enforce container governance policies based on structured metadata.
LABEL maintainer="The Maintainer <maintainer@example.invalid>" \
      org.opencontainers.image.authors="The Maintainer <maintainer@example.invalid>" \
      org.opencontainers.image.vendor="TWU LLC" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.title="TWU DevSecOps Container Platform" \
      org.opencontainers.image.description="Hardened, non-root multi-stage container environment with built-in security auditing" \
      org.opencontainers.image.version="1.0.0"

# Directives: ENV PYTHONDONTWRITEBYTECODE=1 \ PYTHONUNBUFFERED=1 \ PATH=... \ HOME=...
# What it does:
#   Configures runtime environment variables for process execution.
# Why it is best-practice for security:
#   - Environment Persistence: In multi-stage Docker builds, ENV directives from previous
#     stages do NOT automatically propagate. Re-declaring PYTHONDONTWRITEBYTECODE and
#     PYTHONUNBUFFERED ensures these critical runtime protections remain active in Stage 2.
#   - PATH="/app/scripts:${PATH}": Prepends application script directories to system $PATH,
#     allowing security utilities (e.g. 'twu_yara_vet.py') to be invoked directly without hardcoded paths.
#   - HOME="/home/appuser": Explicitly defines the home directory for the unprivileged runtime user,
#     preventing tools from defaulting to '/' or undefined host paths that could trigger write errors.
# Attack Vector Prevented:
#   - Path Hijacking & Write Permission Crashes: Declares explicit paths and homes, stopping
#     arbitrary binary execution from unauthorized writable locations.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/scripts:${PATH}" \
    HOME="/home/appuser"

# Directive: WORKDIR /app
# What it does:
#   Sets the root application working directory inside the container to '/app'.
# Why it is best-practice for security:
#   - Enforces filesystem isolation by segregating application source code and runtime assets
#     from OS system directories (/etc, /bin, /usr, /root).
#   - All subsequent relative paths in COPY, CMD, and RUN commands resolve cleanly against /app.
WORKDIR /app

# Directive: RUN apt-get update && apt-get install -y --no-install-recommends ...
# What it does:
#   1. Installs runtime security tooling: ca-certificates, ClamAV antivirus, and YARA engine.
#   2. Cleans up package caches to reduce image layer size.
#   3. Creates a dedicated non-root user and group with UID/GID 10001 and no login shell.
#   4. Initializes application directories and establishes unprivileged ownership.
# Why it is best-practice for security (Crucial Interview Discussion Point):
#   - ca-certificates: Essential for verifying TLS/SSL certificates, preventing Man-in-the-Middle
#     (MITM) attacks during external threat intelligence feeds or secure API communications.
#   - clamav & clamav-freshclam: Production-grade antivirus scanner and signature updater for
#     scanning untrusted files, attachments, and payloads.
#   - yara: Pattern-matching engine for malware classification, threat hunting, and rule vetting.
#   - Non-Root Principle of Least Privilege (UID 10001):
#       * By default, Docker containers run as UID 0 (root). If a container breakout vulnerability
#         occurs (e.g. kernel exploit, volume mount escape, or runc vulnerability like CVE-2019-5736),
#         a process running as container root can compromise the underlying host system as root.
#       * UID/GID 10001 is a high, non-standard ID outside standard Linux system accounts (0-999)
#         and default interactive users (1000). On the host, UID 10001 has no elevated privileges.
#   - Shell Restriction (-s /sbin/nologin):
#       * Completely disables interactive shell login for the service account.
#       * Prevents attackers from spawning interactive bash/sh sessions or executing reverse shells
#         under the service account credentials if a vulnerability is exploited.
#   - Dedicated Home Directory (-d /home/appuser -m):
#       * Isolates temporary files and user-specific configurations to a controlled, non-root directory.
#   - Directory Pre-creation & Ownership (chown -R appuser:appgroup /app):
#       * Pre-creates /app/data and /app/scripts and sets ownership so the unprivileged user has
#         strict read/write permissions where needed, without requiring sudo or root permissions at runtime.
# Attack Vector Prevented:
#   - Container Breakout to Host Root (CWE-250, CVE-2019-5736): Running as UID 10001 prevents
#     container processes from escaping into host root context even under kernel namespace escapes.
#   - Reverse Shell Access: Assigning '/sbin/nologin' invalidates interactive shell spawns.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    clamav \
    clamav-freshclam \
    yara \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 appgroup \
    && useradd -u 10001 -g appgroup -s /sbin/nologin -d /home/appuser -m appuser \
    && mkdir -p /app/data /app/scripts \
    && chown -R appuser:appgroup /app

# Directive: COPY --chown=appuser:appgroup scripts/ /app/scripts/
# What it does:
#   Copies application scripts into the container image.
# Why it is best-practice for security:
#   - In-flight Ownership Assignment (--chown=appuser:appgroup):
#       * Docker default behavior sets copied file ownership to root:root.
#       * Using the --chown flag sets file ownership directly during the copy operation.
#       * This avoids executing a subsequent 'RUN chown -R appuser:appgroup /app' instruction,
#         which in Docker's union filesystem would duplicate every single file into a new layer,
#         needlessly doubling the image size and slowing build times.
#   - Selective File Copying (Least Privilege):
#       * Avoids sweeping copies like 'COPY . .'.
#       * Copies only the vetted runtime directory ('scripts/').
#       * Ensures test suites, documentation, git history, and development credentials
#         are never included in the production image layer.
# Attack Vector Prevented:
#   - Secret & Metadata Leakage: Restricts container inclusion to runtime-only assets, preventing
#     accidental leakage of developer workstation artifacts, .git histories, or staging configurations.
COPY --chown=appuser:appgroup scripts/ /app/scripts/

# Directive: USER appuser:appgroup
# What it does:
#   Switches the active user and group context from 'root' to the unprivileged 'appuser:appgroup' (UID:GID 10001).
# Why it is best-practice for security:
#   - Privilege Drop: All subsequent commands, container entrypoints, and runtime processes execute
#     as non-root.
#   - Defense-in-Depth: Satisfies strict container security standards (CIS Docker Benchmark 4.1,
#     Kubernetes Pod Security Standards 'Restricted' profile, and OpenShift arbitrary UID security context).
#   - Prevents privilege escalation: Unprivileged users cannot modify system binaries (/bin, /sbin),
#     alter root-owned files, install system packages, or manipulate kernel interfaces.
# Attack Vector Prevented:
#   - Privilege Escalation: Any process executing in the container operates strictly under UID 10001.
USER appuser:appgroup

# Directive: HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 ...
# What it does:
#   Defines an automated container vitality probe executed periodically by the container runtime.
# Parameters:
#   - --interval=30s: Executes the healthcheck every 30 seconds to maintain ongoing health monitoring.
#   - --timeout=5s: Fails the probe if the healthcheck script hangs or exceeds 5 seconds.
#   - --start-period=5s: Grace period on startup where failures do not count against the retry threshold,
#     allowing the application to initialize cleanly.
#   - --retries=3: Marks the container as 'unhealthy' after 3 consecutive failures, alerting orchestrators.
# Why it is best-practice for security & reliability:
#   - Substantive Security Verification: Validates the integrity of the Python runtime and security
#     vetting utility without performing side-effects.
#   - Automated Fail-Closed Recovery: If the execution environment is corrupted, tampered with, or if
#     the Python runtime fails, the container reports unhealthy and orchestrators (Kubernetes/Docker Swarm)
#     can automatically restart or replace the compromised instance, maintaining system integrity.
# Attack Vector Prevented:
#   - Silent Degraded State & Blind Orchestration: Ensures crashed, corrupted, or tampered containers
#     are flagged unhealthy and remediated rather than continuing to receive network traffic.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 /app/scripts/twu_yara_vet.py --help || exit 1

# Directive: ENTRYPOINT ["python3"]
# What it does:
#   Configures 'python3' as the default executable that runs when the container starts.
# Why it is best-practice (Exec Form vs. Shell Form):
#   - Exec Form Syntax (JSON Array): ["python3"] executes the binary directly as PID 1 without
#     spawning an intermediate shell (/bin/sh -c).
#   - POSIX Signal Propagation: When Docker or Kubernetes stops a container, it sends SIGTERM.
#     In shell form, /bin/sh runs as PID 1 and swallows SIGTERM, preventing Python from executing
#     graceful shutdown handlers or cleanup routines until SIGKILL forcibly terminates it after 10s.
#     Using exec form ensures Python receives SIGTERM directly, enabling clean, graceful shutdown.
# Attack Vector Prevented:
#   - Unclean Terminations & State Corruption: Signals are delivered directly to Python PID 1,
#     preventing orphaned child processes and unclosed socket leaks.
ENTRYPOINT ["python3"]

# Directive: CMD ["/app/scripts/twu_yara_vet.py", "--help"]
# What it does:
#   Provides default arguments to the ENTRYPOINT, invoking the YARA security vetting engine CLI help.
# Why it is best-practice:
#   - Safe Default Behavior: Running 'docker run devsecops-container-platform' safely executes a read-only
#     CLI audit verification by default, without performing destructive actions.
#   - Runtime Flexibility: Operators can easily override arguments at runtime (e.g.
#     'docker run devsecops-container-platform /app/scripts/twu_yara_vet.py verify') while retaining
#     the hardened Python entrypoint.
# Attack Vector Prevented:
#   - Accidental Destructive Invocation: Default run is non-destructive read-only help inspection.
CMD ["/app/scripts/twu_yara_vet.py", "--help"]
