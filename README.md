# ledger-api-devsecops

A production-grade DevSecOps pipeline for a cloud-native payments API — workload
hardening, supply-chain security, GitOps, a zero-trust service mesh, and an
authorized penetration test, each backed by live, reproducible evidence rather
than untested configuration.

Built as a hands-on technical assessment for Dodo Payments (Security & DevOps
Engineer role), and shared here as a portfolio reference for the broader
DevSecOps/platform engineering toolchain it demonstrates: Kubernetes admission
control, Sealed Secrets, Cosign/SLSA supply-chain attestation, ArgoCD + Argo
Rollouts, Istio mTLS and identity-based authorization, and OWASP-aligned
application security testing.

## Starting Point

This project began from Dodo Payments' official starter repository:
**[github.com/bhabani-dodo/ledger-api-assignment](https://github.com/bhabani-dodo/ledger-api-assignment)**

That repository ships `ledger-api` deliberately insecure: a root container,
plaintext secrets committed to git, no network policy, and — as documented in
this project's Task 4 penetration test — a genuine unauthenticated remote code
execution vulnerability and an unrestricted SSRF endpoint. The original,
unmodified starter files are preserved in this repo at
[`deploy/insecure-baseline/`](deploy/insecure-baseline/) specifically as negative
test cases proving the security controls built here actually reject them — see
Task 1's verification evidence for the live admission-control rejections.

## What This Repo Contains

| Task | What was built | Report |
|---|---|---|
| **1. Workload Hardening** | securityContext lockdown, dedicated ServiceAccount + least-privilege RBAC, Sealed Secrets, Kyverno admission policies (reject root/`:latest`/unsigned), Pod Security Standards | [`README-task1.md`](README-task1.md) |
| **2. Secure CI/CD & Supply Chain** | GitHub Actions pipeline (Gitleaks, Semgrep, Trivy fs+image scans), Cosign keyless signing + SLSA provenance, GitOps via ArgoCD (drift detection + self-heal, proven), canary rollout via Argo Rollouts | [`README-task2.md`](README-task2.md) |
| **3. Service Mesh & Zero-Trust** | Istio with CNI (a real PSS-vs-sidecar conflict diagnosed and fixed), STRICT mTLS, SPIFFE-identity-based AuthorizationPolicy, NetworkPolicy (written, with an honestly-documented enforcement gap), TLS Ingress Gateway, PCI CDE scope mapping | [`README-task3.md`](README-task3.md) |
| **4. Recon & Penetration Test** | Passive OSINT against `dodopayments.tech` (128 subdomains enumerated), and an authorized penetration test against the local unpatched starter app — 4 findings including the Critical RCE, with CVSS scoring, PoC evidence, and remediation status | [`task4-part-a-recon-report.md`](task4-part-a-recon-report.md), [`task4-part-b-pentest-report.md`](task4-part-b-pentest-report.md) |

## Repository Structure

```
.
├── app/                        # Application source (hardened)
├── deploy/                     # Kubernetes manifests
│   └── insecure-baseline/      # Original starter manifests — kept as negative test cases
├── policies/                   # Kyverno policies + RBAC personas
├── argocd/                     # ArgoCD Application (GitOps source of truth)
├── istio/                      # Service mesh: mTLS, AuthorizationPolicy, NetworkPolicy, Gateway
├── .github/workflows/          # CI/CD pipeline
├── README-task1.md
├── README-task2.md
├── README-task3.md
├── task4-part-a-recon-report.md
├── task4-part-b-pentest-report.md
├── .trivyignore                # Documented, justified CVE exceptions
├── .gitleaksignore             # Documented, justified secret-scan exceptions
└── README.md                   # This file
```

## Setup

Each task README contains its own detailed setup/reproduction steps. High level:

```bash
git clone https://github.com/raimadb/ledger-api-devsecops.git
cd ledger-api-devsecops

# Local Kubernetes cluster
minikube start

# Follow README-task1.md → README-task2.md → README-task3.md in order,
# since each layers on top of the previous task's infrastructure.
```

## Design Philosophy

Every control in this repo is backed by **live, captured evidence** — real
terminal output, real admission-webhook denials, real signature verifications —
not just configuration that's never been exercised. Where something didn't work
as intended (the distroless image experiment increasing CVE findings rather than
reducing them; NetworkPolicy not being enforced on this specific Minikube
cluster; a DNS-rebinding gap in the SSRF mitigation), it's documented honestly
with the reasoning behind the decision, rather than hidden or silently worked
around. Each task README's "Troubleshooting Notes" section captures the real
engineering process, including dead ends, not just the final clean state.

## Security & Quality Gates

This repo's own CI/CD pipeline enforces the same standards it recommends:
Gitleaks (full-history secret scanning), Semgrep (SAST), Trivy (dependency and
image CVE scanning), Cosign (image signing), and Kyverno (cluster-side admission
policy) all gate every change. Documented exceptions (`.trivyignore`,
`.gitleaksignore`) are individually justified, not blanket suppressions — see
Task 2's README for the reasoning behind each one.
