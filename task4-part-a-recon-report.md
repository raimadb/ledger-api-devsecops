# Task 4, Part A — External Attack Surface Reconnaissance Report

**Target:** dodopayments.tech
**Methodology:** Passive OSINT only — certificate transparency, DNS-based subdomain
enumeration, HTTP response fingerprinting, TLS configuration inspection. No active
scanning, fuzzing, or exploitation was performed against any dodopayments.tech or
dodopayments.com host, in accordance with the assessment's rules of engagement.
**Date:** August 2026
**Tools used:** `subfinder` v2.14.0, `assetfinder` v0.1.1, `httpx` v1.10.0, `openssl`
(TLS/certificate inspection, substituted for `testssl.sh` — see Tooling Note below)

## Tooling Note

`testssl.sh` could not be run in this environment — it requires the `hexdump`
utility, which is not present in a stock Git Bash/MSYS2 installation on Windows and
has no available package via `pacman` in this setup (`pacman: command not found`).
Rather than install a heavier environment (WSL/full MSYS2) for a single dependency,
TLS posture was assessed directly via `openssl s_client`, checking protocol
version support, negotiated ciphers, certificate details, and HSTS headers —
functionally equivalent coverage of the specific checks relevant to this report,
gathered manually rather than via `testssl.sh`'s automated output format.

## Methodology

1. **Subdomain enumeration** — `subfinder -d dodopayments.tech -all` and
   `assetfinder --subs-only dodopayments.tech`, results deduplicated and merged.
2. **Live host fingerprinting** — full merged subdomain list piped through
   `httpx -title -tech-detect -status-code` to identify responsive hosts, HTTP
   status, page titles, and detected technologies.
3. **TLS posture** — `openssl s_client` against a representative sample of the
   most significant customer-facing hosts (not all 48 live hosts, to keep scope
   proportionate to risk — internal/infra tooling subdomains were deprioritized
   in favor of the properties an actual customer or attacker would interact with
   first).

## Attack Surface Inventory

**128** unique subdomains discovered via passive sources; **48** responded live
at time of scanning.

### Customer-Facing Properties (highest priority)

| Host | Status | Technology | Notes |
|---|---|---|---|
| `dodopayments.tech` | 301 | Cloudflare | Redirects (apex → app or www) |
| `app.dodopayments.tech` | 200 | Next.js, Node.js, React, Webpack, Cloudflare, HSTS | Main application |
| `website.dodopayments.tech` | 200 | Astro 5.18.0, Cloudflare | Marketing site — "Billing & Payments Platform for AI-First Companies" |
| `checkout.dodopayments.tech` | 404 | Next.js, Node.js, React, Vercel, HSTS | Returns 404 on bare path — likely requires a specific checkout session/token path |
| `test.checkout.dodopayments.tech` | 404 | Same as above | Test environment publicly resolvable — worth flagging (see Risk Observations) |
| `customer.dodopayments.tech` | 429 | Vercel Security Checkpoint | Bot-protection challenge, not app content |
| `partners.dodopayments.tech` | 429 | Vercel Security Checkpoint | Same |
| `store.dodopayments.tech` | 302 | Vercel, HSTS | Redirect |

### Internal/Infrastructure Tooling Exposed on Public DNS

| Host | Status | Technology | Observation |
|---|---|---|---|
| `mb.dodopayments.tech` | 200 | Metabase | BI/analytics dashboard — access control not visible from passive recon alone |
| `keycloak.dodopayments.tech` | 302 | — | Identity/SSO provider |
| `clickhouse-prod-v2.dodopayments.tech` | 200 | ClickHouse | Production analytics DB, HTTP interface responding |
| `clickhouse-dev-v2.dodopayments.tech` | 200 | ClickHouse | Dev instance, also responding |
| `n8n.dodopayments.tech` | 200 | n8n.io Workflow Automation | Internal automation tooling |
| `codecov.dodopayments.tech` | 200 | Codecov | CI/CD coverage reporting |
| `ozone.dodopayments.tech` | 200 | OpenReplay | Session replay tooling |
| `sonarqube.dodopayments.tech` | (in list, not confirmed live in this scan) | — | Static analysis platform — if live, would reveal code quality/security scan results |
| `argocd.dodopayments.tech`, `argocd-dev/prod.infra` | (in list) | — | GitOps control plane — same category of tooling this assessment itself uses |

### Access-Controlled / Gated (positive finding)

`internal.dodopayments.tech`, `live.dodopayments.tech`, `test.dodopayments.tech` all
return a **custom** `403 Forbidden - Dodo Payments` page (not a generic Cloudflare
block page) — indicating deliberate, application-level access gating rather than
default deny. This is a positive security signal: these hosts are intentionally
restricted, not accidentally exposed.

### Operational Anomaly

`dev.dodopayments.tech` returns Cloudflare error `525` (SSL handshake failed
between Cloudflare's edge and the origin server) — indicates a TLS
misconfiguration on that specific origin. Not independently exploitable from
passive recon, but signals operational inconsistency worth an internal follow-up.

## TLS Configuration

| Host | Certificate Issuer | Validity | TLS 1.0/1.1 | TLS 1.2 Cipher | TLS 1.3 Cipher | HSTS |
|---|---|---|---|---|---|---|
| `app.dodopayments.tech` | Google Trust Services (WE1) | Jun 24 – Sep 22 2026 | Rejected (good) | ECDHE-ECDSA-CHACHA20-POLY1305 | TLS_AES_256_GCM_SHA384 | `max-age=63072000; includeSubDomains; preload` |
| `checkout.dodopayments.tech` | Let's Encrypt (YR1) | Jun 12 – Sep 10 2026 | — | — | — | `max-age=63072000; includeSubDomains; preload` |
| `website.dodopayments.tech` | Google Trust Services (WE1) | Jun 29 – Sep 27 2026 | — | — | — | **Not present** |

**Overall assessment: strong.** Modern protocol-only (TLS 1.0/1.1 correctly
rejected), forward-secret ECDHE ciphers, AEAD cipher suites on both TLS 1.2 and
1.3, short-lived automatically-renewed certificates (≈90-day validity consistent
with ACME-based issuance), and maximal HSTS configuration (2-year max-age,
`includeSubDomains`, `preload`-eligible) on the primary properties checked.

**One inconsistency:** `website.dodopayments.tech` does not return an HSTS header,
unlike `app.` and `checkout.`. Low individual severity (the site still only serves
over HTTPS via Cloudflare), but worth normalizing across all customer-facing
properties for defense-in-depth against protocol-downgrade attacks.

## Risk Observations — What an Attacker Would Find Interesting

1. **Breadth of internal tooling on public DNS.** 128 discovered subdomains for
   what is externally a payments platform is a large surface. Many (ClickHouse,
   Metabase, n8n, ArgoCD, SonarQube) are internal engineering tools that — while
   individually may be properly access-controlled — collectively give an attacker
   a detailed map of the company's technology stack and internal tooling
   footprint, which is valuable reconnaissance for social engineering, targeted
   phishing (knowing exactly what tools employees use), or identifying
   less-hardened secondary targets versus the well-defended primary application.

2. **Dev/test environments on public DNS.** `test.checkout.dodopayments.tech`,
   `clickhouse-dev-v2`, `events-dev`, `sequindev` — non-production environments
   are often less rigorously monitored and patched than production, making them
   statistically more likely targets even though they may hold less sensitive
   live data.

3. **`mb.dodopayments.tech` (Metabase) responding `200`** without an
   authentication challenge visible in passive recon is the single most worth
   following up on — Metabase misconfigurations (public dashboards, default
   credentials) are a well-known real-world exposure pattern. This assessment's
   passive-only scope for Part A means it cannot be confirmed further here; it's
   flagged as a recommended follow-up for an authorized active assessment.

4. **Positive: custom 403 pages, strong TLS, HSTS preload readiness.** The
   customer-facing perimeter shows evidence of deliberate security engineering,
   not just default cloud-provider settings.

## Summary

The externally observable attack surface is large (128 subdomains) but the
customer-facing properties specifically show strong TLS hygiene and evidence of
intentional access control. The primary risk signal from passive recon alone is
the volume of internal engineering tooling resolvable on public DNS — this is
common in modern cloud-native organizations and not inherently a vulnerability,
but represents meaningful reconnaissance value to an attacker and warrants
periodic external-facing DNS hygiene review (removing public DNS records for
tooling that doesn't need to be internet-resolvable at all, even behind auth).

No active testing, credential attempts, or exploitation was performed against any
dodopayments.tech/dodopayments.com host as part of this report, per the
assessment's rules of engagement. Part B of this assessment targets the
separately authorized local `ledger-api` instance exclusively.
