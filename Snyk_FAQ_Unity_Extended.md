# 🔐 Snyk Integration & Usage – FAQ + Implementation Guide

This document consolidates how Snyk is integrated and used at Unity, and provides practical, step‑by‑step guides for running Snyk **without code changes**, integrating with **GitHub Enterprise (GHEC/ GHES)**, and using the **Snyk CLI** in CI/CD.

> Fill in `___` placeholders where internal details are required.

---

## 🧭 Executive Summary

- **Today**: Snyk runs in **GitHub Actions** for **SAST (Snyk Code)** and **SCA** on every **push/PR** to `main` and `rc`. Results are shown in **GitHub Checks** and the **Snyk dashboard**.  
- **Near‑term expansion**: Consider enabling **Snyk Container**, **Snyk IaC**, and **automated ticketing/reporting** (Jira/ServiceNow), with **org-wide policies** for gating builds on severity.  
- **Administration**: Managed by **PSO** with support from designated **technical owners**. Business Owner defines overall responsibility (___).  
- **Branch strategy**: `main` is continuously monitored; release branches scanned pre‑release with separate reporting views (___ finalize policy).  
- **Reporting**: Automated org‑level reporting via Snyk **Projects**, **tags**, **email schedules**, and optional **API exports** (___ finalize recipients + cadence).

---

## ❓ FAQs (with Unity context)

### How is Snyk working as of today in Unity?
Snyk is integrated into Unity’s **CI/CD via GitHub Actions**. It runs **SAST (Snyk Code)** and **SCA** on every **PR/push** to `main` and `rc`, pushing results to **GitHub Checks** and the **Snyk dashboard**. Baseline scans are monitored via `snyk monitor` for ongoing visibility.

### How will Snyk be consumed in the future?
Planned/Recommended:
- **Snyk Container** for images and Kubernetes workloads.  
- **Snyk IaC** for Terraform/K8s/Helm config checks.  
- **Ticketing integration** (Jira/ServiceNow) with auto‑create rules for High/Critical.  
- **Org policies** enforcing severity thresholds and license policies.  
- **Unified tagging** for repo/team/app/environment to power dashboards & SLAs.

### Who manages (admin part) the tool for Unity?
- **Business Owner**: ___  
- **Day‑to‑day admin** (user onboarding, policies, integrations): **PSO** with designated technical owners: ___

### How are Main vs Release branches managed for Snyk reporting?
- **`main`**: Always‑on scanning for every PR/commit; dashboard is the primary reporting source.  
- **Release branches**: Scanned prior to release; optionally use **separate tags** (e.g., `branch:release/*`) to filter reports.  
- **Policy**: ___ (e.g., block merges on High/Critical; allow with waiver + SLA).

### How will automated reporting work for current and future repos?
- **Current repos**: Already monitored; nightly re‑tests and PR checks in place.  
- **Future repos**: Auto‑onboard via Snyk GitHub App selection or org‑wide auto‑import rules (___).  
- **Distribution**: Weekly email digest to ___; Jira/ServiceNow issues for High/Critical; optional API exports to BI.  
- **Tagging**: Adopt `team:<name>`, `app:<name>`, `env:<dev|qa|prod>`, `branch:<main|release/*>` for roll‑up dashboards.

---

## 🧪 Running Snyk **Without Code Changes**

You can add Snyk coverage from the **platform/pipeline layer** without editing application code:

1. **Connect Repos in Snyk (UI)**  
   - In Snyk → **Integrations → Source Control → GitHub (Enterprise)**  
   - Install the **Snyk GitHub App** (GHEC) or configure **GHES**.  
   - Select repos to import. Snyk will discover **manifests/lockfiles** and create **Projects**.

2. **Pipeline (CI) Steps**  
   - Add a CI job to run Snyk **without modifying code**:  
     ```bash
     npm i -g snyk
     snyk auth  # Uses SNYK_TOKEN env var in CI
     snyk test          # SCA against manifests
     snyk code test     # SAST (needs repo source, but no code edits)
     snyk iac test      # IaC files
     snyk monitor       # Save snapshot to dashboard for trending
     ```

3. **Container Image Scans** (no code changes)  
   ```bash
   snyk container test your.registry/app:tag
   snyk container monitor your.registry/app:tag
   ```

4. **IaC Scans** (no code changes)  
   ```bash
   snyk iac test ./infra/
   snyk iac test ./k8s/ --report
   ```

5. **Org‑level Policies (no repo edits)**  
   - Prefer **org policies** (severity/licensing) instead of `.snyk` policy files to avoid code changes.  
   - Configure **fail‑the‑build** behavior in CI via exit codes or Snyk Action inputs.

---

## 📈 Impact on **SCA** and **SAST** Features (no code changes)

- **SCA (Dependencies)**  
  - ✅ Works fully by scanning **manifests + lockfiles** (e.g., `pom.xml`, `package-lock.json`, `requirements.txt`).  
  - No code edits required. Includes reachable‑path analysis where supported.

- **SAST (Snyk Code)**  
  - ✅ No code edits required, but **source code must be present** in the repo/CI workspace.  
  - Results quality depends on having complete code; monorepos supported.  
  - PR checks/inline annotations available with GitHub integration.

- **Container & IaC**  
  - ✅ 100% feasible with no code edits; runs on artifacts/configs produced by CI or stored in repo.

---

## 🧩 Option 1: Native **Snyk + GitHub Enterprise** Integration (Recommended)

### A) **GitHub Enterprise Cloud (GHEC)** – easiest path
1. In Snyk, navigate to **Integrations → Source Control → GitHub** (Enterprise Cloud).  
2. **Install the Snyk GitHub App** to your Enterprise org.  
3. **Select repositories** (or allow org‑wide).  
4. Snyk imports repos → creates **Projects** (SCA, SAST, IaC, Container where applicable).  
5. Enable **PR Checks** (branch protection optional) so findings appear inline in PRs.  
6. Configure **org policies** (severity thresholds, license policies).  
7. Set **notifications** (email/Slack) and **ticketing** (Jira/ServiceNow) rules.  
8. Add **tags** at import or via API to support dashboards and SLA views.  

**Branch Protection Example (GitHub)**  
- Require status checks to pass: `snyk (SCA)`, `snyk-code (SAST)`  
- Dismiss stale approvals when new commits are pushed.  
- Require linear history or signed commits (optional, per policy).

### B) **GitHub Enterprise Server (GHES)** – if self‑hosted
- Choose **Direct Integration** (open firewall for Snyk SaaS to reach GHES API) **or** deploy **[Snyk Broker](https://docs.snyk.io/integrations/snyk-broker)** as a secure proxy.  
- Steps mirror GHEC once connectivity is established.  
- Confirm API endpoint (e.g., `https://github.company.com/api/v3`) and install the Snyk App.

---

## 🧪 Option 2: Pipeline‑Based Scanning with **Snyk CLI** (no direct integration)

Use the CLI inside your CI system (GitHub Actions, Jenkins, Azure DevOps, GitLab CI, etc.).

### GitHub Actions – **Language‑agnostic** template
```yaml
name: Snyk Scan
on:
  pull_request:
  push:
    branches: [ "main", "release/*" ]

jobs:
  snyk:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node (for CLI)
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install Snyk
        run: npm i -g snyk

      - name: Auth
        run: snyk auth
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}

      - name: SCA (Dependencies)
        run: snyk test --all-projects --severity-threshold=high

      - name: SAST (Snyk Code)
        run: snyk code test --severity-threshold=high

      - name: IaC
        run: snyk iac test ./infra --report || true  # non-blocking example

      - name: Container (if image available)
        run: |
          docker pull your.registry/app:tag
          snyk container test your.registry/app:tag --severity-threshold=high

      - name: Monitor (save snapshot to dashboard)
        run: snyk monitor --all-projects
```

### Maven/Gradle/Node/Python – examples
```bash
# Maven
snyk test --maven
# Gradle
snyk test --all-sub-projects
# Node
snyk test --yarn-workspaces --detection-depth=4
# Python
snyk test --file=requirements.txt --package-manager=pip
```

**Build Blocking**  
- Use `--severity-threshold=high` to fail builds on High/Critical only.  
- Or allow pass with `|| true` for non‑blocking jobs in early rollout phases.

---

## ☁️ GitHub Enterprise Cloud (GHEC) – Step‑by‑Step

1. **Prereqs**  
   - GitHub Enterprise Cloud org admin rights.  
   - Snyk org admin & seat licenses available.  
   - Decide repo scope: **selected repos** vs **all repositories**.

2. **Install Snyk GitHub App**  
   - From Snyk: **Integrations → GitHub**.  
   - Click **Install** and pick your GHEC org.  
   - Grant requested permissions (Contents, Metadata, Pull Requests, Checks).

3. **Select Repos & Import**  
   - Choose repos to monitor (or all).  
   - Snyk creates **Projects** per manifest/source.  
   - Optional: apply **tags** on import (e.g., `team:platform`, `app:unity`, `env:prod`).

4. **Enable PR Checks & Policies**  
   - In GitHub, add **required status checks** to branch protection.  
   - In Snyk, set **severity/licensing policies** at org level.  
   - Decide **blocking vs advisory** for initial rollout.

5. **Notifications & Ticketing**  
   - Configure **email/Slack** notifications for new vulns or regressions.  
   - Set **Jira/ServiceNow** automation (High/Critical → create ticket).  
   - Define SLAs (e.g., Critical: 7 days; High: 30 days).

6. **Reporting & Cadence**  
   - Schedule **weekly digest** to security + engineering leads (___).  
   - Use **tags** to build team/app dashboards.  
   - Optionally export via **Snyk API** to BI or data lake.

7. **Scale & Hygiene**  
   - Auto‑import new repos (___ decide policy).  
   - Quarterly review of inactive projects.  
   - Maintain **owner mapping** via tags or repo naming conventions.

---

## 🏷️ Tagging & Naming Recommendations

- **Tags**: `team:<name>`, `app:<name>`, `env:<dev|qa|prod>`, `service:<svc>`, `branch:<main|release/*>`  
- **Use cases**: Filter dashboards, route notifications, and enforce SLAs by team/app/env.

---

## 📤 Example: Weekly Reporting via CLI (JSON export)

```bash
# Export Snyk org issues as JSON (example; requires SNYK_TOKEN, org id)
snyk test --all-projects --json > snyk-findings.json
# Or use Snyk API for richer exports (issues, projects, tags) to feed BI dashboards.
```

> Note: Prefer built‑in Snyk email schedules and dashboard views where possible; use API/CLI exports for custom BI.

---

## ✅ Rollout Checklist

- [ ] Install Snyk GitHub App (GHEC) and import target repos.  
- [ ] Add CI step with `snyk test` / `snyk code test` / `snyk monitor`.  
- [ ] Configure org policies and branch protection.  
- [ ] Define tagging convention and apply consistently.  
- [ ] Set notification + ticketing workflows and SLAs.  
- [ ] Schedule weekly reports and quarterly hygiene.  
- [ ] Plan enablement for **Snyk Container** and **Snyk IaC**.

---

## 📎 References (fill internal links)

- Internal runbook: ___  
- Snyk org & seat management: ___  
- Jira/ServiceNow automation rules: ___  
- Reporting recipients & cadence: ___



---

## 🚀 Additional Recommendations & Roadmap

This section outlines governance, process, and scale patterns to turn Snyk usage into an enterprise‑grade AppSec program.

### 1) Role‑Based Access & Governance
**Goal:** Clear ownership, least‑privilege, and repeatable onboarding/offboarding.
- **Org Structure:** One Snyk Org per business unit or environment (e.g., `Unity‑Prod`, `Unity‑NonProd`).  
- **RBAC:**  
  - *Org Admins:* PSO + designated technical owners (___).  
  - *Project Admins:* Repo/service owners.  
  - *Viewers/Reporters:* Leads, auditors, compliance.  
- **On/Offboarding:**  
  - Standard request via ITSM (___).  
  - 30/60/90‑day access reviews.  
  - Immediate removal on role change.

### 2) Waivers / Risk Acceptance Process
**Goal:** Formal, time‑boxed exceptions with visibility.
- **Request Template:** vuln ID, justification, compensating controls, expiry date, owner.  
- **Approval:** PSO/AppSec (___) with change record #.  
- **Tracking:** Tag projects/issues `risk‑accepted:true`, auto‑remind 7 days before expiry.  
- **Audit:** Monthly waiver report to ___.

### 3) Severity SLAs & Policy Enforcement
**Goal:** Predictable remediation timelines and automated guardrails.
- **Suggested SLAs:** Critical 7d, High 30d, Medium 90d, Low 180d (confirm with PSO).  
- **CI Rules:**  
  - Block on **Critical/High** for `main` and release branches.  
  - Advisory only on feature branches initially.  
- **License Policy:** Define allow/deny list for OSS licenses (___).

### 4) Audit & Compliance Reporting
**Goal:** Evidence for SOX/ISO/FDA/PCI with minimal toil.
- **Evidence Pack:** Monthly PDF/CSV export (Snyk dashboards + API pulls).  
- **Controls Mapping:** Link checks to controls (e.g., ISO 27001 A.12, FDA CSV section ___).  
- **Retention:** Store exports in GxP/controlled SharePoint with metadata (___).

### 5) Integrations (Tickets / SIEM / ChatOps)
**Goal:** Fast routing, measurable closure, and higher signal‑to‑noise.
- **Jira/ServiceNow:** Auto‑create for Critical/High; set component/labels from tags.  
- **SIEM (Splunk/Datadog/ELK):** Stream new‑issue events for correlation with runtime signals.  
- **ChatOps:** Slack/Teams alerts to `#appsec‑alerts‑<team>` on regressions.

### 6) Advanced Reporting & KPIs
**Goal:** Outcome‑based visibility for leadership and teams.
- **Coverage:** `% repos onboarded`, `% pipelines with Snyk`, `% images scanned`.  
- **Risk Posture:** `Open Critical/High`, `Mean time to remediate (MTTR)`, `SLA adherence`.  
- **Trend:** 30/60/90‑day burn‑down by team/app/env.  
- **Drill‑downs:** Use tags: `team:<name>`, `app:<name>`, `env:<dev|qa|prod>`, `branch:<...>`.

### 7) Developer Enablement
**Goal:** Shift‑left with fewer false positives and faster fixes.
- **IDE Plugins:** VS Code/IntelliJ Snyk extensions rollout and training.  
- **Playbooks:** “How to fix” guides per language stack (___).  
- **Office Hours:** Monthly AppSec clinics; publish recordings & tips.  
- **Golden Paths:** Sample pipelines with Snyk steps pre‑wired.

### 8) Future Expansion
**Goal:** Broaden coverage and unify risk signals.
- **License Compliance:** Enable Snyk license policies + legal review workflow.  
- **AppRisk:** Evaluate Snyk AppRisk to correlate SAST/SCA/Container/IaC to business context.  
- **DAST Complement:** Standardize on OWASP ZAP/Burp Enterprise for runtime testing; feed into unified reporting.  
- **Third‑Party/Vendor Code:** Contractual clauses to provide SBOM + vulnerability posture; import into Snyk/Cybeats.

### 9) RACI (Sample) for Vulnerability Management
| Task | PSO | Dev Team | App Owner | Platform/DevOps | Compliance |
|---|---|---|---|---|---|
| Tool Admin & Policy | **R** | C | C | C | I |
| Onboarding/Offboarding | **R** | C | C | C | I |
| PR Check Enforcement | C | **R** | A | **R** | I |
| Triage Critical/High | **R** | **R** | A | C | I |
| Waiver Approval | **A** | R | **A** | C | I |
| Reporting & Audits | **R** | C | C | C | **A** |

> **R = Responsible, A = Accountable, C = Consulted, I = Informed**

### 10) Sample Quarterly Objectives (OKRs)
- **KR1:** ≥95% repos onboarded to Snyk scanning.  
- **KR2:** ≥90% Critical vulns remediated within SLA.  
- **KR3:** Reduce Critical/High backlog by **40%** QoQ.  
- **KR4:** Enable Snyk Container for ≥80% of production images.

---

## 📚 Appendices

- **Conventions:** Tag schema, branch naming, repo naming.  
- **Templates:** Waiver request, exception review, remediation plan.  
- **APIs:** Saved queries for exports (`/orgs/{id}/projects`, `/issues`, `/reporting`).  
- **Training:** Slide decks, recordings, labs (___ links).

