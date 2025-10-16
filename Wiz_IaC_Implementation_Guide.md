# Wiz IaC Scanning and Implementation Guide for Unity

**Last Updated:** Oct 16, 2025  
**Author:** Timi Pere  

---

## 1. Introduction

Wiz provides agentless scanning and security analysis for Infrastructure-as-Code (IaC) templates and deployed cloud environments. This guide outlines how Wiz is integrated into Unity’s CI/CD pipelines, local development environments, and production runtime for continuous cloud security and compliance.

---

## 2. How Wiz Is Used in Unity

### Primary Method: CI/CD Pipeline (GitHub Actions)

- Automatically scans IaC templates (Terraform, Bicep, ARM, CloudFormation, Kubernetes manifests) on every Pull Request (PR) to `main` or `release` branches.  
- Triggers when a developer modifies IaC files or creates a PR.  
- Blocks merges if critical or high vulnerabilities are detected.  

**Benefits:**
- Detects misconfigurations, secrets, vulnerabilities, and compliance issues before deployment.  
- Ensures security gates in PRs with no manual effort.  

### Secondary Method: Wiz Portal

- URL: [https://app.wiz.io](https://app.wiz.io)  
- Used by Security and DevOps teams for:
  - Security dashboard visibility  
  - Continuous monitoring of Azure resources  
  - Compliance reporting (CIS, NIST, ISO, SOC2, HIPAA)  
  - Policy management  

**Access:** Security team and DevOps leads (read-only for most users).

### Tertiary Method: Wiz CLI (Optional)

Used by developers for local scans before committing code.

```bash
curl -o wizcli https://wizcli.app.wiz.io/latest/wizcli
chmod +x wizcli
sudo mv wizcli /usr/local/bin/
wizcli iac scan --path ./terraform --output results.json
```

---

## 3. Setup Wiz Code in Visual Studio Code

### Step 1: Install Wiz Code Extension
- Open VS Code → Extensions (`Ctrl+Shift+X`)
- Search and install **Wiz Code** by WizCloud

### Step 2: Authenticate Wiz Code
- Command Palette (`Ctrl+Shift+P`) → “Wiz: Authenticate”
- Login via browser with Wiz credentials

### Step 3: Scan IaC Files or Folders
- Right-click on a file/folder → “Scan with Wiz”
- Scans for:
  - Misconfigurations
  - Secrets exposure
  - Vulnerabilities
  - Compliance violations
- Results shown in Wiz Findings Panel with suggested remediations.

---

## 4. CI/CD Integration with GitHub Actions

### Step 1: Install Wiz CLI
```bash
npm install -g wiz-cli    # Windows
brew install --cask wizcli  # macOS
```

### Step 2: Create Wiz Service Account
- Wiz Portal → Settings → Access Management → Service Accounts  
- Create or use existing:
  - `DevOps_IaC_Scan`
  - `Terraform_IaC_Scan`

### Step 3: Configure GitHub Secrets
Repository → Settings → Secrets and Variables → Actions:
- `WIZ_CLIENT_ID`
- `WIZ_CLIENT_SECRET`

### Step 4: Add GitHub Workflow

`.github/workflows/wiz-iac-scan.yml`
```yaml
name: Wiz IaC Security Scan

on:
  pull_request:
    branches: [main, release]
    paths: ['**.tf', '**.bicep', '**.json']
  push:
    branches: [main, release]

jobs:
  wiz-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
      - uses: actions/checkout@v4
      - name: Download Wiz CLI
        run: |
          curl -o wizcli https://wizcli.app.wiz.io/latest/wizcli
          chmod +x wizcli && sudo mv wizcli /usr/local/bin/
      - name: Authenticate
        env:
          WIZ_CLIENT_ID: ${{ secrets.WIZ_CLIENT_ID }}
          WIZ_CLIENT_SECRET: ${{ secrets.WIZ_CLIENT_SECRET }}
        run: wizcli auth --id "$WIZ_CLIENT_ID" --secret "$WIZ_CLIENT_SECRET"
      - name: Run Scan
        run: wizcli iac scan --path . --output wiz-results.json --output-format json
      - name: Check Results
        run: |
          CRITICAL=$(jq '.summary.critical // 0' wiz-results.json)
          HIGH=$(jq '.summary.high // 0' wiz-results.json)
          if [[ "$GITHUB_REF" == "refs/heads/main" && "$CRITICAL" -gt 0 ]]; then exit 1; fi
          if [[ "$GITHUB_REF" == "refs/heads/release" && ("$CRITICAL" -gt 0 || "$HIGH" -gt 0) ]]; then exit 1; fi
      - name: Upload Results
        uses: actions/upload-artifact@v4
        with:
          name: wiz-scan-results
          path: wiz-results.json
```

### Optional: Fail Build on Critical Issues
```bash
jq '.findings[] | select(.severity == "CRITICAL")' wiz-results.json && exit 1 || exit 0
```

---

## 5. Branch Protection and Policies

| Branch | Scan Policy | Blocking Criteria | Approvals Required |
|---------|--------------|-------------------|--------------------|
| **Feature** | Informational | None | None |
| **Main** | Strict | Block on Critical | 1 Reviewer |
| **Release** | Very Strict | Block on Critical + High | 2 Reviewers + PSO |

**Main Branch**
- Require status check: “Wiz IaC Security Scan”  
- Block: Critical  
- Warn: High (>5)  
- Store reports for 30 days  

**Release Branch**
- Require status checks: Wiz + Compliance  
- Block: Critical or High  
- PSO approval mandatory  
- Store reports for 90 days  

---

## 6. Runtime Security of Infrastructure

### Agentless Continuous Scanning
- Azure resources scanned every 1–6 hours:
  - Configurations (hourly)
  - Vulnerabilities (every 4 hours)
  - Compliance (every 6 hours)
  - Network exposure (continuous)

### Monitored Assets
| Category | Checks |
|-----------|---------|
| Compute | OS CVEs, open ports, patching |
| AKS | Container images, RBAC misconfigurations |
| Data | Encryption, firewall, access |
| Identity | Overprivileged roles, managed identities |
| Network | NSG exposure, segmentation, DDoS protection |

### Alert Routing
| Severity | Destination | Response Time |
|-----------|--------------|----------------|
| Critical | PagerDuty + Slack `#security-critical` | 15 min |
| High | Slack `#security-alerts` + Email | 1 hour |
| Medium | Daily email digest | 1 day |
| Low | Weekly digest | Next sprint |

---

## 7. Vulnerability Prioritization and PSO Approval

| Wiz Severity | Environment | Internet-Facing | Priority | SLA |
|---------------|--------------|----------------|----------|------|
| Critical | Prod | Yes | P0 | 1 hr |
| Critical | Prod | No | P1 | 24 hrs |
| High | Prod | Yes | P1 | 24 hrs |
| High | Prod | No | P2 | 7 days |
| Medium | Any | Any | P3 | 30 days |
| Low | Any | Any | P4 | 90 days |

### PSO Approval Workflow
1. Wiz detects vulnerability  
2. Auto-create Jira ticket (Critical/High)  
3. Security triages (within 4 hours)  
4. Assigns to resource owner  
5. Remediation plan prepared  
6. PSO reviews and approves  
7. Fix implemented and verified  
8. Ticket closed  

**Remediation plan must include:**
- Technical fix description  
- Timeline and rollback plan  
- Risk and impact analysis  

---

## 8. Compliance and Policy Configuration

- Enable CSPM under Wiz Console → Settings → Cloud Integrations  
- Select Azure/AWS and integrate via API (agentless)  
- Use built-in frameworks (CIS, PCI-DSS, SOC2) or custom Rego rules  
- Visualize risks in the **Wiz Security Graph**

---

## 9. Common CLI Commands

### Authentication
```bash
wizcli auth --id "CLIENT_ID" --secret "CLIENT_SECRET"
wizcli auth status
```

### Scanning
```bash
wizcli iac scan --path .
wizcli iac scan --path ./terraform --output results.json
wizcli iac scan --path . --policy "Default IaC Policy"
```

### Analyzing Results
```bash
cat results.json | jq '.summary'
cat results.json | jq '.findings[] | select(.severity=="CRITICAL")'
```

---

## 10. References
- [Scan IaC files with Wiz CLI | Wiz Docs](https://docs.wiz.io/docs/scan-iac-files-with-wiz-cli#ia-c-scanning-usage)
- [Integrate Wiz with VS Code](https://docs.wiz.io/docs/integrate-wiz-with-vscode)
- [Wiz Policies Documentation](https://docs.wiz.io/docs/policies)
