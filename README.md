# Project 2: Fully Automated SOAR Triage Pipeline

**Role Focus:** SOC Analyst · Security Automation Engineer

---

## What This Is

A miniature, production-grade SOC backend that **fully automates Tier-1 analyst triage** — from initial alert detection all the way to a pre-populated incident ticket — without a human touching anything.

When Wazuh detects a malicious login, the entire investigation runs itself in under 30 seconds:

```
Wazuh SIEM  →  n8n SOAR  →  VirusTotal + Azure AD  →  TheHive IR Case
```

---

## Architecture

```
  ┌─────────────┐    custom rule fires     ┌──────────────────┐
  │  SSH / RDP  │ ───────────────────────▶ │   Wazuh Manager  │
  │  Brute Force│                          │   (SIEM / IDS)   │
  └─────────────┘                          └────────┬─────────┘
                                                    │ webhook (JSON)
                                                    ▼
                                           ┌────────────────────────────────┐
                                           │         n8n  (SOAR)            │
                                           │                                │
                                           │  ┌──────────┐  ┌───────────┐  │
                                           │  │VirusTotal│  │ Azure AD  │  │
                                           │  │ IP Check │  │ User Check│  │
                                           │  └──────────┘  └───────────┘  │
                                           │         │              │       │
                                           │         └──────┬───────┘       │
                                           │                ▼               │
                                           │       Risk Scoring Engine      │
                                           │       (0 – 100 composite)      │
                                           └───────────────┬────────────────┘
                                                           │
                                                           ▼
                                           ┌───────────────────────────────┐
                                           │    TheHive  (IR Platform)     │
                                           │                               │
                                           │  Case auto-created with:      │
                                           │  • Full markdown report       │
                                           │  • IP + Username observables  │
                                           │  • 5 investigation tasks      │
                                           │  • MITRE ATT&CK tags          │
                                           │  • P1/P2 priority + assignee  │
                                           └───────────────────────────────┘
                                                    │ if risk ≥ 70
                                                    ▼
                                           ┌──────────────────────┐
                                           │  Slack P1 Page Alert │
                                           └──────────────────────┘
```

---

## Stack

| Component  | Tool               | Role                                           |
|------------|--------------------|------------------------------------------------|
| SIEM       | Wazuh 4.7          | Log ingestion, rule-based detection, alerts    |
| SOAR       | n8n (open-source)  | Workflow orchestration, API calls, logic       |
| Threat Intel| VirusTotal API v3 | IP reputation, malicious vendor count, country |
| Identity   | Azure AD / Entra ID | User profile, sign-in history, risk level    |
| IR Platform| TheHive 5          | Case management, observables, task tracking    |
| Notifier   | Slack Webhook      | P1 real-time escalation paging                 |

---

## Automated Detections (8 Rules)

All rules are in [`wazuh/custom-rules/local_rules.xml`](wazuh/custom-rules/local_rules.xml)

| Rule    | Scenario                              | Level | MITRE                       |
|---------|---------------------------------------|-------|-----------------------------|
| 100100  | SSH Brute Force (≥5 fails / 2 min)    | 10    | T1110.001                   |
| **100101** | **SSH Login AFTER brute force**    | **14**| T1110.004, T1078            |
| 100102  | RDP Brute Force (≥10 fails / 1 min)   | 10    | T1110.001, T1021.001        |
| **100103** | **RDP Login AFTER brute force**    | **14**| T1110, T1078, T1021.001     |
| 100104  | Login from unexpected country         | 12    | T1078                       |
| 100105  | After-hours authentication            | 10    | T1078                       |
| 100106  | Privilege escalation post-login       | 13    | T1078, T1548.003            |
| 100107  | Password spray (many accounts, 1 IP)  | 12    | T1110.003                   |

---

## n8n Workflow — Node-by-Node

The workflow lives in [`n8n/workflows/soar_triage_workflow.json`](n8n/workflows/soar_triage_workflow.json) and can be imported directly into n8n.

```
[Webhook]  →  [Extract Fields]  →  [VirusTotal IP]  ──────────┐
                                →  [AAD OAuth Token]           │
                                   → [AAD User Lookup]         │
                                     → [AAD Sign-in Logs]  ────┤
                                                               ▼
                                                    [Merge All Intel]
                                                               │
                                                    [Build Triage Report]
                                                    (JS: risk score + markdown)
                                                               │
                                                    [TheHive: Create Case]
                                                               │
                                          ┌────────────────────┤
                                          ▼                    ▼
                                 [Add IP Observable]   [Add User Observable]
                                          │
                                          ▼
                                    [P1 Check (risk ≥ 70)]
                                          │           │
                                          ▼           ▼
                                  [Slack Alert]  [Log Success]
```

**Parallel execution**: VirusTotal and Azure AD queries run simultaneously — total pipeline time ≈ 8–12 seconds.

---

## Risk Scoring Engine

The n8n Code node computes a composite risk score (0–100):

| Condition                   | Points |
|-----------------------------|--------|
| VT malicious detections > 5  | +40    |
| VT malicious detections 1–5  | +20    |
| Successful login post-attack | +30    |
| Geo-anomaly country          | +15    |
| Azure AD HIGH risk           | +25    |
| Azure AD MEDIUM risk         | +10    |
| Account disabled             | −10    |

| Score   | Label    | TheHive Severity | SOAR Action                   |
|---------|----------|------------------|-------------------------------|
| 75–100  | CRITICAL | Critical (4)     | P1 · Tier-2 · Slack page      |
| 50–74   | HIGH     | High (3)         | P1 · Tier-2 assign            |
| 25–49   | MEDIUM   | Medium (2)       | P2 · Tier-1 assign            |
| 0–24    | LOW      | Low (1)          | P3 · queue                    |

---

## What Gets Auto-Created in TheHive

Every triggered alert creates a case with:

- **Title** — `[P1] CRITICAL: SSH login after brute force — 185.220.101.45 → ubuntu-prod-01`
- **Full Markdown Report** containing:
  - Alert metadata (rule, severity, timestamp, agent)
  - VirusTotal: vendor count table, country, ASN, VT link
  - Azure AD: account status, department, risk level, last password change
  - Sign-in history table (last 5 with IP, location, MFA status)
  - MITRE ATT&CK techniques used
  - Raw log line from Wazuh
  - Recommended analyst actions (auto-tailored to scenario)
- **Observables**: source IP (marked IOC if malicious), target username
- **5 Investigation Tasks**: pre-assigned to correct tier
- **Tags**: `rule:100101`, `vt:MALICIOUS`, `priority:P1`, `T:T1110.004`, etc.

---

## Setup

### Prerequisites
- Docker Desktop with ≥8 GB RAM allocated
- VirusTotal API key (free tier works)
- Azure App Registration with `User.Read.All` + `AuditLog.Read.All` permissions

### 1. Clone & Configure

```bash
cd Project_2_SOAR_Triage_Pipeline

# Copy environment template
cp .env.example .env

# Edit with your real values
nano .env
```

**.env contents:**
```env
VT_API_KEY=your_virustotal_api_key
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-app-client-id
AZURE_CLIENT_SECRET=your-app-secret
AZURE_DOMAIN=corp.com
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

### 2. Generate Wazuh SSL Certificates

```bash
# Wazuh provides a certificate generation tool
docker run --rm \
  -v $(pwd)/wazuh/config:/tmp/certs \
  wazuh/wazuh-certs-generator:0.0.1 \
  -config /tmp/certs/config.yml
```

### 3. Start the Stack

```bash
docker compose up -d

# Check all services are healthy
docker compose ps
```

Services start order: Cassandra → Elasticsearch → Wazuh → TheHive → n8n

Allow ~3 minutes for full initialisation.

### 4. Import n8n Workflow

1. Open **http://localhost:5678** (admin / SOARpass123)
2. Click **Workflows → Import from file**
3. Select [`n8n/workflows/soar_triage_workflow.json`](n8n/workflows/soar_triage_workflow.json)
4. Add credentials:
   - **VirusTotal API Key** → `x-apikey` header credential
   - **TheHive API Key** → Bearer header credential
5. Set n8n Variables: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_DOMAIN`, `SLACK_WEBHOOK_URL`
6. **Activate** the workflow (toggle top-right)

### 5. Configure Wazuh Integration

```bash
# Copy integration script into running container
docker exec wazuh.manager bash -c "
  cp /var/ossec/integrations/custom-n8n.py /var/ossec/integrations/custom-n8n.py
  chown root:wazuh /var/ossec/integrations/custom-n8n.py
  chown root:wazuh /var/ossec/integrations/custom-n8n
  chmod 750 /var/ossec/integrations/custom-n8n*
"

# Restart Wazuh manager to pick up new rules + integration
docker restart wazuh.manager
```

### 6. Create TheHive API Key

1. Open **http://localhost:9000** (admin@thehive.local / secret)
2. Go to **Settings → Users → API Keys → Add Key**
3. Copy the key to your `.env` and n8n credentials

---

## Testing the Pipeline

### Automated End-to-End Test

```bash
# Simulate a credential stuffing breach (P1, highest severity)
python scripts/test_pipeline.py --scenario breach --ip 185.220.101.45 --user jsmith

# Brute force only (no successful login)
python scripts/test_pipeline.py --scenario bruteforce

# Geo-anomaly login from Russia
python scripts/test_pipeline.py --scenario geo --user alice

# Password spray against multiple accounts
python scripts/test_pipeline.py --scenario spray --ip 45.33.32.156
```

After running, check:
1. **n8n** → Executions → verify all nodes green
2. **TheHive** → Cases → new case with full report
3. **Slack** → escalation message (if P1)

### Real Agent Simulation

```bash
# Install a Wazuh agent on any Linux VM
# Then fire real SSH failures:
for i in {1..10}; do
  ssh wrongpass@<wazuh-agent-ip> 2>/dev/null
done

# Then a successful login — rule 100101 fires
ssh correctuser@<wazuh-agent-ip>
```

---

## Standalone Script Usage

```bash
# Check any IP against VirusTotal
export VT_API_KEY=your_key
python scripts/virustotal_check.py --ip 185.220.101.45

# Investigate a user in Azure AD
export AZURE_TENANT_ID=... AZURE_CLIENT_ID=... AZURE_CLIENT_SECRET=... AZURE_DOMAIN=corp.com
python scripts/azure_ad_check.py --user jsmith

# Manually create a TheHive case
export THEHIVE_URL=http://localhost:9000 THEHIVE_API_KEY=your_key
python scripts/thehive_create_case.py \
  --title "Suspicious login from 1.2.3.4" \
  --severity 3 \
  --src-ip 1.2.3.4 \
  --user alice
```

---

## Service URLs

| Service        | URL                        | Credentials              |
|----------------|----------------------------|--------------------------|
| Wazuh Dashboard| https://localhost           | admin / SecretPassword   |
| n8n SOAR       | http://localhost:5678       | admin / SOARpass123      |
| TheHive IR     | http://localhost:9000       | admin@thehive.local / secret |

---

## File Structure

```
Project_2_SOAR_Triage_Pipeline/
├── docker-compose.yml                  # Full stack definition
├── .env.example                        # Environment variable template
│
├── wazuh/
│   ├── custom-rules/
│   │   └── local_rules.xml             # 8 custom detection rules (100100-100107)
│   ├── integration/
│   │   ├── custom-n8n                  # Bash wrapper (Wazuh calls this)
│   │   └── custom-n8n.py              # Python integration script
│   └── config/
│       └── wazuh.manager.conf          # ossec.conf overlay with integration block
│
├── n8n/
│   └── workflows/
│       └── soar_triage_workflow.json   # Import-ready n8n workflow (12 nodes)
│
├── thehive/
│   └── config/
│       └── application.conf            # TheHive 5 config (Cassandra + ES)
│
├── scripts/
│   ├── virustotal_check.py             # Standalone VT IP/domain/hash lookup
│   ├── azure_ad_check.py              # Standalone Azure AD user investigation
│   ├── thehive_create_case.py         # Standalone TheHive case creator
│   └── test_pipeline.py               # End-to-end pipeline tester
│
├── docs/
│   └── architecture.md                 # ASCII architecture diagram + tables
│
└── sample_data/
    └── sample_wazuh_alert.json         # Real-format Wazuh alert example
```

---

## Skills Demonstrated

| Skill Area               | Evidence                                                    |
|--------------------------|-------------------------------------------------------------|
| SIEM Rule Writing        | 8 custom Wazuh rules with frequency, timeframe, MITRE tags  |
| SOAR Workflow Design     | 12-node n8n workflow with parallel branches + logic gates   |
| API Integration          | VirusTotal v3, Microsoft Graph, TheHive REST APIs           |
| Threat Intelligence      | IP reputation, geo-anomaly, ASN, vendor scoring             |
| Identity Investigation   | Azure AD risk levels, sign-in logs, group membership        |
| Incident Management      | Structured TheHive cases, observables, IOC tagging          |
| Risk Quantification      | Composite scoring model with conditional logic              |
| Automation Engineering   | Full Tier-1 triage without human intervention               |
| Python Scripting         | 4 standalone scripts covering every integration             |
| Infrastructure as Code   | Full stack Docker Compose (6 services)                      |

---

*Part of the [Jay Patel Cybersecurity Portfolio](../)*
