# SOAR Triage Pipeline — Architecture

## Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SOAR TRIAGE PIPELINE                                 │
│                     Automated Tier-1 SOC Response                           │
└─────────────────────────────────────────────────────────────────────────────┘

  DETECTION LAYER                ORCHESTRATION LAYER              RESPONSE LAYER
  ───────────────                ───────────────────              ──────────────

  ┌─────────────┐
  │   SSH/RDP   │  failed auth
  │   Linux/Win │─────────────┐
  │   Endpoints │             │
  └─────────────┘             ▼
                       ┌─────────────┐
  ┌─────────────┐      │             │
  │  Wazuh      │      │   Wazuh     │
  │  Agents     │─────▶│   Manager   │
  │  (3-5 hosts)│      │   (SIEM)    │
  └─────────────┘      │             │
                       │ Rules fire: │
                       │ 100100-107  │
                       └──────┬──────┘
                              │ custom-n8n.py
                              │ HTTP POST (JSON)
                              ▼
                       ┌─────────────────────────────────────────────────────┐
                       │                    n8n SOAR                         │
                       │                                                     │
                       │  [Webhook] ──▶ [Extract Fields]                    │
                       │                       │                             │
                       │            ┌──────────┴──────────┐                 │
                       │            ▼                     ▼                 │
                       │     ┌─────────────┐    ┌─────────────────┐        │
                       │     │ VirusTotal  │    │   Azure AD      │        │
                       │     │  API (v3)   │    │  Graph API      │        │
                       │     │             │    │                 │        │
                       │     │ IP Verdict  │    │ User Profile    │        │
                       │     │ Country/ASN │    │ Sign-in History │        │
                       │     │ Malicious # │    │ Risk Level      │        │
                       │     │ VT Link     │    │ Group Memberships│       │
                       │     └──────┬──────┘    └───────┬─────────┘        │
                       │            │                   │                   │
                       │            └─────────┬─────────┘                  │
                       │                      ▼                             │
                       │              [Merge + Build Report]                │
                       │              - Risk Score (0-100)                  │
                       │              - Markdown Case Description           │
                       │              - TheHive severity mapping            │
                       │                      │                             │
                       └──────────────────────┼─────────────────────────────┘
                                              │
                                              ▼
                       ┌──────────────────────────────────────┐
                       │            TheHive 5 (IR)            │
                       │                                      │
                       │  ┌─────────────────────────────┐    │
                       │  │         CASE CREATED         │    │
                       │  │                              │    │
                       │  │  Title: [P1] Brute force...  │    │
                       │  │  Severity: CRITICAL          │    │
                       │  │  Assignee: tier2-analyst     │    │
                       │  │                              │    │
                       │  │  Observables:                │    │
                       │  │   • IP: 185.220.101.45 (IOC) │    │
                       │  │   • Username: jsmith         │    │
                       │  │                              │    │
                       │  │  Tasks (auto-generated):     │    │
                       │  │   ☐ Verify alert legitimacy  │    │
                       │  │   ☐ VirusTotal enrichment    │    │
                       │  │   ☐ Azure AD review          │    │
                       │  │   ☐ Lateral movement check   │    │
                       │  │   ☐ Block decision           │    │
                       │  └─────────────────────────────┘    │
                       └──────────────────────────────────────┘
                                              │
                              Risk Score ≥ 70 │
                                              ▼
                       ┌──────────────────────────────────────┐
                       │     Slack P1 Escalation Webhook      │
                       │   "🚨 P1 Security Incident — Now"    │
                       └──────────────────────────────────────┘
```

## Risk Scoring Engine

The n8n Code node calculates a composite risk score (0–100):

| Condition                          | Score Delta |
|------------------------------------|-------------|
| VT malicious detections > 5        | +40         |
| VT malicious detections 1-5        | +20         |
| Post-authentication success        | +30         |
| Geo-anomaly (unexpected country)   | +15         |
| Azure AD risk level = HIGH         | +25         |
| Azure AD risk level = MEDIUM       | +10         |
| Account is disabled                | -10         |

| Score   | Label    | TheHive Severity | Action             |
|---------|----------|------------------|--------------------|
| 75–100  | CRITICAL | 4 — Critical     | P1, Slack page     |
| 50–74   | HIGH     | 3 — High         | P1, Tier-2 assign  |
| 25–49   | MEDIUM   | 2 — Medium       | P2, Tier-1 assign  |
| 0–24    | LOW      | 1 — Low          | P3, queue          |

## Detection Rules Coverage

| Rule ID | Scenario                     | Level | Priority |
|---------|------------------------------|-------|----------|
| 100100  | SSH Brute Force (5+ fails)   | 10    | P2       |
| 100101  | SSH Login AFTER brute force  | 14    | P1       |
| 100102  | RDP Brute Force (10+ fails)  | 10    | P2       |
| 100103  | RDP Login AFTER brute force  | 14    | P1       |
| 100104  | Login from geo-anomaly       | 12    | P2       |
| 100105  | After-hours authentication   | 10    | P2       |
| 100106  | Priv escalation post-login   | 13    | P1       |
| 100107  | Password spray (many users)  | 12    | P2       |

## Component Ports

| Service          | Port  | Purpose                  |
|------------------|-------|--------------------------|
| Wazuh Dashboard  | 443   | SIEM web UI              |
| Wazuh API        | 55000 | REST API                 |
| Wazuh Agent Reg  | 1515  | Agent enrollment         |
| n8n              | 5678  | SOAR UI + Webhook        |
| TheHive          | 9000  | IR Platform UI + API     |
| Elasticsearch    | 9200  | TheHive index (internal) |
| Cassandra        | 9042  | TheHive DB (internal)    |
