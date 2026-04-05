#!/usr/bin/env python3
"""
custom-n8n.py — Wazuh → n8n SOAR Webhook Integration
======================================================
Placed at: /var/ossec/integrations/custom-n8n.py
Permissions: chown root:wazuh && chmod 750

Triggered by Wazuh when any rule in the group "soar_trigger" fires.
Forwards the enriched alert payload to the n8n webhook, which starts
the automated triage workflow.

Configuration in ossec.conf:
  <integration>
    <name>custom-n8n</name>
    <hook_url>http://n8n:5678/webhook/wazuh-triage</hook_url>
    <rule_id>100100,100101,100102,100103,100104,100105,100106,100107</rule_id>
    <alert_format>json</alert_format>
  </integration>
"""

import sys
import json
import os
import re
import logging
from datetime import datetime, timezone
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode

# ── Logging ──────────────────────────────────────────────────────────────────
LOG_FILE = "/var/ossec/logs/integrations/custom-n8n.log"
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("custom-n8n")


# ── Severity Mapping ──────────────────────────────────────────────────────────
SEVERITY_MAP = {
    range(1, 4):   "low",
    range(4, 8):   "medium",
    range(8, 12):  "high",
    range(12, 16): "critical",
}


def level_to_severity(level: int) -> str:
    for r, label in SEVERITY_MAP.items():
        if level in r:
            return label
    return "unknown"


# ── Alert Enrichment ──────────────────────────────────────────────────────────
def build_payload(alert: dict) -> dict:
    """
    Extract and normalise alert fields into a structured payload
    that n8n will receive via the webhook trigger node.
    """
    rule      = alert.get("rule", {})
    data      = alert.get("data", {})
    agent     = alert.get("agent", {})
    manager   = alert.get("manager", {})
    location  = alert.get("location", "")

    # Source IP — check several common field paths
    src_ip = (
        data.get("srcip")
        or data.get("src_ip")
        or alert.get("decoder", {}).get("parent", "")
        or "unknown"
    )

    # Target username
    username = (
        data.get("dstuser")
        or data.get("win", {}).get("eventdata", {}).get("targetUserName", "")
        or data.get("user")
        or "unknown"
    )

    # Destination host
    dst_host = (
        data.get("dsthost")
        or agent.get("name", manager.get("name", "unknown"))
    )

    level = rule.get("level", 0)

    payload = {
        # ── Core Identity ─────────────────────────────────────────────────
        "alert_id":      alert.get("id", ""),
        "timestamp":     alert.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "wazuh_manager": manager.get("name", "wazuh-manager"),

        # ── Agent Info ────────────────────────────────────────────────────
        "agent": {
            "id":   agent.get("id", "000"),
            "name": agent.get("name", "unknown"),
            "ip":   agent.get("ip", "unknown"),
        },

        # ── Rule / Detection Info ─────────────────────────────────────────
        "rule": {
            "id":          rule.get("id", ""),
            "level":       level,
            "severity":    level_to_severity(level),
            "description": rule.get("description", ""),
            "groups":      rule.get("groups", []),
            "mitre":       rule.get("mitre", {}).get("id", []),
        },

        # ── Event Context ─────────────────────────────────────────────────
        "event": {
            "source_ip":  src_ip,
            "username":   username,
            "dest_host":  dst_host,
            "location":   location,
            "full_log":   alert.get("full_log", ""),
            "decoder":    alert.get("decoder", {}).get("name", ""),
        },

        # ── Triage Metadata (consumed by n8n branching logic) ─────────────
        "triage": {
            "is_brute_force":         "brute_force" in rule.get("groups", []),
            "is_post_auth_success":   any(
                g in rule.get("groups", [])
                for g in ("credential_stuffing", "authentication_success")
            ),
            "is_geo_anomaly":         "geo_anomaly" in rule.get("groups", []),
            "is_after_hours":         "after_hours" in rule.get("groups", []),
            "is_priv_escalation":     "privilege_escalation" in rule.get("groups", []),
            "is_password_spray":      "password_spray" in rule.get("groups", []),
            "soar_priority":          "P1" if level >= 12 else "P2" if level >= 10 else "P3",
        },

        # ── Raw alert for archival in TheHive ─────────────────────────────
        "raw_alert": alert,
    }

    return payload


# ── HTTP POST ─────────────────────────────────────────────────────────────────
def send_to_n8n(webhook_url: str, payload: dict) -> bool:
    """POST JSON payload to the n8n webhook URL."""
    body = json.dumps(payload).encode("utf-8")
    req  = Request(
        webhook_url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent":   "Wazuh-SOAR-Integration/1.0",
        },
        method="POST",
    )

    try:
        with urlopen(req, timeout=10) as resp:
            status = resp.status
            log.info("Webhook delivered — HTTP %d | Alert: %s | Rule: %s",
                     status, payload["alert_id"], payload["rule"]["id"])
            return True
    except HTTPError as e:
        log.error("HTTP error %d posting to n8n: %s", e.code, e.reason)
    except URLError as e:
        log.error("URL error posting to n8n: %s", e.reason)
    except Exception as e:
        log.exception("Unexpected error: %s", e)

    return False


# ── Entry Point ───────────────────────────────────────────────────────────────
def main():
    """
    Wazuh passes 3 args to integration scripts:
      sys.argv[1] — path to JSON alert file
      sys.argv[2] — API key (unused here, set in ossec.conf <api_key>)
      sys.argv[3] — webhook URL (set in ossec.conf <hook_url>)
    """
    if len(sys.argv) < 4:
        log.error("Usage: custom-n8n.py <alert_file> <api_key> <hook_url>")
        sys.exit(1)

    alert_file  = sys.argv[1]
    webhook_url = sys.argv[3]

    # Read alert JSON written by Wazuh
    try:
        with open(alert_file, "r", encoding="utf-8") as f:
            alert = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        log.error("Failed to read alert file %s: %s", alert_file, e)
        sys.exit(1)

    log.info("Processing alert ID=%s Rule=%s Level=%s",
             alert.get("id", "?"),
             alert.get("rule", {}).get("id", "?"),
             alert.get("rule", {}).get("level", "?"))

    payload = build_payload(alert)
    success = send_to_n8n(webhook_url, payload)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
