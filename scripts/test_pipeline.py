#!/usr/bin/env python3
"""
test_pipeline.py — End-to-End SOAR Pipeline Simulator
======================================================
Fires a realistic Wazuh alert payload directly at the n8n webhook
to test the full automation pipeline without needing a real agent.

Usage:
  # Test brute force + successful login (highest severity)
  python test_pipeline.py --scenario breach

  # Test brute force only
  python test_pipeline.py --scenario bruteforce

  # Test geo-anomaly login
  python test_pipeline.py --scenario geo

  # Test password spray
  python test_pipeline.py --scenario spray

  # Custom IP and user
  python test_pipeline.py --scenario breach --ip 1.2.3.4 --user alice

Env vars:
  N8N_WEBHOOK_URL — default: http://localhost:5678/webhook/wazuh-triage
"""

import argparse
import json
import random
import string
import sys
import os
from datetime import datetime, timezone
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

N8N_WEBHOOK = os.environ.get("N8N_WEBHOOK_URL", "http://localhost:5678/webhook/wazuh-triage")


def rand_alert_id() -> str:
    return "".join(random.choices(string.hexdigits.lower(), k=16))


def make_alert(scenario: str, src_ip: str, username: str) -> dict:
    """Build a realistic Wazuh JSON alert for the given scenario."""

    base = {
        "id":        rand_alert_id(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "manager":   {"name": "wazuh-manager"},
        "agent": {
            "id":   "003",
            "name": "ubuntu-prod-01",
            "ip":   "10.0.1.10",
        },
        "location":  "/var/log/auth.log",
        "decoder":   {"name": "sshd"},
        "event":     {},
    }

    scenarios = {
        "bruteforce": {
            "rule": {
                "id":          "100100",
                "level":       10,
                "severity":    "high",
                "description": f"SSH Brute Force: {src_ip} fired 7 failures in 2 minutes against {username}",
                "groups":      ["authentication_failures", "brute_force", "soar_trigger"],
                "mitre":       {"id": ["T1110.001"]},
            },
            "data": {
                "srcip":   src_ip,
                "dstuser": username,
            },
            "triage": {
                "is_brute_force":        True,
                "is_post_auth_success":  False,
                "is_geo_anomaly":        False,
                "is_after_hours":        False,
                "is_priv_escalation":    False,
                "is_password_spray":     False,
                "soar_priority":         "P2",
            },
            "full_log": f"Mar 15 22:14:32 ubuntu-prod-01 sshd[4821]: Failed password for {username} from {src_ip} port 54321 ssh2",
        },

        "breach": {
            "rule": {
                "id":          "100101",
                "level":       14,
                "severity":    "critical",
                "description": f"CRITICAL: Successful SSH login from {src_ip} after brute force — possible credential stuffing or compromise of {username}",
                "groups":      ["authentication_success", "brute_force", "credential_stuffing", "soar_trigger"],
                "mitre":       {"id": ["T1110.004", "T1078"]},
            },
            "data": {
                "srcip":   src_ip,
                "dstuser": username,
            },
            "triage": {
                "is_brute_force":        True,
                "is_post_auth_success":  True,
                "is_geo_anomaly":        False,
                "is_after_hours":        True,
                "is_priv_escalation":    False,
                "is_password_spray":     False,
                "soar_priority":         "P1",
            },
            "full_log": f"Mar 15 23:47:01 ubuntu-prod-01 sshd[4891]: Accepted password for {username} from {src_ip} port 54328 ssh2",
        },

        "geo": {
            "rule": {
                "id":          "100104",
                "level":       12,
                "severity":    "high",
                "description": f"Suspicious Geolocation Login: {username} authenticated from {src_ip} in Russia — outside expected countries",
                "groups":      ["authentication_success", "geo_anomaly", "soar_trigger"],
                "mitre":       {"id": ["T1078"]},
            },
            "data": {
                "srcip":             src_ip,
                "dstuser":           username,
                "srcgeoip_country":  "RU",
                "srcgeoip_country_name": "Russia",
            },
            "triage": {
                "is_brute_force":        False,
                "is_post_auth_success":  True,
                "is_geo_anomaly":        True,
                "is_after_hours":        False,
                "is_priv_escalation":    False,
                "is_password_spray":     False,
                "soar_priority":         "P2",
            },
            "full_log": f"Mar 15 09:12:55 ubuntu-prod-01 sshd[5023]: Accepted publickey for {username} from {src_ip} port 49822 ssh2",
        },

        "spray": {
            "rule": {
                "id":          "100107",
                "level":       12,
                "severity":    "high",
                "description": f"Password Spray Detected: {src_ip} attempted login against 8 different accounts in 3 minutes",
                "groups":      ["authentication_failures", "password_spray", "soar_trigger"],
                "mitre":       {"id": ["T1110.003"]},
            },
            "data": {
                "srcip":   src_ip,
                "dstuser": username,
            },
            "triage": {
                "is_brute_force":        False,
                "is_post_auth_success":  False,
                "is_geo_anomaly":        False,
                "is_after_hours":        False,
                "is_priv_escalation":    False,
                "is_password_spray":     True,
                "soar_priority":         "P2",
            },
            "full_log": f"Mar 15 14:33:10 ubuntu-prod-01 sshd[6671]: Failed password for {username} from {src_ip} port 45001 ssh2",
        },
    }

    if scenario not in scenarios:
        sys.exit(f"[ERROR] Unknown scenario '{scenario}'. Choose: {list(scenarios.keys())}")

    sc = scenarios[scenario]
    payload = {**base}
    payload["rule"]     = sc["rule"]
    payload["data"]     = sc["data"]
    payload["triage"]   = sc["triage"]
    payload["full_log"] = sc["full_log"]

    # Enrich with event fields (mirrors what custom-n8n.py produces)
    payload["event"] = {
        "source_ip":  src_ip,
        "username":   username,
        "dest_host":  base["agent"]["name"],
        "location":   base["location"],
        "full_log":   sc["full_log"],
        "decoder":    "sshd",
    }

    return payload


def send_alert(payload: dict, webhook_url: str) -> None:
    body = json.dumps(payload).encode("utf-8")
    req  = Request(
        webhook_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urlopen(req, timeout=15) as resp:
            status   = resp.status
            response = resp.read().decode()
            print(f"[+] Webhook delivered — HTTP {status}")
            try:
                print(f"    Response: {json.dumps(json.loads(response), indent=2)}")
            except Exception:
                print(f"    Response: {response}")
    except HTTPError as e:
        print(f"[-] HTTP error {e.code}: {e.read().decode()}")
    except URLError as e:
        print(f"[-] Cannot reach n8n at {webhook_url}")
        print(f"    Make sure n8n is running (docker compose up)")
        print(f"    Reason: {e.reason}")


def main():
    parser = argparse.ArgumentParser(description="SOAR pipeline end-to-end test")
    parser.add_argument("--scenario", default="breach",
                        choices=["bruteforce", "breach", "geo", "spray"],
                        help="Attack scenario to simulate")
    parser.add_argument("--ip",   default="185.220.101.45", help="Source IP (use a known-bad IP for VT hits)")
    parser.add_argument("--user", default="jsmith",          help="Target username")
    parser.add_argument("--url",  default=N8N_WEBHOOK,        help="n8n webhook URL")
    parser.add_argument("--dry-run", action="store_true",    help="Print payload without sending")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  SOAR Pipeline Test — Scenario: {args.scenario.upper()}")
    print(f"{'='*60}")
    print(f"  Source IP   : {args.ip}")
    print(f"  Target User : {args.user}")
    print(f"  Webhook     : {args.url}")
    print(f"{'='*60}\n")

    alert = make_alert(args.scenario, args.ip, args.user)

    if args.dry_run:
        print("[DRY RUN] Alert payload:")
        print(json.dumps(alert, indent=2))
        return

    print(f"[*] Sending {args.scenario} alert to n8n...")
    send_alert(alert, args.url)
    print(f"\n[*] Done. Check n8n workflow execution and TheHive for the case.")


if __name__ == "__main__":
    main()
