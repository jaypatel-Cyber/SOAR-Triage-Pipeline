#!/usr/bin/env python3
"""
thehive_create_case.py — TheHive 5 Case + Observable Creator
=============================================================
Standalone script to create a TheHive case programmatically.
Used for manual submissions, testing, or as a module from n8n Code nodes.

Usage:
  python thehive_create_case.py --title "SSH Brute Force from 185.220.101.45" \
      --severity 3 --tags "brute-force,ssh" --src-ip 185.220.101.45 --user jsmith

Env vars:
  THEHIVE_URL     — e.g. http://localhost:9000
  THEHIVE_API_KEY — TheHive API key
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError

THEHIVE_URL     = os.environ.get("THEHIVE_URL", "http://localhost:9000")
THEHIVE_API_KEY = os.environ.get("THEHIVE_API_KEY", "")


def hive_post(path: str, body: dict) -> dict:
    if not THEHIVE_API_KEY:
        sys.exit("[ERROR] Set THEHIVE_API_KEY env var")

    url   = f"{THEHIVE_URL}/api/v1/{path}"
    data  = json.dumps(body).encode("utf-8")
    req   = Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {THEHIVE_API_KEY}",
            "Content-Type":  "application/json",
        },
        method="POST",
    )

    try:
        with urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except HTTPError as e:
        body = e.read().decode()
        sys.exit(f"[ERROR] TheHive API {e.code}: {body}")
    except URLError as e:
        sys.exit(f"[ERROR] Cannot reach TheHive at {THEHIVE_URL}: {e.reason}")


def create_case(
    title:       str,
    description: str,
    severity:    int = 2,
    tlp:         int = 2,
    pap:         int = 2,
    tags:        list = None,
    assignee:    str = None,
    source:      str = "SOAR Pipeline",
    source_ref:  str = None,
) -> dict:
    """
    severity: 1=Low, 2=Medium, 3=High, 4=Critical
    tlp/pap:  0=WHITE, 1=GREEN, 2=AMBER, 3=RED
    """
    payload = {
        "title":       title,
        "description": description,
        "severity":    severity,
        "startDate":   datetime.now(timezone.utc).isoformat(),
        "tlp":         tlp,
        "pap":         pap,
        "tags":        tags or [],
        "status":      "New",
        "source":      source,
    }
    if assignee:
        payload["assignee"] = assignee
    if source_ref:
        payload["sourceRef"] = source_ref

    return hive_post("case", payload)


def add_observable(case_id: str, data_type: str, data: str,
                   message: str = "", tags: list = None,
                   ioc: bool = False, tlp: int = 2) -> dict:
    """
    data_type: ip | domain | url | hash | email | username | filename | registry
    """
    payload = {
        "dataType": data_type,
        "data":     data,
        "message":  message,
        "tlp":      tlp,
        "ioc":      ioc,
        "tags":     tags or [],
    }
    return hive_post(f"case/{case_id}/observable", payload)


def add_task(case_id: str, title: str, description: str = "",
             assignee: str = None, group: str = "Investigation") -> dict:
    payload = {
        "title":       title,
        "description": description,
        "group":       group,
        "status":      "Waiting",
    }
    if assignee:
        payload["assignee"] = assignee
    return hive_post(f"case/{case_id}/task", payload)


def create_full_investigation(
    alert_id:    str,
    src_ip:      str,
    username:    str,
    rule_desc:   str,
    severity:    int = 3,
    tags:        list = None,
) -> dict:
    """
    End-to-end: create case + add standard observables + add investigation tasks.
    Returns the created case object.
    """
    title = f"[SOAR] {rule_desc} — {src_ip}"

    description = f"""## Automated SOC Alert
**Alert ID**: `{alert_id}`
**Source IP**: `{src_ip}`
**Target User**: `{username}`
**Detection**: {rule_desc}

---
*This case was auto-created by the SOAR Triage Pipeline.
Enrich with VirusTotal, Azure AD data before escalating.*
"""

    case = create_case(
        title=title,
        description=description,
        severity=severity,
        tags=tags or [f"src_ip:{src_ip}", f"user:{username}", "soar-auto"],
        source="Wazuh SOAR Pipeline",
        source_ref=alert_id,
    )

    case_id = case.get("_id")
    if not case_id:
        return case

    print(f"[+] Case created: {case_id} — {title}")

    # Observables
    add_observable(case_id, "ip",       src_ip,   "Source IP from Wazuh alert",  ioc=True)
    add_observable(case_id, "username", username, "Target account")
    print(f"[+] Observables added")

    # Standard investigation tasks
    tasks = [
        ("Verify alert legitimacy",       "Contact user to confirm if login was authorised."),
        ("VirusTotal IP enrichment",      f"Check {src_ip} on VirusTotal and threat intel feeds."),
        ("Azure AD account review",       f"Check {username} sign-in logs, MFA status, risk level in Entra ID."),
        ("Lateral movement check",        "Search Wazuh for any events from this IP across all agents."),
        ("Block decision",                "Recommend IP block if malicious. Escalate to Tier-2 if P1."),
    ]
    for title_t, desc_t in tasks:
        add_task(case_id, title_t, desc_t)
    print(f"[+] {len(tasks)} investigation tasks added")

    return case


def main():
    parser = argparse.ArgumentParser(description="Create a TheHive case")
    parser.add_argument("--title",    required=True)
    parser.add_argument("--desc",     default="Auto-created by SOAR pipeline")
    parser.add_argument("--severity", type=int, default=2, choices=[1,2,3,4])
    parser.add_argument("--tags",     default="soar")
    parser.add_argument("--src-ip",   default=None)
    parser.add_argument("--user",     default=None)
    parser.add_argument("--alert-id", default="manual-test")
    args = parser.parse_args()

    tag_list = [t.strip() for t in args.tags.split(",")]

    if args.src_ip:
        result = create_full_investigation(
            alert_id=args.alert_id,
            src_ip=args.src_ip,
            username=args.user or "unknown",
            rule_desc=args.title,
            severity=args.severity,
            tags=tag_list,
        )
    else:
        result = create_case(
            title=args.title,
            description=args.desc,
            severity=args.severity,
            tags=tag_list,
        )

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
