#!/usr/bin/env python3
"""
azure_ad_check.py — Microsoft Graph API User Investigation
===========================================================
Queries Azure AD (Entra ID) for a user's profile, risk state,
recent sign-in logs, and group memberships.

Usage:
  python azure_ad_check.py --user jsmith
  python azure_ad_check.py --user john.smith@corp.com --json

Required env vars:
  AZURE_TENANT_ID     — Directory (tenant) ID
  AZURE_CLIENT_ID     — App registration client ID
  AZURE_CLIENT_SECRET — App registration client secret
  AZURE_DOMAIN        — UPN suffix, e.g. corp.com (if using short usernames)

Required Graph API permissions (application):
  User.Read.All
  AuditLog.Read.All
  IdentityRiskyUser.Read.All
"""

import argparse
import json
import os
import sys
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode

GRAPH_BASE = "https://graph.microsoft.com/v1.0"


# ── Auth ──────────────────────────────────────────────────────────────────────
def get_access_token() -> str:
    tenant_id = os.environ.get("AZURE_TENANT_ID", "")
    client_id = os.environ.get("AZURE_CLIENT_ID", "")
    secret    = os.environ.get("AZURE_CLIENT_SECRET", "")

    if not all([tenant_id, client_id, secret]):
        sys.exit("[ERROR] Set AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET")

    url  = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    body = urlencode({
        "grant_type":    "client_credentials",
        "client_id":     client_id,
        "client_secret": secret,
        "scope":         "https://graph.microsoft.com/.default",
    }).encode("utf-8")

    req = Request(url, data=body, method="POST")
    try:
        with urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())["access_token"]
    except HTTPError as e:
        body = e.read().decode()
        sys.exit(f"[ERROR] Auth failed ({e.code}): {body}")
    except URLError as e:
        sys.exit(f"[ERROR] Network error: {e.reason}")


def graph_get(path: str, token: str) -> dict:
    url = f"{GRAPH_BASE}/{path}"
    req = Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except HTTPError as e:
        if e.code == 404:
            return {"error": "not_found"}
        body = e.read().decode()
        return {"error": f"http_{e.code}", "detail": body}
    except URLError as e:
        return {"error": "network", "detail": str(e.reason)}


# ── Investigation ─────────────────────────────────────────────────────────────
def investigate_user(username: str, token: str) -> dict:
    # Normalise: if no @ append domain
    domain = os.environ.get("AZURE_DOMAIN", "")
    upn = username if "@" in username else (f"{username}@{domain}" if domain else username)

    # 1. Core user profile
    select = "displayName,userPrincipalName,accountEnabled,department,jobTitle,officeLocation,lastPasswordChangeDateTime,createdDateTime,riskLevel,riskState,riskLastUpdatedDateTime"
    profile = graph_get(f"users/{upn}?$select={select}", token)

    if "error" in profile:
        return {"upn": upn, "found": False, "error": profile}

    # 2. Group memberships
    groups_raw = graph_get(f"users/{upn}/memberOf?$select=displayName,id", token)
    groups = [g["displayName"] for g in groups_raw.get("value", [])]

    # 3. Recent sign-ins (last 10)
    signin_filter = f"userPrincipalName eq '{upn}'"
    signins_raw = graph_get(
        f"auditLogs/signIns?$filter={signin_filter}&$top=10&$orderby=createdDateTime desc",
        token,
    )
    signins = []
    for s in signins_raw.get("value", []):
        signins.append({
            "time":         s.get("createdDateTime"),
            "ip":           s.get("ipAddress"),
            "app":          s.get("appDisplayName"),
            "location":     f"{s.get('location', {}).get('city', '?')}, {s.get('location', {}).get('countryOrRegion', '?')}",
            "result":       "Success" if s.get("status", {}).get("errorCode") == 0 else f"Fail: {s.get('status', {}).get('failureReason')}",
            "mfa_used":     any(d.get("authenticationMethod") not in [None, "Password"] for d in s.get("authenticationDetails", [])),
            "device_os":    s.get("deviceDetail", {}).get("operatingSystem", "N/A"),
        })

    # 4. Risky user detail
    risky = graph_get(f"identityProtection/riskyUsers?$filter=userPrincipalName eq '{upn}'", token)
    risky_detail = risky.get("value", [{}])[0] if risky.get("value") else {}

    return {
        "upn":                   upn,
        "found":                 True,
        "display_name":          profile.get("displayName", "N/A"),
        "account_enabled":       profile.get("accountEnabled", False),
        "department":            profile.get("department", "N/A"),
        "job_title":             profile.get("jobTitle", "N/A"),
        "office":                profile.get("officeLocation", "N/A"),
        "created_at":            profile.get("createdDateTime", "N/A"),
        "last_password_change":  profile.get("lastPasswordChangeDateTime", "N/A"),
        "risk_level":            profile.get("riskLevel", "none"),
        "risk_state":            profile.get("riskState", "none"),
        "risk_updated":          profile.get("riskLastUpdatedDateTime", "N/A"),
        "risky_user_detail":     risky_detail,
        "group_memberships":     groups,
        "recent_signins":        signins,
        "admin_groups":          [g for g in groups if "admin" in g.lower() or "privilege" in g.lower()],
    }


def print_result(result: dict) -> None:
    if not result.get("found"):
        print(f"\n⚠️  User not found in Azure AD: {result['upn']}")
        return

    risk_icon = {"high": "🔴", "medium": "🟡", "none": "🟢", "low": "🟢"}.get(
        result["risk_level"], "⚪"
    )

    print(f"\n{'='*60}")
    print(f"Azure AD Profile: {result['display_name']} ({result['upn']})")
    print(f"{'='*60}")
    print(f"  Account Enabled : {'✅ Yes' if result['account_enabled'] else '🚫 DISABLED'}")
    print(f"  Department      : {result['department']}")
    print(f"  Job Title       : {result['job_title']}")
    print(f"  Last Pw Change  : {result['last_password_change']}")
    print(f"  Risk Level      : {risk_icon} {result['risk_level'].upper()}")
    print(f"  Risk State      : {result['risk_state']}")
    if result["admin_groups"]:
        print(f"  ⚡ ADMIN GROUPS : {', '.join(result['admin_groups'])}")
    print(f"\n  Group Memberships ({len(result['group_memberships'])} total):")
    for g in result["group_memberships"][:10]:
        print(f"    • {g}")

    print(f"\n  Recent Sign-Ins:")
    for s in result["recent_signins"][:5]:
        mfa = "🔐 MFA" if s["mfa_used"] else "⚠️ No MFA"
        print(f"    [{s['time']}] {s['ip']:20} — {s['location']:25} — {s['result']} — {mfa}")


def main():
    parser = argparse.ArgumentParser(description="Azure AD user investigation")
    parser.add_argument("--user", required=True, help="Username or UPN")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    token  = get_access_token()
    result = investigate_user(args.user, token)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_result(result)


if __name__ == "__main__":
    main()
