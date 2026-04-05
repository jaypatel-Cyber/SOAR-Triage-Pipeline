#!/usr/bin/env python3
"""
virustotal_check.py — Standalone VirusTotal IP/Domain/Hash Lookup
==================================================================
Usage:
  python virustotal_check.py --ip 185.220.101.45
  python virustotal_check.py --domain evil.example.com
  python virustotal_check.py --hash d41d8cd98f00b204e9800998ecf8427e

Can be called standalone for testing or imported as a module.
API key: set VT_API_KEY environment variable or --api-key flag.
"""

import argparse
import json
import os
import sys
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError

VT_BASE = "https://www.virustotal.com/api/v3"


def get_api_key(cli_key: str = None) -> str:
    key = cli_key or os.environ.get("VT_API_KEY", "")
    if not key:
        sys.exit("[ERROR] Set VT_API_KEY env var or pass --api-key")
    return key


def vt_get(endpoint: str, api_key: str) -> dict:
    url = f"{VT_BASE}/{endpoint}"
    req = Request(url, headers={"x-apikey": api_key})
    try:
        with urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except HTTPError as e:
        if e.code == 404:
            return {"error": "not_found", "status": 404}
        raise
    except URLError as e:
        sys.exit(f"[ERROR] Network error: {e.reason}")


def check_ip(ip: str, api_key: str) -> dict:
    data = vt_get(f"ip_addresses/{ip}", api_key)
    if "error" in data:
        return {"ip": ip, "verdict": "UNKNOWN", "detail": data}

    attrs  = data["data"]["attributes"]
    stats  = attrs.get("last_analysis_stats", {})
    mal    = stats.get("malicious", 0)
    sus    = stats.get("suspicious", 0)
    clean  = stats.get("harmless", 0)
    total  = sum(stats.values())

    verdict = "MALICIOUS" if mal > 5 else "SUSPICIOUS" if mal > 0 else "CLEAN"

    return {
        "ip":              ip,
        "verdict":         verdict,
        "malicious":       mal,
        "suspicious":      sus,
        "harmless":        clean,
        "undetected":      stats.get("undetected", 0),
        "total_vendors":   total,
        "reputation":      attrs.get("reputation", 0),
        "country":         attrs.get("country", "N/A"),
        "asn":             attrs.get("asn", "N/A"),
        "as_owner":        attrs.get("as_owner", "N/A"),
        "tags":            attrs.get("tags", []),
        "vt_link":         f"https://www.virustotal.com/gui/ip-address/{ip}/detection",
    }


def check_domain(domain: str, api_key: str) -> dict:
    data = vt_get(f"domains/{domain}", api_key)
    if "error" in data:
        return {"domain": domain, "verdict": "UNKNOWN", "detail": data}

    attrs  = data["data"]["attributes"]
    stats  = attrs.get("last_analysis_stats", {})
    mal    = stats.get("malicious", 0)

    verdict = "MALICIOUS" if mal > 5 else "SUSPICIOUS" if mal > 0 else "CLEAN"

    return {
        "domain":       domain,
        "verdict":      verdict,
        "malicious":    mal,
        "suspicious":   stats.get("suspicious", 0),
        "categories":   attrs.get("categories", {}),
        "registrar":    attrs.get("registrar", "N/A"),
        "creation_date":attrs.get("creation_date", "N/A"),
        "reputation":   attrs.get("reputation", 0),
        "vt_link":      f"https://www.virustotal.com/gui/domain/{domain}/detection",
    }


def check_hash(file_hash: str, api_key: str) -> dict:
    data = vt_get(f"files/{file_hash}", api_key)
    if "error" in data:
        return {"hash": file_hash, "verdict": "UNKNOWN", "detail": data}

    attrs  = data["data"]["attributes"]
    stats  = attrs.get("last_analysis_stats", {})
    mal    = stats.get("malicious", 0)

    verdict = "MALICIOUS" if mal > 5 else "SUSPICIOUS" if mal > 0 else "CLEAN"

    return {
        "hash":         file_hash,
        "verdict":      verdict,
        "malicious":    mal,
        "suspicious":   stats.get("suspicious", 0),
        "name":         attrs.get("meaningful_name", "unknown"),
        "type":         attrs.get("type_description", "N/A"),
        "size_bytes":   attrs.get("size", 0),
        "first_seen":   attrs.get("first_submission_date", "N/A"),
        "vt_link":      f"https://www.virustotal.com/gui/file/{file_hash}/detection",
    }


def print_result(result: dict) -> None:
    verdict = result.get("verdict", "UNKNOWN")
    icon    = {"MALICIOUS": "🔴", "SUSPICIOUS": "🟡", "CLEAN": "🟢"}.get(verdict, "⚪")
    print(f"\n{icon}  Verdict: {verdict}")
    print(json.dumps(result, indent=2))


def main():
    parser = argparse.ArgumentParser(description="VirusTotal lookup utility")
    group  = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ip",     help="IP address to check")
    group.add_argument("--domain", help="Domain to check")
    group.add_argument("--hash",   help="File hash (MD5/SHA1/SHA256)")
    parser.add_argument("--api-key", help="VT API key (or set VT_API_KEY env)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON only")
    args = parser.parse_args()

    api_key = get_api_key(args.api_key)

    if args.ip:
        result = check_ip(args.ip, api_key)
    elif args.domain:
        result = check_domain(args.domain, api_key)
    else:
        result = check_hash(args.hash, api_key)

    if args.json:
        print(json.dumps(result))
    else:
        print_result(result)


if __name__ == "__main__":
    main()
