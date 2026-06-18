#!/usr/bin/env python3
"""Native KQL detection rules -> Sentinel deployment params.

Companion to sigma_to_sentinel.py. Reads rules/kql/*.yaml (metadata + embedded KQL)
and writes build/<name>.params.json in the same shape the Bicep template expects,
so the existing CI/CD workflow deploys Sigma-derived and native-KQL rules identically.
"""
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
KQL_DIR = ROOT / "rules" / "kql"
BUILD_DIR = ROOT / "build"

SEVERITY = {
    "informational": "Informational",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "High",
}


def norm_severity(val):
    if not val:
        return "Medium"
    return SEVERITY.get(str(val).lower(), str(val))


def norm_techniques(techs):
    """Sentinel accepts parent techniques only: T1566.001 -> T1566."""
    out = []
    for t in (techs or []):
        out.append(str(t).upper().split(".")[0])
    seen = set()
    return [x for x in out if not (x in seen or seen.add(x))]


def main():
    BUILD_DIR.mkdir(exist_ok=True)
    if not KQL_DIR.exists():
        print(f"[i] no KQL rules dir at {KQL_DIR}, nothing to do")
        return 0

    count = 0
    for rp in sorted(KQL_DIR.glob("*.yaml")):
        meta = yaml.safe_load(rp.read_text(encoding="utf-8"))
        kql = (meta.get("query") or "").strip()
        if not kql:
            print(f"[!] {rp.name}: empty query, skipped")
            continue

        params = {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
            "contentVersion": "1.0.0.0",
            "parameters": {
                "ruleId":      {"value": meta.get("id")},
                "displayName": {"value": meta["title"]},
                "description": {"value": meta.get("description", "")},
                "severity":    {"value": norm_severity(meta.get("severity"))},
                "query":       {"value": kql},
                "tactics":     {"value": meta.get("tactics", [])},
                "techniques":  {"value": norm_techniques(meta.get("techniques", []))},
            },
        }
        out = BUILD_DIR / f"{rp.stem}.params.json"
        out.write_text(json.dumps(params, indent=2), encoding="utf-8")
        count += 1
        print(
            f"[+] {rp.name} -> {out.name}  "
            f"(sev={params['parameters']['severity']['value']}, "
            f"techniques={params['parameters']['techniques']['value']})"
        )

    print(f"---- KQL rules processed: {count} ----")
    return 0


if __name__ == "__main__":
    sys.exit(main())
