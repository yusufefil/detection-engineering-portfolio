#!/usr/bin/env python3
"""Sigma -> KQL (sigma-cli kusto) -> Bicep parameter files for Microsoft Sentinel."""
import json, re, subprocess, sys, uuid, pathlib
import yaml

RULES_DIR = pathlib.Path("rules/sigma")
BUILD_DIR = pathlib.Path("build")
PIPELINE  = "azure_monitor"

SEVERITY = {"critical": "High", "high": "High", "medium": "Medium",
            "low": "Low", "informational": "Informational"}

TACTIC_MAP = {
    "reconnaissance": "Reconnaissance", "resource_development": "ResourceDevelopment",
    "initial_access": "InitialAccess", "execution": "Execution",
    "persistence": "Persistence", "privilege_escalation": "PrivilegeEscalation",
    "defense_evasion": "DefenseEvasion", "credential_access": "CredentialAccess",
    "discovery": "Discovery", "lateral_movement": "LateralMovement",
    "collection": "Collection", "command_and_control": "CommandAndControl",
    "exfiltration": "Exfiltration", "impact": "Impact",
}

def to_kql(rule_path):
    res = subprocess.run(
        ["sigma", "convert", "-t", "kusto", "-p", PIPELINE, str(rule_path)],
        capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[!] convert failed for {rule_path}:\n{res.stderr}", file=sys.stderr)
        sys.exit(1)
    # son satir(lar) KQL; "Parsing Sigma rules" progress satirini at
    lines = [l for l in res.stdout.splitlines() if l.strip() and "Parsing" not in l]
    return "\n".join(lines).strip()

def parse_tags(tags):
    tactics, techniques = [], []
    for t in tags or []:
        if not t.startswith("attack."):
            continue
        val = t.split("attack.", 1)[1]
        if re.match(r"t\d{4}", val):
            techniques.append(val.upper().split(".")[0])
        elif val in TACTIC_MAP:
            tactics.append(TACTIC_MAP[val])
    return sorted(set(tactics)), sorted(set(techniques))

def main():
    BUILD_DIR.mkdir(exist_ok=True)
    rules = list(RULES_DIR.glob("*.yml"))
    if not rules:
        print("No .yml rules found in rules/sigma", file=sys.stderr)
        return 1
    for rp in rules:
        meta = yaml.safe_load(rp.read_text(encoding="utf-8"))
        kql = to_kql(rp)
        tactics, techniques = parse_tags(meta.get("tags"))
        params = {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
            "contentVersion": "1.0.0.0",
            "parameters": {
                "ruleId":      {"value": meta.get("id") or str(uuid.uuid4())},
                "displayName": {"value": meta["title"]},
                "description": {"value": meta.get("description", "")},
                "severity":    {"value": SEVERITY.get(meta.get("level", "medium"), "Medium")},
                "query":       {"value": kql},
                "tactics":     {"value": tactics},
                "techniques":  {"value": techniques},
            },
        }
        out = BUILD_DIR / f"{rp.stem}.params.json"
        out.write_text(json.dumps(params, indent=2), encoding="utf-8")
        print(f"[+] {rp.name} -> {out.name}  (sev={params['parameters']['severity']['value']}, techniques={techniques})")
        print("---- KQL ----")
        print(kql)
        print("-------------")
    return 0

if __name__ == "__main__":
    sys.exit(main())
