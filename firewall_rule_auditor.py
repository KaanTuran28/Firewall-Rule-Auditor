import argparse
import ipaddress
import json
import re
import sys

SENSITIVE_PORTS = {
    22: "SSH",
    23: "Telnet",
    21: "FTP",
    3389: "RDP",
    445: "SMB",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
}

POLICY_RE = re.compile(r"^:(\S+)\s+(\S+)\s+\[\d+:\d+\]")
RULE_RE = re.compile(r"^-A\s+(\S+)\s+(.*)$")


def _is_any_source(source):
    if source is None:
        return True
    try:
        net = ipaddress.ip_network(source, strict=False)
    except ValueError:
        return False
    return net.prefixlen == 0


def parse_rules(text: str) -> dict:
    policies = {}
    rules = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "*")) or line == "COMMIT":
            continue

        policy_match = POLICY_RE.match(line)
        if policy_match:
            chain, policy = policy_match.groups()
            policies[chain] = policy
            continue

        rule_match = RULE_RE.match(line)
        if not rule_match:
            continue

        chain, rest = rule_match.groups()
        tokens = rest.split()
        rule = {
            "chain": chain,
            "raw": line,
            "protocol": None,
            "source": None,
            "dport": None,
            "target": None,
        }
        i = 0
        while i < len(tokens):
            token = tokens[i]
            if token == "-p" and i + 1 < len(tokens):
                rule["protocol"] = tokens[i + 1]
                i += 2
            elif token == "-s" and i + 1 < len(tokens):
                rule["source"] = tokens[i + 1]
                i += 2
            elif token == "--dport" and i + 1 < len(tokens):
                try:
                    rule["dport"] = int(tokens[i + 1])
                except ValueError:
                    rule["dport"] = None
                i += 2
            elif token == "-j" and i + 1 < len(tokens):
                rule["target"] = tokens[i + 1]
                i += 2
            else:
                i += 1
        rules.append(rule)

    return {"policies": policies, "rules": rules}


def audit(parsed: dict) -> list:
    findings = []
    rules = parsed["rules"]
    policies = parsed["policies"]

    chains_with_accept = set()
    chains_with_catchall = set()

    for rule in rules:
        if rule["target"] != "ACCEPT":
            if (
                rule["target"] in ("DROP", "REJECT")
                and rule["protocol"] is None
                and rule["source"] is None
                and rule["dport"] is None
            ):
                chains_with_catchall.add(rule["chain"])
            continue

        chains_with_accept.add(rule["chain"])
        is_any = _is_any_source(rule["source"])
        dport = rule["dport"]

        if dport in (23, 21):
            proto_name = "Telnet" if dport == 23 else "FTP"
            findings.append(
                {
                    "severity": "HIGH",
                    "rule_or_policy": rule["raw"],
                    "reason": f"Insecure/deprecated cleartext protocol ({proto_name}, port {dport}) is allowed.",
                    "recommendation": f"Disable {proto_name} entirely or replace with an encrypted alternative (e.g. SSH/SFTP).",
                }
            )
        elif is_any and dport in SENSITIVE_PORTS:
            service = SENSITIVE_PORTS[dport]
            findings.append(
                {
                    "severity": "HIGH",
                    "rule_or_policy": rule["raw"],
                    "reason": f"Management/sensitive port {dport} ({service}) is open to the world (0.0.0.0/0).",
                    "recommendation": f"Restrict the source to a specific management CIDR or place {service} behind a VPN.",
                }
            )
        elif rule["protocol"] is None and rule["source"] is None and rule["dport"] is None:
            findings.append(
                {
                    "severity": "HIGH",
                    "rule_or_policy": rule["raw"],
                    "reason": "Unrestricted accept-all rule with no protocol, source, or port filter.",
                    "recommendation": "Scope the rule to a specific protocol, source, and port.",
                }
            )

    for chain, policy in policies.items():
        if chain == "INPUT" and policy == "ACCEPT":
            findings.append(
                {
                    "severity": "MEDIUM",
                    "rule_or_policy": f":{chain} {policy}",
                    "reason": "Default policy is ACCEPT (default-allow). Best practice is default-deny.",
                    "recommendation": f"Set the {chain} chain's default policy to DROP and explicitly allow required traffic.",
                }
            )

    for chain in chains_with_accept:
        policy = policies.get(chain)
        if policy != "DROP" and chain not in chains_with_catchall:
            findings.append(
                {
                    "severity": "MEDIUM",
                    "rule_or_policy": f"chain {chain}",
                    "reason": f"Chain '{chain}' has ACCEPT rules but no explicit DROP/REJECT catch-all fallback rule, and its default policy is not DROP.",
                    "recommendation": f"Add an explicit `-A {chain} -j DROP` rule at the end of the chain, or set the default policy to DROP.",
                }
            )

    return findings


def build_report(findings: list, source_path: str) -> str:
    high = [f for f in findings if f["severity"] == "HIGH"]
    medium = [f for f in findings if f["severity"] == "MEDIUM"]
    lines = [
        "# Firewall Rule Audit Report",
        "",
        f"Source: `{source_path}`",
        f"Findings: {len(high)} HIGH, {len(medium)} MEDIUM",
        "",
        "| Severity | Finding | Rule/Policy | Recommendation |",
        "|---|---|---|---|",
    ]
    for finding in high + medium:
        lines.append(
            f"| {finding['severity']} | {finding['reason']} | `{finding['rule_or_policy']}` | {finding['recommendation']} |"
        )
    return "\n".join(lines) + "\n"


def build_json_report(findings: list, source_path: str) -> str:
    high = [f for f in findings if f["severity"] == "HIGH"]
    medium = [f for f in findings if f["severity"] == "MEDIUM"]
    payload = {
        "source": source_path,
        "summary": {"high": len(high), "medium": len(medium)},
        "findings": findings,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def main():
    parser = argparse.ArgumentParser(description="Static audit of an iptables-save formatted ruleset.")
    parser.add_argument("--rules", required=True, help="Path to an iptables-save output file.")
    parser.add_argument("--output", default="sample_report.md", help="Path to write the report.")
    parser.add_argument(
        "--format", choices=["markdown", "json"], default="markdown", help="Output report format."
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "medium", "high"],
        default="none",
        help="Exit with code 1 if findings at/above this severity are present (for CI gating).",
    )
    args = parser.parse_args()

    with open(args.rules, "r", encoding="utf-8") as fh:
        text = fh.read()

    parsed = parse_rules(text)
    findings = audit(parsed)
    report = build_json_report(findings, args.rules) if args.format == "json" else build_report(findings, args.rules)

    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(report)

    high_count = sum(1 for f in findings if f["severity"] == "HIGH")
    medium_count = sum(1 for f in findings if f["severity"] == "MEDIUM")
    print(f"Audited {len(parsed['rules'])} rules across {len(parsed['policies'])} chains.")
    print(f"Findings: {high_count} HIGH, {medium_count} MEDIUM")
    print(f"Report written to {args.output}")

    if args.fail_on == "high" and high_count > 0:
        return 1
    if args.fail_on == "medium" and (high_count > 0 or medium_count > 0):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
