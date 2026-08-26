import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from firewall_rule_auditor import audit, build_json_report, main, parse_rules

SAMPLE_PATH = pathlib.Path(__file__).resolve().parent.parent / "sample_rules" / "iptables-save-example.txt"


def load_sample():
    return parse_rules(SAMPLE_PATH.read_text(encoding="utf-8"))


def test_parse_rules_sample_file():
    parsed = load_sample()
    assert parsed["policies"] == {"INPUT": "ACCEPT", "FORWARD": "DROP", "OUTPUT": "ACCEPT"}
    assert len(parsed["rules"]) == 5


def test_open_ssh_rule_flagged_high():
    findings = audit(load_sample())
    ssh_findings = [f for f in findings if "22" in f["rule_or_policy"] and f["severity"] == "HIGH"]
    assert ssh_findings
    assert "SSH" in ssh_findings[0]["reason"]


def test_restricted_https_rule_not_flagged():
    findings = audit(load_sample())
    https_findings = [f for f in findings if "--dport 443" in f["rule_or_policy"]]
    assert https_findings == []


def test_telnet_flagged_even_with_restricted_source():
    findings = audit(load_sample())
    telnet_findings = [f for f in findings if "23" in f["rule_or_policy"] and f["severity"] == "HIGH"]
    assert telnet_findings
    assert "Telnet" in telnet_findings[0]["reason"]


def test_any_any_accept_flagged_high():
    findings = audit(load_sample())
    any_any = [f for f in findings if f["rule_or_policy"] == "-A INPUT -j ACCEPT"]
    assert any_any
    assert any_any[0]["severity"] == "HIGH"
    assert "accept-all" in any_any[0]["reason"]


def test_default_accept_policy_flagged_medium():
    parsed = {"policies": {"INPUT": "ACCEPT"}, "rules": []}
    findings = audit(parsed)
    assert any(f["severity"] == "MEDIUM" and "default-allow" in f["reason"] for f in findings)

    parsed_drop = {"policies": {"INPUT": "DROP"}, "rules": []}
    findings_drop = audit(parsed_drop)
    assert not any("default-allow" in f["reason"] for f in findings_drop)


def test_missing_catchall_flagged_medium():
    parsed = {
        "policies": {"INPUT": "ACCEPT"},
        "rules": [
            {"chain": "INPUT", "raw": "-A INPUT -p tcp --dport 8080 -s 10.0.0.0/24 -j ACCEPT",
             "protocol": "tcp", "source": "10.0.0.0/24", "dport": 8080, "target": "ACCEPT"},
        ],
    }
    findings = audit(parsed)
    assert any("catch-all" in f["reason"] for f in findings)


def test_json_format_is_valid_with_expected_fields():
    findings = audit(load_sample())
    data = json.loads(build_json_report(findings, str(SAMPLE_PATH)))
    assert data["summary"] == {"high": 4, "medium": 2}
    assert len(data["findings"]) == len(findings)
    for f in data["findings"]:
        assert {"severity", "reason", "rule_or_policy", "recommendation"} <= set(f.keys())


def test_json_format_matches_markdown_finding_count():
    findings = audit(load_sample())
    data = json.loads(build_json_report(findings, str(SAMPLE_PATH)))
    high = sum(1 for f in data["findings"] if f["severity"] == "HIGH")
    medium = sum(1 for f in data["findings"] if f["severity"] == "MEDIUM")
    assert high == 4
    assert medium == 2


def run_main(monkeypatch, tmp_path, rules_path, extra_args):
    out = str(tmp_path / "out.md")
    argv = ["firewall_rule_auditor.py", "--rules", rules_path, "--output", out] + extra_args
    monkeypatch.setattr(sys, "argv", argv)
    return main()


def test_fail_on_high_exits_nonzero_for_sample_with_high_findings(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, str(SAMPLE_PATH), ["--fail-on", "high"]) == 1


def test_fail_on_medium_exits_nonzero_too(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, str(SAMPLE_PATH), ["--fail-on", "medium"]) == 1


def test_fail_on_none_exits_zero_by_default(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, str(SAMPLE_PATH), []) == 0


def test_fail_on_high_exits_zero_when_no_high_findings(monkeypatch, tmp_path):
    clean_rules = tmp_path / "clean.rules"
    clean_rules.write_text(
        "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n",
        encoding="utf-8",
    )
    assert run_main(monkeypatch, tmp_path, str(clean_rules), ["--fail-on", "high"]) == 0
