# Firewall Rule Audit Report

Source: `sample_rules/iptables-save-example.txt`
Findings: 4 HIGH, 2 MEDIUM

| Severity | Finding | Rule/Policy | Recommendation |
|---|---|---|---|
| HIGH | Management/sensitive port 22 (SSH) is open to the world (0.0.0.0/0). | `-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT` | Restrict the source to a specific management CIDR or place SSH behind a VPN. |
| HIGH | Management/sensitive port 3389 (RDP) is open to the world (0.0.0.0/0). | `-A INPUT -p tcp -m tcp --dport 3389 -s 0.0.0.0/0 -j ACCEPT` | Restrict the source to a specific management CIDR or place RDP behind a VPN. |
| HIGH | Insecure/deprecated cleartext protocol (Telnet, port 23) is allowed. | `-A INPUT -p tcp -m tcp --dport 23 -s 10.0.0.5/32 -j ACCEPT` | Disable Telnet entirely or replace with an encrypted alternative (e.g. SSH/SFTP). |
| HIGH | Unrestricted accept-all rule with no protocol, source, or port filter. | `-A INPUT -j ACCEPT` | Scope the rule to a specific protocol, source, and port. |
| MEDIUM | Default policy is ACCEPT (default-allow). Best practice is default-deny. | `:INPUT ACCEPT` | Set the INPUT chain's default policy to DROP and explicitly allow required traffic. |
| MEDIUM | Chain 'INPUT' has ACCEPT rules but no explicit DROP/REJECT catch-all fallback rule, and its default policy is not DROP. | `chain INPUT` | Add an explicit `-A INPUT -j DROP` rule at the end of the chain, or set the default policy to DROP. |
