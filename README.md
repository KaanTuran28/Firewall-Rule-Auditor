# Firewall Rule Auditor

![CI](https://github.com/KaanTuran28/Firewall-Rule-Auditor/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

<p align="center"><b><a href="#english">English</a></b> · <b><a href="#türkçe">Türkçe</a></b></p>

---

## English

A static audit tool for `iptables-save` formatted firewall rulesets. It flags overly permissive rules, insecure protocols, and missing default-deny hygiene, and produces a Markdown report.

### Overview

Given an exported `iptables` ruleset, the tool parses every `-A` rule and chain policy, then applies a small set of heuristics that a network/Blue Team engineer would check manually: is a management port open to the world, is a deprecated cleartext protocol allowed, is there an unrestricted accept-all rule, and does the chain have sane default-deny behavior.

### Installation

Requires Python 3.9+. No external dependencies.

```bash
git clone <this-repo>
cd Firewall-Rule-Auditor
pip install -e .
```

This installs a `firewall-rule-auditor` command. You can also run the script directly with `python firewall_rule_auditor.py` without installing.

### Usage

Export your live ruleset (on the firewall host, as root):

```bash
iptables-save > rules.txt
```

Then audit it:

```bash
firewall-rule-auditor --rules rules.txt --output report.md
# or, without installing:
python firewall_rule_auditor.py --rules rules.txt --output report.md
```

```
Audited 5 rules across 3 chains.
Findings: 4 HIGH, 2 MEDIUM
Report written to report.md
```

For machine-readable output (e.g. to feed into another tool or CI check), use `--format json`:

```bash
firewall-rule-auditor --rules rules.txt --output report.json --format json
```

### CI Integration

`--fail-on {none,medium,high}` (default `none`) turns an audit into a gate you can run against a ruleset exported in CI, e.g. before deploying it:

```bash
firewall-rule-auditor --rules rules.txt --fail-on high
```

```yaml
# GitHub Actions step
- name: Audit firewall ruleset before deploy
  run: firewall-rule-auditor --rules rules.txt --fail-on high
```

### Detection Rules

| Check | Severity | Description |
|---|---|---|
| Sensitive port open to `0.0.0.0/0` | HIGH | A management/database port (SSH, RDP, SMB, MySQL, PostgreSQL, Redis, MongoDB, ...) is accepted from any source. |
| Telnet / FTP allowed | HIGH | Cleartext, deprecated protocols — flagged regardless of source restriction. |
| Unrestricted accept-all rule | HIGH | A rule with no protocol, source, or port filter. |
| Default policy is ACCEPT | MEDIUM | The `INPUT` chain's default policy should be `DROP`, not `ACCEPT`. |
| No catch-all fallback rule | MEDIUM | A chain has `ACCEPT` rules but no explicit `DROP`/`REJECT` rule at the end and a non-`DROP` default policy. |

Rules scoped to a specific CIDR (not `0.0.0.0/0` or unset) are treated as intentionally restricted and are not flagged.

### Limitations

This is a **static** analyzer of an exported ruleset — it does not connect to a live firewall, and it only understands the `iptables-save` text format (not `ufw status`, `nftables`, or cloud security-group formats).

### Example Output

See [`sample_report.md`](./sample_report.md), generated from [`sample_rules/iptables-save-example.txt`](./sample_rules/iptables-save-example.txt).

### Project Structure

```
Firewall-Rule-Auditor/
├── firewall_rule_auditor.py
├── pyproject.toml
├── sample_rules/
│   └── iptables-save-example.txt
├── sample_report.md
├── tests/
│   └── test_firewall_rule_auditor.py
├── .github/workflows/ci.yml
├── requirements.txt
├── requirements-dev.txt
├── LICENSE
└── README.md
```

### Testing

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -v
```

### License

MIT — see [LICENSE](./LICENSE).

---

## Türkçe

`iptables-save` formatındaki güvenlik duvarı kural kümeleri için statik bir denetim aracı. Aşırı izin verici kuralları, güvensiz protokolleri ve eksik default-deny (varsayılan reddet) hijyenini tespit eder ve bir Markdown raporu üretir.

### Genel Bakış

Dışa aktarılmış bir `iptables` kural kümesi verildiğinde, araç her bir `-A` kuralını ve chain (zincir) politikasını ayrıştırır, ardından bir ağ/Blue Team mühendisinin manuel olarak kontrol edeceği küçük bir sezgisel kurallar kümesi uygular: bir yönetim portu dünyaya açık mı, kullanımdan kaldırılmış açık metin bir protokole izin veriliyor mu, kısıtlamasız bir accept-all (hepsini kabul et) kuralı var mı ve chain mantıklı bir default-deny davranışına sahip mi.

### Kurulum

Python 3.9+ gerektirir. Harici bağımlılık yoktur.

```bash
git clone <this-repo>
cd Firewall-Rule-Auditor
pip install -e .
```

Bu, bir `firewall-rule-auditor` komutu kurar. Kurulum yapmadan da doğrudan `python firewall_rule_auditor.py` ile betiği çalıştırabilirsiniz.

### Kullanım

Canlı kural kümenizi dışa aktarın (güvenlik duvarı sunucusunda, root olarak):

```bash
iptables-save > rules.txt
```

Ardından denetleyin:

```bash
firewall-rule-auditor --rules rules.txt --output report.md
# veya, kurulum yapmadan:
python firewall_rule_auditor.py --rules rules.txt --output report.md
```

```
Audited 5 rules across 3 chains.
Findings: 4 HIGH, 2 MEDIUM
Report written to report.md
```

Makine tarafından okunabilir çıktı için (örn. başka bir araca veya CI kontrolüne beslemek amacıyla) `--format json` kullanın:

```bash
firewall-rule-auditor --rules rules.txt --output report.json --format json
```

### CI Entegrasyonu

`--fail-on {none,medium,high}` (varsayılan `none`) bir denetimi, CI'da dışa aktarılan bir kural kümesine karşı çalıştırabileceğiniz bir kapıya (gate) dönüştürür, örn. dağıtımdan önce:

```bash
firewall-rule-auditor --rules rules.txt --fail-on high
```

```yaml
# GitHub Actions adımı
- name: Audit firewall ruleset before deploy
  run: firewall-rule-auditor --rules rules.txt --fail-on high
```

### Tespit Kuralları

| Kontrol | Önem Derecesi | Açıklama |
|---|---|---|
| Hassas port `0.0.0.0/0` adresine açık | HIGH | Bir yönetim/veritabanı portu (SSH, RDP, SMB, MySQL, PostgreSQL, Redis, MongoDB, ...) herhangi bir kaynaktan kabul ediliyor. |
| Telnet / FTP'ye izin veriliyor | HIGH | Açık metin, kullanımdan kaldırılmış protokoller — kaynak kısıtlamasından bağımsız olarak işaretlenir. |
| Kısıtlamasız accept-all kuralı | HIGH | Protokol, kaynak veya port filtresi olmayan bir kural. |
| Varsayılan politika ACCEPT | MEDIUM | `INPUT` chain'inin varsayılan politikası `ACCEPT` değil, `DROP` olmalıdır. |
| Kapsayıcı (catch-all) bir yedek kural yok | MEDIUM | Bir chain'in `ACCEPT` kuralları var ama sonunda açık bir `DROP`/`REJECT` kuralı yok ve varsayılan politika `DROP` değil. |

Belirli bir CIDR'ye kapsamlandırılmış kurallar (`0.0.0.0/0` veya boş değil) kasıtlı olarak kısıtlanmış kabul edilir ve işaretlenmez.

### Sınırlamalar

Bu, dışa aktarılmış bir kural kümesinin **statik** bir analizörüdür — canlı bir güvenlik duvarına bağlanmaz ve yalnızca `iptables-save` metin formatını anlar (`ufw status`, `nftables` veya bulut güvenlik grubu formatlarını değil).

### Örnek Çıktı

[`sample_rules/iptables-save-example.txt`](./sample_rules/iptables-save-example.txt) dosyasından üretilen [`sample_report.md`](./sample_report.md) dosyasına bakın.

### Proje Yapısı

```
Firewall-Rule-Auditor/
├── firewall_rule_auditor.py
├── pyproject.toml
├── sample_rules/
│   └── iptables-save-example.txt
├── sample_report.md
├── tests/
│   └── test_firewall_rule_auditor.py
├── .github/workflows/ci.yml
├── requirements.txt
├── requirements-dev.txt
├── LICENSE
└── README.md
```

### Test

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -v
```

### Lisans

MIT — bkz. [LICENSE](./LICENSE).

---
