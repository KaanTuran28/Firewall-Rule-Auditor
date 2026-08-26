# Durum Günlüğü

> En üstteki kayıt en güncelidir. Her çalışma sonrası buraya kısa bir not düşülür.

---

## 2026-08-21 — CI gating için `--fail-on` eklendi

- Konu: `--fail-on {none,medium,high}` bayrağı eklendi — deploy öncesi ruleset denetimini CI'da build kırıcı hale getirebilmek için. Varsayılan `none`, geriye dönük uyumlu.
- 4 yeni test eklendi (9 → 13), hepsi geçti. Ruff temiz.
- Durum: ✅ Henüz push edilmedi.

**Sıradaki iş:** GitHub'da `Firewall-Rule-Auditor` adıyla repo aç, git init + push.

---

## 2026-08-20 — Paketleme, JSON çıktı ve lint eklendi

- Konu: `pyproject.toml` ile pip kurulabilir hale getirildi (`pip install -e .` → `firewall-rule-auditor` komutu), `--format json` eklendi, ruff lint + CI lint job'u eklendi.
- Durum: ✅ Tüm testler geçiyor (9/9), ruff temiz, kurulum/çalıştırma/uninstall gerçekten doğrulandı.

**Sıradaki iş:** GitHub'da `Firewall-Rule-Auditor` adıyla repo aç, git init + push.

---

## 2026-08-20 — İlk sürüm oluşturuldu (test + CI dahil)

- Konu: iptables-save formatlı firewall kural setlerini statik olarak denetleyen script + örnek ruleset + örnek rapor + pytest test paketi + GitHub Actions CI hazırlandı.
- Durum: ✅ Çalışıyor, test edildi (7/7 test geçti, örnek ruleset üzerinde 4 HIGH + 2 MEDIUM bulgu doğru üretildi).

**Sıradaki iş:** GitHub'da `Firewall-Rule-Auditor` adıyla repo aç, git init + push.
