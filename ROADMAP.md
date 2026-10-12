# ThreatEye — Roadmap: labdan korporativ SaaS'gacha

Bu hujjat — ThreatEye'ni hozirgi holatidan (to'liq funksional, o'zini-o'zi hostlaydigan
lab/MVP) kompaniyalar joylashtira oladigan va global sotiladigan mahsulot/SaaS'ga olib
chiqish uchun **jamoa backlog'i**. Nima yetishmayotganiga halol qaraydi va ishlarni avval
nima bloklasa, shunга qarab tartiblaydi.

> **Progress (2026-10-12):** ✅ tenant izolyatsiyasi · ✅ settings secretlari shifrlangan (Fernet)
> · ✅ production hardening (startup secret guard) · ✅ per-tenant rate limitlar · ✅ **SSRF egress
> guard** · ✅ **majburiy parol o'zgartirish (UI modal)** · ✅ **HSTS TLS orqasidа** · ✅ **barcha
> dependency CVE'lari yopildi (pin + gophish --no-deps)** · ✅ **GitHub Security tab 0 alert** · ✅
> **CPU ML klassifikatori** (1M dataset, 3-qatlam) · ✅ **3 tilli UI (UZ/RU/EN) + setup picker** ·
> ✅ **AI Awareness PDF hisoboti (3 til)** · ✅ **LLM chiqishi o'zbek tilида** · ✅ **homoglif/
> typosquat floor tuzatildi** (LLM yo'q bo'lsa ham ushlaydi). Keyingi: advanced-evaziya aniqlash,
> GoPhish LLM template, multi-user SOC, billing.

---

## 1. Hozirgi holat

**Qurilган va tekshirilған**
- Aniqlash pipeline: deterministik stek (auth / domen-razvedka / homoglif / korpus / BEC /
  injection) **1M datasetда 99.9% precision, 86% recall**, plus maxsus lokal LLM
  (`threateye-phish:1.3`) va **CPU ML klassifikatori** (til-agnostik, 3-qatlam).
- SOC/Blue-team: cases + SLA/MTTD/MTTR, triage, ATT&CK coverage, threat-intel, Sigma qoidalar,
  SIEM eksport (ECS/OCSF → Elasticsearch/Kibana), SOAR-playbooklar.
- Phishing simulyatsiyasi (GoPhish): AI-yaratған lure + landing sahifa, click/submit kuzatish.
- **AI Awareness PDF hisoboti** — LLM xulosasi + bo'lim-zaifligi tahlili, 3 tilда.
- Platforma: multi-tenant, RBAC, API-key ingestion, SQL migratsiyalar, JWT-cookie sessiyalar
  + CSRF, Redis rate-limit, adaptiv o'rganish, attachment tahlili, Prometheus, **54 test + CI**.
- **3 tilli UI** (UZ/RU/EN) + setup picker; LLM chiqishi tanlangan tilда.
- **Xavfsizlik:** SSRF egress guard, majburiy parol (UI modal), HSTS, pin qilinган deps,
  GitHub Security tab 0 alert (CodeQL/Bandit/Semgrep/osv-scanner yashil).

**Hali EMAS**
- Hardening qisman: dev qulayliklar (`UVICORN_RELOAD`, lab POSTGRES default) hali yoqilgan.
- Real pochta hajmiga masshtablanмаган (LLM inline, CPU'да ~1-3 min/xat).
- Tijorat mahsuloti emas (signup, billing, onboarding, plans yo'q).
- Advanced evaziya (Unicode/kirill homoglif, zero-width, anchor≠href) hali to'liq qamralмаган.

---

## 2. Ma'lum cheklovlar (kodга nisbatан tekshirilган)

### 2.1 Aniqlash sifati — **ustuvor**
- **Advanced evaziya texnikalari.** Hozirgi homoglif faqat ASCII (`rn`→`m`, `0`→`o`). Kirill
  harf almashtirish (`mediа-tecth.com`da `а` = U+0430), zero-width belgilar (U+200B),
  ko'rinmas keyword stuffing (font-size:0), HTML anchor-matni ≠ href domeni, quoted-reply
  ichida yashirilган link — bular uchun **Unicode/mixed-script, zero-width strip va anchor/href
  mos-kelmaslik** aniqlash qo'shilishi kerak.
- **DKIM/SPF-PASS phishing.** Haqiqiy SES/infra orqali yuborilган (auth PASS) phishing uchun
  faqat semantik + lookalike + content signallari qoladi — bu eng qiyin holat.
- **Yarim-sintetik validatsiya.** 1M dataset real domenlar, lekin shablon bodylar; real pochta
  murakkabroq. Auto-karantin real pochtада (shadow rejim bilan) validatsiya qilinishi kerak.

### 2.2 Masshtab va unumdorlik
- LLM har so'rovда inline (`DETECTOR_FAST_PATH=0`), CPU'да ~1-3 min/xat. Async navbat yo'q.
- Gorizontal masshtab isbotlanмаган; GPU inference yo'li yo'q.

### 2.3 Mahsulot va tijorat
- Self-serve signup / tenant provisioning / onboarding yo'q.
- Billing / subscription / plans / metering yo'q.
- SaaS operatori uchun admin konsoli yo'q.
- **Multi-user:** hozir asosan bitta hisob uchun sozlangan; butun kompaniya xodimlarini
  kuzatadigan to'liq SOC platformaga aylantirish kerak.

### 2.4 Compliance, ma'lumot, huquq
- Email kontenti (PII) saqlanadi — retention/residency/DSAR/body shifri yo'q.
- Jonli phishing freymvork (GoPhish) + ochiq pochta serveri — abuse/huquqiy nazorat kerak.

### 2.5 Operatsiyalar
- Backuplar/DR/alerting/centralized logs/SLO yo'q.

---

## 3. Bosqichli roadmap

### Bosqich 0 — Production hardening ✅ (asosan bajarilди)
- [x] `--reload`ни olib tashlash; bir nechta worker + Caddy/nginx TLS.
- [x] Insecure default'larда fail-close (`THREATEYE_ENV=production`).
- [x] Birinchi loginда majburiy admin-parol (UI modal); `admin/admin` tashlab yuborildi.
- [x] HSTS (backend TLS orqasidа); `COOKIE_SECURE=true` production yo'li.
- [x] Settings secretlari shifrlangan (Fernet).
- [x] SSRF egress allow-list (`test-imap`/`test-siem`/AI base-URL/webhooks).
- [ ] Postgres backup + restore runbook; metrics alerting.

### Bosqich 1 — Haqiqiy multi-tenant SaaS
- [x] To'liq tenant izolyatsiyasi + cross-tenant testlar.
- [x] Per-tenant rate limitlar & kvotalar.
- [ ] Self-serve signup + tenant provisioning.
- [ ] Billing (Stripe): plans, metering, kvotalar.
- [ ] Operator konsoli.
- [ ] Async task queue (Celery/RQ/Arq) — LLM/WHOIS/attachment request yo'lidан chiqadi.
- [ ] **Multi-user SOC:** butun kompaniya xodimlari hisoblarini (M365/Google journaling yoki
      IMAP) kuzatadigan platforma.

### Bosqich 2 — Korporativ daraja
- [ ] SSO (SAML/OIDC), SCIM, MFA.
- [ ] Data governance: retention, residency, DSAR, body shifri, PII redaksiya.
- [ ] Native mail-gateway integratsiyalari (M365 / Google Workspace).
- [ ] To'liq audit trail + tamper-evidence.
- [ ] Compliance: SOC 2 / ISO 27001, DPA, pen-test.

### Bosqich 3 — Masshtab va global go-to-market
- [ ] Gorizontal masshtab, read replicas, autoscaling, multi-region.
- [x] UI lokalizatsiyasi (UZ/RU/EN) — *bajarilди*.
- [ ] Marketplace listinglari (Microsoft, Google, AWS).

---

## 4. AI / ML roadmap

1. **CPU ML klassifikatori** — ✅ **BAJARILДИ** (`scripts/train_ml_classifier.py` →
   `services/ml_classifier.py`, HashingVectorizer + SGD log-loss, raise-only/fail-open).
2. **Advanced-evaziya aniqlash** (keyingi ustuvor) — Unicode/mixed-script homoglif, punycode,
   zero-width strip, anchor-matni ≠ href, HTML'dagi yashirin kontent.
3. **GoPhish LLM template generatsiyasi** — LLM GoPhish'да to'g'ridan-to'g'ri template/landing
   yaratadi; roster bo'yicha avtomatik yuboradi.
4. **GPU LoRA fine-tune** — real belgilangan pochtada; eval-gated promote.
5. **Retrieval augmentation** — per-tenant threat-intel + tarixiy verdictlar kontekst sifatida.
6. **Katta/ko'p tilli baza chat uchun** — o'zbek texnik chuqurligi uchun kattaroq baza.
7. **Boshqariladigan o'z-o'zини yaxshilash** (`scripts/self_improve.py`) — allaqachon chegaralangan.

---

## 5. SaaS launch uchun "definition of done"

Tashqi to'lovchi tenantlarni qo'shishdan oldin quyidagilar bajarilishi shart:

- [x] Tenant izolyatsiyasi + cross-tenant testlar.
- [x] Secretlar shifrlangan; default kredential yo'q; TLS; `--reload` olib tashlangan.
- [ ] Async ishlov (request hech qachon LLM'да bloklanmaydi); per-tenant kvotalar.
- [ ] Signup, billing, operator konsoli.
- [ ] Data retention/residency/DSAR va body shifri.
- [ ] Backup + DR; alerting + on-call.
- [ ] Mustaqil xavfsizlik ko'rigi / pen-test.
- [ ] Auto-karantin real pochtада shadow rejimда validatsiya qilinди.

---

*Bu faylni ishlar yakunlanған sari yangilab turing. Yaqin muddatли kritik yo'l:
**advanced-evaziya aniqlash → GoPhish LLM template → async queue → multi-user → billing**.*
