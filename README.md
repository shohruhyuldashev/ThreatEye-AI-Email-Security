# ThreatEye — AI quvvatli Email Xavfsizlik platformasi

ThreatEye — bu **real vaqtda phishing aniqlaydigan** o'zini-o'zi hostlaydigan platforma:
bu yerda **AI, AI tomonidan yaratilgan hujumlarга qarshi himoya qiladi**. Tizim kiruvchi
pochtani ushlaydi, har bir xatni maxsus lokal LLM va deterministik aniqlash steki bilan
baholaydi, tahdidlarni karantinga oladi va o'z xodimlaringizga qarshi to'liq phishing
simulyatsiyalarini o'tkazadi — hammasi offline ishlay oladi va SOC uchun tayyor.

Asosiy qismlar:

- **Maxsus aniqlash modeli** (`threateye-phish:1.3`, default) — `qwen2.5:3b` asosida
  qurilgan lokal Ollama modeli, unga ekspertlik "pishirib" kiritilgan (phishing, zararli
  dastur, kod tahlili, ATT&CK, IR) — **semantik-niyat tahlili**, **prompt-injection/jailbreak
  himoyasi** va ikki chiqish rejimi (chat uchun matn, baholash uchun JSON) bilan.
  **Ko'p tilli 7b variant** (`2.0`, Ingliz/Rus/O'zbek) talab bo'yicha qayta qurилади. Har
  qanday OpenAI-moslashgan provayder ham ishlaydi. LLM **har qanday tildagi** phishingni
  aniqlaydi va sabablarini **tanlangan tilда** (default — o'zbek) yozadi.
- **CPU ML klassifikatori** — 1 million qatorli belgilangan dataset'да o'qitilgan
  HashingVectorizer + SGD (log-loss) modeli (`scripts/train_ml_classifier.py`). Bu mustaqil,
  **til-agnostik** statistik signal bo'lib, CPU'да ishlaydi va faqat xavf bahosini **ko'tara
  oladi** (fail-open — model/sklearn yo'q bo'lsa, pipeline o'zgarmay ishlaydi).
- **MITRE'ga asoslangan phishing korpusi** (1,210 texnika) — modelning bilimi — plus real
  ochiq feedlardан qurilgan **1,000,000 qatorli belgilangan dataset**, detektorni katta
  miqyosда **validatsiya** (benchmark) qilish uchun.
- **Deterministik aniqlash steki** — evristika, SPF/DKIM/DMARC autentifikatsiyasi, domen
  razvedkasi/typosquat (**homoglif** aniqlash, masalan `rnicrosoft`→`microsoft`), BEC
  signallari, prompt-injection qo'riqchisi va korpus moslashtiruvchi — LLM sekin yoki offline
  bo'lganда ham aniqlash saqlanib qoladi.
- **Real vaqt tahlili** ikki kirish nuqtasida: async IMAP monitoring va mashina ingestion
  API, dashboardга SSE orqali uzatiladi.
- **AI boshqaruvidagi GoPhish simulyatsiyalari** — model lure (aldov) ham, credential-ushlovchi
  landing sahifasini ham yozadi; GoPhish kim bosgani va kim ma'lumot kiritganini kuzatadi.
- **AI Awareness hisoboti** — simulyatsiya natijalaridan lokal LLM **xulosa yozadi**: qaysi
  bo'lim eng zaif, qanday phishingга aldanadi, qaysi bo'limga awareness trening kerak —
  **PDF ko'rinishida 3 tilда** (o'zbek/rus/ingliz) eksport qilinadi.
- **Real SIEM integratsiyasi** — Elasticsearch + Kibana, ECS/OCSF eksport, admin paneldan
  sozlanadi.
- Ko'p-ijarachili (multi-tenant) RBAC, JWT-cookie sessiyalar, adaptiv o'rganish, attachment
  zararli dastur tahlili, SOC copilot, PostgreSQL dalillar ombori.
- **Ko'p tilli interfeys** — O'zbek (asosiy) · Русский · English; til setup paytida tanlanadi.

---

## 🏗 Arxitektura

```
Kiruvchi pochta ──▶ IMAP watcher ─┐
Gateway/API     ──▶ /api/v1/emails ┤
                                   ▼
                        Aniqlash pipeline
   evristika · auth · domen-razvedka · homoglif · korpus · BEC · injection
          · CPU ML klassifikatori (til-agnostik) · maxsus LLM (asosiy)
                                   ▼
   Verdict ──▶ Karantin ──▶ PostgreSQL dalillar (IOC/MITRE/timeline)
                                   ├─▶ SIEM (ECS → Elasticsearch/Kibana)
                                   └─▶ SSE ──▶ Dashboard (:3000)
```

`:3000` dashboard UI'ni serve qiladi va **`/api`ni backendга same-origin proxy qiladi**,
shuning uchun JWT sessiya cookie'lari CORS muammolarsiz ishlaydi.

**Aniqlash qatlamlari qanday birlashadi:** LLM **asosiy** aniqlovchi (har xatга ishlaydi,
`DETECTOR_FAST_PATH=0`). Deterministik stek va CPU ML klassifikatori — **xavfsizlik to'ri**:
ular faqat ballni **ko'tara oladi**, hech qachon LLM tahlilini almashtirmaydi. Shu sababli
`rnicrosoft.com` kabi aniq homoglif LLM sekin yoki offline bo'lsa ham ushlanadi.

---

## 🐳 Lokal ishga tushirish

```bash
cp .env.example .env          # keyin secretlarni tahrirlang
docker compose up --build     # asosiy stek
```

- **Dashboard:** http://localhost:3000
- **Backend API:** http://localhost:8000  (health: `/health`, ready: `/ready`, metrics: `/metrics`)

Birinchi kirish `admin` / `admin` — server **boshqa hamma narsadan oldin parolni
o'zgartirishni majbur qiladi** (parol o'zgartirilgunча har bir boshqa endpoint 403 qaytaradi).
Parol o'zgartirish chiroyli **UI modal** orqali bo'ladi.

**Ixtiyoriy profillar:**

```bash
docker compose --profile siem up -d elasticsearch kibana   # SIEM (Kibana :5601)
./scripts/siem-setup.sh                                     # ES indeks + Kibana view
docker compose --profile production up                      # Caddy TLS reverse proxy
```

---

## 🤖 AI: maxsus model + ML klassifikatori + bilimlar bazasi

Aniqlash ochiq-manbali bilimlar bazasiga asoslangan, taxminга emas.

- **Phishing korpusi** (`data/phishing_corpus.json`) — real **MITRE ATT&CK** Enterprise
  phishing daraxtiga asoslangan 1,210 ta aniq texnika, pretext × brend × evaziya × rol
  bo'yicha kengaytirilgan.
- **Belgilangan dataset** (`scripts/build_dataset.py`) — **Phishing.Database**, **OpenPhish**,
  **URLhaus** va top-100k qonuniy domenlardan **1,000,000 qatorgacha**. Katta fayl
  git-ignored va qayta ishlab chiqariladi; namuna + statistika commit qilingan.
- **Maxsus model** (`scripts/build_phish_model.py`) — Ollama'да `threateye-phish:1.3`ni
  quradi: korpusdан distillanган ekspert brifi modelга "pishirilgan" (Ollama Modelfile) —
  gradient fine-tuning emas, prompt/parametr maxsuslashtiruvi. Tafsilotlar: [MODEL.md](MODEL.md).
- **CPU ML klassifikatori** (`scripts/train_ml_classifier.py` → `backend/services/ml_classifier.py`)
  — 1M dataset'да daqiqalarда (GPU'siz) o'qitiladi; aniqlash pipelinega **uchinchi qatlam**
  sifatida ulanadi. 2MB artefakt (`backend/models/ml_phish.joblib`) repozitoriyда.
- **Katta miqyosда validatsiya** — 1M dataset bo'yicha deterministik qatlam yolg'iz
  **precision 99.9%, recall 86%** ga yetadi (FPR ~0.07%).
- **Modelni saqlash** — `scripts/model-archive.sh export|import` o'qitilган modelni tar
  sifatida arxivlaydi (`down -v` / host qayta qurish / offline ko'chirishdan omon qoladi).
- **Boshqariladigan o'z-o'zини yaxshilash** (`scripts/self_improve.py`) — faqat
  analitik-tasdiqlaган verdictlardан o'rganadi, nomzodni validatsiya + xavfsizlik darvozasidan
  o'tgandагина ko'taradi, misol chegarasi, versiya shifti, kill-switch va audit jurnali bilan
  cheklangan (inson `--confirm` majburiy). Hech qachon avtonom emas.

Provayderni **Settings → AI Engine**dan sozlang (OpenAI / Anthropic / Groq / Ollama-lokal /
Custom). Model bilan to'g'ridan-to'g'ri gaplashish:

```bash
docker exec -it ollama ollama run threateye-phish:1.3
```

---

## 🔐 Autentifikatsiya va sessiyalar

- **JWT** (PyJWT ≥2.15.1, HS256) **access + refresh tokenlar httpOnly cookie'larда** —
  `localStorage`да token yo'q. Access ~15 min, refresh ~7 kun rotatsiya + reuse aniqlash bilan.
- **Birinchi loginда majburiy parol o'zgartirish** — `admin/admin` default endi ishlamaydi:
  `must_change_password` bayrog'i, JWT'да `mcp` claim, `require_auth` parol almashtirilgunча
  har bir non-auth endpointni 403 bilan bloklaydi. UI modal orqали (prompt emas).
- **CSRF** double-submit: o'qilsa bo'ladigan `csrf_token` cookie mutatsion so'rovlarда
  `X-CSRF-Token`да qaytariladi.
- **SSRF egress guard** (`framework/egress.py`) — admin boshqaradigan tashqi so'rovlar
  (SIEM webhook, test-imap, test-ai, integratsiya webhook'lari) private/loopback/link-local/
  reserved IP'larга (jumladan cloud metadata `169.254.169.254`ga) chiqolmaydi; bundled
  service nomlari allow-list'да. `EGRESS_*` env bilan sozlanadi.
- Login rate-limiting (per-IP, Redis), PBKDF2-HMAC-SHA256 parol saqlash, API kalitlar uchun
  HMAC-SHA256 (keyed) hash, umumiy 401, maskalangan secretlar. Qarang: [SECURITY.md](SECURITY.md).

---

## 👥 Foydalanuvchilar, rollar va ingestion API

Multi-tenant + RBAC; **Team & Access**da foydalanuvchilar va API kalitlarni boshqaring (admin).

**Rollar:** `viewer` → `analyst` → `admin` → `owner`

**Mashina ingestion** — gateway/konnektordan per-tenant API kalit bilan pochta berish:

```bash
curl -X POST http://localhost:3000/api/v1/emails \
  -H "X-API-Key: tek_xxxxxxxx" -H "Content-Type: application/json" \
  -d '{"sender":"it@0ffice365-reset.com","subject":"Mandatory password reset",
       "body":"Reset at http://0ffice365-reset.com/login and enter your password.",
       "recipient":"finance@corp.com","spf":"fail","dkim":"fail","dmarc":"fail"}'
```

Verdict, xavf bahosi, tahdid turi va tavsiya qilingan amalni qaytaradi; xabar to'liq
IOC/MITRE/timeline dalili bilan saqlanadi. Sxema o'zgarishlari startda tartibli SQL
migratsiya runner orqali qo'llanadi (`backend/migrations/`).

---

## 🛡 SOC & Blue-Team

**SOC Center** (va uning API'lari): Triage queue (`GET /api/triage`), SLA & metrikalar
(MTTD/MTTR), Threat intel (per-tenant blocklist/allowlist), ATT&CK coverage, Response actions
(`notify`/`ticket`/`clawback`/`block_ioc`), Phishing korpus API.

**Alert filtrlash:** qo'ng'iroq (bell) faqat **suspicious + karantinга olinган** pochtani
ko'rsatadi; yetkazilган past-xavfli pochta alert qilinmaydi, lekin baribar SIEM'ga yoziladi
(`ALERT_SUSPICIOUS_MIN_SCORE`).

---

## 🔌 SIEM integratsiyasi (Elasticsearch + Kibana)

Karantin ogohlantirishlari real vaqtда, **bloklamasdan**, retry va **replay** bilan SIEM'ga
uzatiladi — hammasi **Settings → Integrations**da sozlanadi.

```bash
docker compose --profile siem up -d elasticsearch kibana
./scripts/siem-setup.sh          # ECS indeks shabloni + Kibana data view
```

Keyin **Webhook URL** `http://elasticsearch:9200/threateye-alerts/_doc`, **Format** ECS.
Formatlar: `raw` / **ECS** (Elastic) / **OCSF**. `siem_min_score` yetkazilган-lekin-shubhali
pochtani ham uzatadi; `POST /api/siem-events/replay` muvaffaqiyatsiz yetkazishlarни qayta yuboradi.

---

## 🎣 Phishing simulyatsiyasi (GoPhish) — to'liq AI boshqaruvида

Xodimlar qaysi phishingга aldanishini bo'lim bo'yicha sinang — kampaniyani AI boshqaradi.

1. **GoPhishni sozlang** — Settings'да URL + API kalit (yoki `GOPHISH_URL`/`GOPHISH_API_KEY`).
2. **Rosterni import qiling** (Simulations → *Employee Roster*): `email, first_name,
   last_name, department` CSV.
3. **Ishga tushiring:**
   - **AI Automated** — model rolга mos ATT&CK texnikasini tanlaydi, lure **va** brend-mos
     credential-ushlovchi landing sahifasini yozadi va yuboradi.
   - **Manual** — CSV yuklang yoki rosterni qayta ishlating.
4. **Jalb qilишні kuzating** — GoPhish **bosish** (sahifa ochildi) va **ma'lumot kiritish**
   (forma yuborildi)ни yozadi, keyin redirect qiladi. Simulations ko'rinishi sent/opened/
   clicked/submitted, **bo'lim-zaifligi** jadvali va aynan kim bosganини ko'rsatadi.

### AI Awareness hisoboti (PDF)

Simulations → **AI Awareness Report** → til tanlang (O'zbek/Русский/English) → **Awareness PDF**.
Lokal LLM quyidagilarni yozadi: eng zaif bo'limlar, qaysi lure/ATT&CK texnikasi odamlarni
aldaydi va **ustuvorlik bo'yicha awareness-trening tavsiyalari**. API: `GET
/api/simulations/report/pdf?lang=uz|ru|en`, `GET /api/simulations/awareness`. PDF DejaVu
Unicode shriftidан foydalanadi — rus (kirill) va o'zbek matni to'g'ri chiqadi.

---

## 🌐 Ko'p tilli interfeys (i18n)

UI uch tilда ishlaydi: **O'zbek (asosiy) · Русский · English**. Birinchi ishga tushishда
setup oynasi tilni so'raydi; tanlov localStorage'да saqlanadi; yuqori-o'ngdagi tugma
tillarни almashtiradi. `frontend/i18n.js` render qilinган DOM'ни aniq to'liq-matn moslik
bo'yicha tarjima qiladi (ma'lumot qiymatlari tegilmaydi) va view qayta render bo'lganда
MutationObserver orqali qayta qo'llaydi.

LLM-yaratган matn (AI sabab, tahdid turi, tavsiya) ham **tanlangan tilда** chiqadi
(`detection_language` setting / `DETECTION_LANG` env, default `uz`).

---

## 🧠 Adaptiv o'rganish, attachmentlar, hisobotlar, copilot

- **Adaptiv o'rganish** — **Confirmed Phishing** belgilash sender/URL-domen obro'sini
  tushiradi va IOC'larни blocklist qiladi; **Safe** obro'ni ko'taradi.
- **Attachment zararli dastur tahlili** — magic bytes, xavfli/ikki kengaytma, PDF faol
  kontent, arxivlar, Office makrolar (`oletools`), SHA-256 blocklist, ixtiyoriy ClamAV.
- **Foydalanuvchi xabar bergan phishing** — `POST /api/report-phishing`.
- **AI SOC copilot** — asoslangan Q&A (`POST /api/copilot`) va per-email AI tekshiruvi.

---

## 🏗 Platforma (testlar, metrikalar, Redis, TLS, xavfsizlik skanlari)

- **Testlar + CI:** `docker compose exec backend python -m pytest` (**54 test**); GitHub
  Actions compile + testlar + compose validatsiyasini ishga tushiradi.
- **Xavfsizlik skanlari (CI):** CodeQL, Bandit (xizmat kodi), Semgrep (tokensiz OSS),
  osv-scanner (bog'liqliklar). GitHub Security tab'да **0 ochiq alert**.
- **Observability:** Prometheus metrikalari `/metrics`, `/ready`, `/health`.
- **Redis:** replikalar bo'ylab umumiy login rate-limit (`REDIS_URL`).
- **TLS:** `docker compose --profile production up` Caddy reverse proxy (`Caddyfile`) qo'shadi;
  backend TLS orqasidа HSTS yuboradi.

`frontend-react/` — UI'ning Vite + React + TS porti; repozitoriyда saqlanadi lekin **ishga
tushirilmaydi** — shipping dashboard = `frontend/` (`:3000`).

---

## ⚙ Asosiy environment o'zgaruvchilari

| O'zgaruvchi | Vazifasi |
|-------------|----------|
| `THREATEYE_AUTH_SECRET` | JWT imzolash kaliti (o'rnatilmasa auto-generatsiya + saqlash) |
| `THREATEYE_ENV` | `production` — insecure defaultларда fail-close |
| `COOKIE_SECURE` / `COOKIE_SAMESITE` | Sessiya-cookie bayroqlari (TLS orqasidа `true`) |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | Baza ma'lumotlari |
| `AI_MODEL` / `OPENAI_API_BASE` / `OPENAI_API_KEY` | LLM provayder (default `threateye-phish:1.3`) |
| `DETECTION_LANG` | LLM chiqish tili (`uz`/`ru`/`en`, default `uz`) |
| `EGRESS_GUARD` / `EGRESS_INTERNAL_HOSTS` / `EGRESS_ALLOW_CIDRS` | SSRF egress siyosati |
| `ALERT_SUSPICIOUS_MIN_SCORE` | Alertга chiqadigan minimal xavf bahosi (default 40) |
| `GOPHISH_API_KEY` / `GOPHISH_URL` / `GOPHISH_VERIFY_TLS` | GoPhish integratsiyasi |
| `SIEM_WEBHOOK_URL` / `SIEM_FORMAT` | SIEM eksport (Settings'да ham) |
| `REDIS_URL` / `CLAMAV_TCP` / `ML_MODEL_PATH` | Rate-limit / AV / ML model yo'li |

---

## 🧱 Texnologik stek

FastAPI · PostgreSQL · Redis · Ollama (`threateye-phish:1.3`, base qwen2.5:3b) ·
scikit-learn (CPU ML) · docker-mailserver (Postfix/Dovecot) · GoPhish · Elasticsearch +
Kibana · nginx · Caddy.

---

## 📌 Loyiha maqsadi

Real, o'zini-o'zi hostlaydigan email-xavfsizlik labi: bu yerda AI boshqaradigan aniqlash
AI yaratган phishingни ushlaydi — SOC ish oqimi, phishing simulyatsiyalari va SIEM
integratsiyasi bilan. **Faqat ruxsat etilган foydalanish:** tizim jonli phishing freymvorki
va pochta serverini o'z ichiga oladi; uni faqat o'zingiz nazorat qiladigan ajratilган
tarmoqда ishga tushiring.

## 🗺 Roadmap va hujjatlar

- [ROADMAP.md](ROADMAP.md) — labdan korporativ SaaS'ga yo'l, bajarilган va qolган ishlar.
- [SECURITY.md](SECURITY.md) — xavfsizlik holati, hardening, ma'lum cheklovlar.
- [MODEL.md](MODEL.md) — model qayerда ishlaydi, qayta qurish, arxivlash, o'z-o'zини yaxshilash.
