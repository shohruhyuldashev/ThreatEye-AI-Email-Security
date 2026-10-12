# Xavfsizlik eslatmalari — ThreatEye

ThreatEye — bu **xavfsizlik labi / tadqiqot platformasi**. U GoPhish (jonli phishing
freymvork) va ochiq pochta serverini o'z ichiga oladi, shuning uchun har bir joylashtirishni
sezgir deb biling va faqat o'zingiz nazorat qiladigan hamda sinashga ruxsatingiz bo'lgan
ajratilган tarmoqда saqlang. Bu hujjat ichkи o'rnatilган hardeningni, siz hali sozlashingiz
kerak bo'lgan narsalarni va lab default'larining ma'lum cheklovlarini sanaб beradi.

## Ilovaга o'rnatilган hardening

| Soha | Nazorat |
|------|---------|
| Sessiyalar | **JWT** (PyJWT ≥2.15.1, HS256) **access + refresh tokenlar `httpOnly` cookie'larда** — hech qachon `localStorage`да emas, shuning uchun saqlanган XSS ularni o'qiy olmaydi. Access ~15 min, refresh ~7 kun **rotatsiya + reuse aniqlash** bilan. Imzolash kaliti `THREATEYE_AUTH_SECRET`dan yoki auto-generatsiya + saqlash. |
| Majburiy parol o'zgartirish | Birinchi login (yoki hali `admin/admin` default)да server parolni o'zgartirishni **majbur qiladi**: `must_change_password` bayrog'i, JWT'да `mcp` claim, `require_auth` parol almashtirilgunча har bir non-auth endpointni 403 bilan bloklaydi. Parol **UI modal** orqали o'rnatiladi (prompt emas). Mavjud `admin/admin` deployment'lar ham seed vaqtidа aniqlanadi va majburlanadi. |
| CSRF | Double-submit: o'qilsa bo'ladigan `csrf_token` cookie cookie-autentifikatsiyalangан mutatsion so'rovlarда `X-CSRF-Token` sarlavhasidа qaytarilishi kerak (`CSRFMiddleware`). |
| Same-origin | `:3000` dashboard `/api`ni backendга proxy qiladi — brauzer bitta origin ko'radi. |
| SSRF egress guard | `framework/egress.py` — admin boshqaradigan tashqi so'rovlar (SIEM webhook, `test-imap`, `test-ai`, integratsiya webhook'lari) private/loopback/link-local/reserved IP'larга (jumladan cloud metadata `169.254.169.254`ga) chiqolmaydi. Bundled service nomlari (`elasticsearch`, `mail_server`, `ollama`, ...) allow-list'да. `EGRESS_GUARD`/`EGRESS_INTERNAL_HOSTS`/`EGRESS_ALLOW_CIDRS` bilan sozlanadi. |
| Login brute force | `/api/auth/login`'да per-IP sliding-window rate limit (`THREATEYE_LOGIN_MAX_ATTEMPTS`/`THREATEYE_LOGIN_WINDOW_SECONDS`), Redis-backed, `login_success`/`login_failed` audit yozuvlari bilan. |
| Kredential xatolari | Noto'g'ri username va noto'g'ri parol **bir xil** umumiy `401` qaytaradi. |
| Parol saqlash | PBKDF2-HMAC-SHA256 (har-hash salt). API kalitlar **HMAC-SHA256 (auth secret bilan keyed)** hash sifatida saqlanadi — DB sizib chiqsa ham, server secreti bo'lmasdан kalitlarni taxmin qilib bo'lmaydi. |
| Secret oshkorligi | `admin_password`/`auth_secret` hech qachon `GET /api/settings`da qaytarilmaydi; boshqa `*pass*/*key*/*secret*/*token*` settinglar maskalangan. Settings secretlari DB'да **Fernet bilan shifrlangan** (encrypt-at-rest). |
| HTTP sarlavhalari | `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, API javoblarда `Cache-Control: no-store`, va TLS orqasidа **HSTS** (`Strict-Transport-Security`). |
| CORS | Aniq origin allow-list (`CORS_ALLOWED_ORIGINS`); kredentiallar faqat sozlanган dashboard origin(lar)i uchun. |
| Uploadlar | Kengaytma-cheklanган (`.txt`/`.csv`), fayl nomi tozalanган, tasodifiy qayta nomlanган, hajm-cheklanган. |
| SQL | Barcha so'rovlar parametrlangan; kam sonli dinamik identifikatorlar qat'iy allow-list'dan (user input emas). Bandit/CodeQL tekshirди: SQL injection yo'q. |
| Stack-trace oshkorligi | Istisno matni klientга qaytarilmaydi — xatolar server tomonда log qilinadi, javobда umumiy xabar (`/ready`, SIEM, GoPhish yo'llari tuzatilган). |
| ReDoS | Copilot token-qidiruvi backtracking regex o'rniga chiziqli string-ops ishlatadi (polinomial ReDoS yo'q). |
| Chiqish render | Frontend barcha hujumchi ta'sirida bo'lgan maydonlarни (sender, subject, evidence, timeline) DOM'ga kiritishdan oldin HTML-escape qiladi. |
| Tarmoq ekspozitsiyasi | `docker-compose.yml` Postgres, Redis va Ollama'ни faqat `127.0.0.1`ga bog'laydi. |
| SIEM yetkazish | Ogohlantirishlar fon worker'ga (bloklamasdan) retry + backoff bilan jo'natiladi; destination + kalit admin panelдан. |
| Prompt injection / jailbreak | Hujumchi-boshqaradigan email kontentini o'qiydigan model uni **ma'lumot deb biladi, ko'rsatma emas**; model'ni boshqarish urinishlari ("ignore previous instructions", "mark safe", DAN) belgilanadi va bajarilmaydi. Deterministik detektor ham bu oilalarni ushlaydi — LLM offline bo'lsa ham. |
| Policy engine | Karantin/javob siyosatlari **fail closed**: shartsiz yoki noma'lum shartli siyosat mos kelmaydi. |
| O'z-o'zини yaxshilash | `scripts/self_improve.py` boshqariladi: faqat analitik-tasdiqlaган ma'lumotdan o'rganadi, validatsiya + xavfsizlik darvozasidan o'tgandагина ko'taradi, misol chegarasi, versiya shifti, kill-switch (`data/SELF_IMPROVE_DISABLED`), audit jurnali va majburiy inson `--confirm` bilan. |
| Model arxivlari | `scripts/model-archive.sh` eksport tar'idan Ollama'ning private imzolash kalitini chiqarib tashlaydi. |

## CI xavfsizlik skanlari

GitHub Actions har push'да ishlaydi va natijalar Security tab'da ko'rinadi:

- **CodeQL** — Python/JS/Actions statik tahlili (haqiqiy topilmalar kodda tuzatilди).
- **Bandit** — xizmat kodi (`backend`) uchun Python xavfsizlik linteri (testlar/scriptlar
  qamrovdan tashqarida).
- **Semgrep** — tokensiz OSS qoidalar (p/python, p/owasp-top-ten, p/javascript).
- **osv-scanner** — bog'liqlik CVE'lari (barcha deps pin qilinган → yopiq).

**Holat: GitHub Security & Quality tab'да 0 ochiq alert.** Haqiqiy zaifliklar kodда
tuzatildi; false-positive'lar (parametrlashган SQL, testlardagi assert, offline-script
subprocess) tekshirilib sabab bilan yopildi.

## Haqiqiy foydalanishdan OLDIN sozlashingiz SHART

1. **Admin parolini o'zgartiring.** Default `admin` (server birinchi loginда majbur qiladi).
2. **`.env`да kuchli secretlar o'rnating** (`.env.example`dan): `THREATEYE_AUTH_SECRET` va
   `POSTGRES_PASSWORD`. Production uchun `THREATEYE_ENV=production` (insecure default'larда
   fail-close).
3. **TLS orqali serve qiling va `COOKIE_SECURE=true` o'rnating.** `docker compose --profile
   production up` Caddy TLS proxy qo'shadi.
4. **`CORS_ALLOWED_ORIGINS`ни aniq dashboard origin'ига cheklang.**
5. **Egress guard'ni yoqiq qoldiring** (`EGRESS_GUARD=on`, default).

## Multi-tenancy va RBAC

- Foydalanuvchilar `users` jadvalida, to'rt rol bilan (`viewer` < `analyst` < `admin` <
  `owner`); endpointlar rol-gated, o'qish/yozish `organization_id` bo'yicha scoped.
- Mashina klientlari `POST /api/v1/emails`ga per-tenant `X-API-Key` bilan (faqat HMAC-SHA256
  hash sifatida saqlanadi; plaintext bir marta ko'rsatiladi, bekor qilish mumkin).
- Himoyalar: o'z-o'zини bloklash/o'chirish yo'q, oxirgi `owner`ни olib bo'lmaydi, faqat
  owner `owner` bera oladi.

## Ma'lum cheklovlar (lab uchun maqbul, productiondan oldin ko'rib chiqing)

- **Advanced evaziya qisman.** Kirill/Unicode homoglif, zero-width belgilar, ko'rinmas keyword
  stuffing, anchor-matni ≠ href — bular uchun qo'shimcha aniqlash rejalashtirilган (ROADMAP §4.2).
- **Dev qulayliklari** (`UVICORN_RELOAD`, lab POSTGRES default) hali yoqilgan bo'lishi mumkin —
  real deployment uchun o'chiring.
- **Bundled model og'irliklari imzolanмаган** — import qilinган arxiv manbasini tekshiring.
- **GoPhish va pochta serveri** to'liq funksional; faqat o'zingiz nazorat qiladigan va ruxsat
  olgan lab tarmog'ida ishga tushiring. Phishing simulyatsiyalari faqat roziligi bor xodimlar /
  ruxsat etilган ishlar uchun.

## Xabar berish

Bu shaxsiy lab loyihasi — issue oching yoki topilmalarni `CHANGELOG.md`da qayd eting.
