# ThreatEye modeli — `threateye-phish`

Email'ni baholaydigan va analitik savollarга javob beradigan maxsus lokal model.

## Qayerда ishlaydi

**Ollama** konteyneri ichida (`ollama` servisi), CPU'да. Bu `qwen2.5:3b`dan olingan model
bo'lib, unga ekspert system brifi "pishirib" kiritilган (phishing texnikalari, zararli dastur,
kod tahlili, ATT&CK, semantik-niyat tahlili va prompt-injection/jailbreak himoyasi).

Backend uni har email uchun OpenAI-moslashган Ollama endpoint orqali chaqiradi. Bu **asosiy**
aniqlovchi: to'liq model har email'ga default ishlaydi (`DETECTOR_FAST_PATH=0`). Deterministik
qatlamlar (autentifikatsiya, korpus, homoglif, themed-domain, injection evristikalari) va
**CPU ML klassifikatori** — **xavfsizlik to'ri**: ular faqat ballni **ko'tara oladi**, hech
qachon model tahlilini almashtirmaydi. `DETECTOR_FAST_PATH=1` aniq-hal qiluvчи holatlarни CPU'да
tezlik uchun LLM'siz o'tkazishga ruxsat beradi.

**Til:** LLM chiqishi (sabab, tahdid turi, tavsiya, agent verdictlari) **tanlangan tilда**
yoziladi — `detection_language` setting yoki `DETECTION_LANG` env, default `uz` (o'zbek).
Model phishingни **xatning o'z tilidan qat'i nazar** aniqlaydi.

```
docker exec ollama ollama ps      # ishlayotganда RAM'да yuklangan modelни ko'rsatadi
docker exec ollama ollama list    # barcha o'rnatilган modellar
```

## Model bilan to'g'ridan-to'g'ri gaplashish

```bash
docker exec -it ollama ollama run threateye-phish:1.3
```

Keyin chat qiling — email'ni baholashni, texnikani tushuntirishni, snippet ko'rishni so'rang.
Bir martalik:

```bash
docker exec ollama ollama run threateye-phish:1.3 "Homoglif domen hujumi nima va uni qanday aniqlaysiz?"
```

## Manbadan qayta qurish (qayta ishlab chiqariladigan "paket")

Aniq modelni qayta qurish uchun kerak bo'lgan hamma narsa repozitoriyда — bu kichik,
git-qulay yetkazish usuli:

```bash
python3 scripts/build_phishing_corpus.py     # MITRE-asoslangan texnika korpusi
python3 scripts/build_phish_model.py          # -> Ollama'да threateye-phish:1.3
```

`data/Modelfile.threateye-phish` — ishlab chiqarilган Modelfile (pishirilган brif). Qayta
qurish uchun Ollama'да `qwen2.5:3b` baza bo'lishi kerak.

## CPU ML klassifikatorini o'qitish (3-aniqlash qatlami)

LLM'dan alohida, mustaqil statistik signal — 1M belgilangan dataset'да (GPU'siz, daqiqalarда):

```bash
python3 scripts/train_ml_classifier.py        # -> backend/models/ml_phish.joblib
```

HashingVectorizer (lug'at saqlanmaydi → kichik model) + SGD (log-loss) — sender + subject +
body + URL'lar bo'yicha. Runtime'да `services/ml_classifier.py` 2MB artefaktни yuklaydi va
email'ни phishing ehtimoli (0-100) sifatida baholaydi; `ai_detector` uni **faqat-ko'taruvchi,
fail-open** booster sifatida ishlatadi. Dataset tartiblangan (avval phishing, keyin benign)
bo'lгani uchun o'qitishdан oldin `shuf` bilan aralashtiring.

## O'qitilган og'irliklarni saqlash/tiklash (tar)

Og'irliklar `ollama_data` Docker volume'да, image'да emas. Arxiv/tiklash:

```bash
./scripts/model-archive.sh export           # -> models/threateye-phish-<ver>-<sana>.tar.gz
./scripts/model-archive.sh import <fayl>    # volume'ga tiklaydi (offline-xavfsiz)
docker exec ollama ollama list
```

**Yengil arxiv** (`models/threateye-phish-1.3-*.tar.gz`, ~1.8 GB) faqat `threateye-phish:1.3`
+ uning `qwen2.5:3b` bazasini o'z ichiga oladi — GitHub Release asseti uchun yetarlicha kichik
(2 GB limit). Private imzolash kaliti chiqarib tashlanган. Bir xil `import` buyrug'i bilan tiklang.

> Og'irliklarni yuklash: ular oddiy `git` uchun juda katta (100 MB limit). `.tar.gz`ни
> **GitHub Release**ga biriktiring, **Git LFS** orqali push qiling yoki bulutli omborда
> saqlang. tar fayllar atayin git-ignored. Juda katta arxivlar `split` bilan bo'linadi
> (qarang `models/split-3b/`).

## Boshqariladigan o'z-o'zини yaxshilash (avtonom emas)

`scripts/self_improve.py` modelni real, tasdiqlanган ma'lumotdan kuchaytiradi — qat'iy
cheklovlar bilan:

- Faqat **analitik-tasdiqlаган** verdictlardан o'rganadi (inson ground truth), hech qachon
  o'z chiqishidан emas.
- **Nomzod** quradi va faqat **validatsiya darvozasi** o'tsa ko'taradi: datasetда sifat
  chegaralari (precision ≥ 0.98, recall ≥ 0.80) **va** anti-injection/xavfsizlik bo'limlari
  butun bo'lsa.
- **Qat'iy chegaralar:** faqat aniq `--confirm` bilan ishlaydi (hech qachon avtonom emas),
  tsikl boshiga yangi misollarни cheklaydi, versiya shiftidan oshmaydi (`1.<max>`), kill-switch
  (`data/SELF_IMPROVE_DISABLED`)ни hurmat qiladi, har tsiklni `data/self_improve_audit.jsonl`ga
  audit qiladi. Yakuniy ko'tarish qarorini doim inson qabul qiladi.

```bash
python3 scripts/self_improve.py --dry-run      # nomzod qurib tekshiradi, ko'tarmaydi
python3 scripts/self_improve.py --confirm       # to'liq tsikl; o'tsa ko'taradi
```

## Versiyalar

- `1.0` — phishing-maxsus (MITRE korpus).
- `1.1` — + zararli dastur / kod-ko'rik / web-tarmoq / ATT&CK / IR ekspertligi.
- `1.2` — + semantik-niyat tahlili, prompt-injection & jailbreak himoyasi, real-shablon asoslash.
- `1.3` — + **ikki chiqish rejimi**: salom/savol/chat uchun matn, haqiqiy email uchun faqat
  baholash JSON'i. (3b baza, tez — CPU'да ~1 min/xat.)
- `2.0` — **qwen2.5:7b baza** + ko'p tilli (Ingliz / Rus / O'zbek). Ravon rus & o'zbek chat;
  o'zbek texnik chuqurligi baza model bilan cheklangан; CPU'да ~3 min/xat. Default o'rnatilmaydi
  (CPU uchun og'ir) — kerak bo'lsa qayta quring:
  `python3 scripts/build_phish_model.py --base qwen2.5:7b --name threateye-phish:2.0`
  (avval `ollama pull qwen2.5:7b`).

**Faol default: `threateye-phish:1.3` (3b, tez).**
