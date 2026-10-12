"""
Security-awareness analysis — turn phishing-simulation results into a conclusion
a CISO can act on: which departments are most vulnerable, which lure types fool
them, and where to run awareness training first.

The local LLM writes the narrative + recommendations (grounded strictly in the
simulation numbers, in the requested language — O'zbek / Русский / English). A
deterministic summary is returned when no model is reachable, so the report
always renders.
"""
from __future__ import annotations

import os

from typing import Any

from framework.copilot import _llm_text

_LANG_NAME = {"uz": "O'zbek (Uzbek)", "ru": "Русский (Russian)", "en": "English"}


def _rank_departments(departments: list[dict]) -> list[dict]:
    """Add a failure rate and sort worst-first."""
    ranked = []
    for d in departments or []:
        total = d.get("total", 0) or 0
        # Submitting credentials implies clicking, so "caught" = people who at least
        # clicked (never double-count), and the rate can't exceed 100%.
        caught = min(max(d.get("clicked", 0) or 0, d.get("submitted", 0) or 0), total) if total else 0
        rate = round(min(100.0, (caught / total) * 100), 1) if total else 0.0
        ranked.append({**d, "caught": caught, "failure_rate": rate})
    return sorted(ranked, key=lambda x: (x["failure_rate"], x["caught"]), reverse=True)


def _lure_breakdown(campaigns: list[dict]) -> list[dict]:
    """Aggregate caught counts by the ATT&CK technique / lure each campaign modelled."""
    by_lure: dict[str, dict] = {}
    for c in campaigns or []:
        lure = c.get("technique") or c.get("lure") or c.get("name") or "Unknown"
        res = c.get("results", {}) if isinstance(c.get("results"), dict) else {}
        caught = (res.get("clicked", 0) or 0) + (res.get("submitted", 0) or 0)
        total = res.get("total", 0) or 0
        row = by_lure.setdefault(lure, {"lure": lure, "caught": 0, "total": 0})
        row["caught"] += caught
        row["total"] += total
    out = list(by_lure.values())
    for r in out:
        r["failure_rate"] = round((r["caught"] / r["total"]) * 100, 1) if r["total"] else 0.0
    return sorted(out, key=lambda x: x["caught"], reverse=True)


def _facts(dept_ranked: list[dict], lures: list[dict], totals: dict) -> str:
    lines = [
        f"Overall targets: {totals.get('total', 0)}; opened: {totals.get('opened', 0)}; "
        f"clicked: {totals.get('clicked', 0)}; submitted credentials: {totals.get('submitted', 0)}.",
        "Department failure rates (worst first):",
    ]
    for d in dept_ranked[:12]:
        lines.append(f"  - {d['department']}: {d['caught']}/{d['total']} caught ({d['failure_rate']}%)")
    if lures:
        lines.append("Lure/technique effectiveness (most people caught first):")
        for l in lures[:10]:
            lines.append(f"  - {l['lure']}: {l['caught']} caught ({l['failure_rate']}% of {l['total']})")
    return "\n".join(lines)


def _deterministic_conclusion(dept_ranked: list[dict], lures: list[dict], lang: str,
                              totals: dict | None = None) -> dict:
    """
    A rich, data-grounded analysis written from templates, so the grammar is clean
    and correct in every language (unlike the small base model's weak O'zbek/Русский
    free-text). Covers overall numbers, a per-department breakdown worst→best, the
    most effective lure, and prioritised training recommendations.
    """
    totals = totals or {}
    hit = [d for d in dept_ranked if d["caught"] > 0]
    safe = [d for d in dept_ranked if d["caught"] == 0 and d.get("total", 0) > 0]
    worst = hit[0] if hit else None
    worst_lure = lures[0] if lures and lures[0]["caught"] else None
    t_total = totals.get("total", 0)
    t_click = totals.get("clicked", 0)
    t_sub = totals.get("submitted", 0)

    if lang == "ru":
        con = [f"Симуляция: {t_total} целей, {t_click} перешли по ссылке, {t_sub} ввели данные."]
        if worst:
            con.append(f"Наиболее уязвим отдел «{worst['department']}» — "
                       f"{worst['caught']} из {worst['total']} ({worst['failure_rate']}%).")
        for d in hit[1:4]:
            con.append(f"Отдел «{d['department']}»: {d['caught']}/{d['total']} ({d['failure_rate']}%).")
        if safe:
            con.append("Без инцидентов: " + ", ".join(d["department"] for d in safe[:5]) + ".")
        if worst_lure:
            con.append(f"Самая результативная приманка — «{worst_lure['lure']}» "
                       f"({worst_lure['caught']} чел.).")
        rec = []
        for i, d in enumerate(hit[:3], 1):
            rec.append(f"{i}. «{d['department']}»: приоритетное обучение распознаванию фишинга "
                       f"(сброс пароля, счета/реквизиты), проверка платежей вне почты, фишинг-устойчивая MFA.")
        if not rec:
            rec.append("Заметных слабых мест нет — поддерживайте регулярные тренинги и MFA.")
        return {"conclusion": " ".join(con), "recommendations": "\n".join(rec), "llm": False}

    if lang == "en":
        con = [f"Simulation: {t_total} targets, {t_click} clicked the link, {t_sub} submitted data."]
        if worst:
            con.append(f"Most at risk is the '{worst['department']}' department — "
                       f"{worst['caught']} of {worst['total']} ({worst['failure_rate']}%).")
        for d in hit[1:4]:
            con.append(f"'{d['department']}': {d['caught']}/{d['total']} ({d['failure_rate']}%).")
        if safe:
            con.append("No incidents: " + ", ".join(d["department"] for d in safe[:5]) + ".")
        if worst_lure:
            con.append(f"The most effective lure was '{worst_lure['lure']}' "
                       f"({worst_lure['caught']} caught).")
        rec = []
        for i, d in enumerate(hit[:3], 1):
            rec.append(f"{i}. '{d['department']}': priority awareness training on recognising phishing "
                       f"(password-reset, invoice/bank-detail lures), out-of-band payment verification, "
                       f"and phishing-resistant MFA.")
        if not rec:
            rec.append("No significant weakness — keep up regular training and MFA.")
        return {"conclusion": " ".join(con), "recommendations": "\n".join(rec), "llm": False}

    # O'zbek (default)
    con = [f"Simulyatsiya: {t_total} ta xodim nishonga olindi, {t_click} tasi havolani bosdi, "
           f"{t_sub} tasi ma'lumot kiritdi."]
    if worst:
        con.append(f"Eng zaif bo'lim — «{worst['department']}»: {worst['caught']} tadan {worst['total']} "
                   f"({worst['failure_rate']}%) aldandi.")
    for d in hit[1:4]:
        con.append(f"«{d['department']}» bo'limi: {d['caught']}/{d['total']} ({d['failure_rate']}%).")
    if safe:
        con.append("Hech kim aldanmagan bo'limlar: " + ", ".join(d["department"] for d in safe[:5]) + ".")
    if worst_lure:
        con.append(f"Eng ko'p ishlagan aldov turi — «{worst_lure['lure']}» "
                   f"({worst_lure['caught']} kishi aldandi).")
    rec = []
    for i, d in enumerate(hit[:3], 1):
        rec.append(f"{i}. «{d['department']}» bo'limi: phishingni tanish bo'yicha ustuvor awareness trening "
                   f"(parol tiklash, hisob-faktura/bank rekvizit aldovlari), to'lovlarni pochtadan tashqari "
                   f"tasdiqlash va phishingga chidamli MFA joriy etish.")
    if not rec:
        rec.append("Sezilarli zaiflik aniqlanmadi — muntazam trening va MFA'ni saqlab turing.")
    return {"conclusion": " ".join(con), "recommendations": "\n".join(rec), "llm": False}


def generate_awareness_report(results: dict, lang: str = "uz", use_llm: bool = True) -> dict[str, Any]:
    """
    results: the dict from services.gophish_client.get_results()
             ({campaigns, departments, employees, ...}).
    use_llm: when False, skip the (slow, CPU-bound) model call and return the
             deterministic conclusion — used for the responsive inline Analytics
             panel; the PDF export uses the full LLM write-up.
    Returns {conclusion, recommendations, department_ranking, lure_breakdown, llm}.
    """
    lang = lang if lang in _LANG_NAME else "uz"
    departments = results.get("departments", []) or []
    campaigns = results.get("campaigns", []) or []
    dept_ranked = _rank_departments(departments)
    lures = _lure_breakdown(campaigns)

    totals = {
        "total": sum(d.get("total", 0) or 0 for d in departments),
        "opened": sum(d.get("opened", 0) or 0 for d in departments),
        "clicked": sum(d.get("clicked", 0) or 0 for d in departments),
        "submitted": sum(d.get("submitted", 0) or 0 for d in departments),
    }

    facts = _facts(dept_ranked, lures, totals)
    _lang_instr = {
        "uz": "MUHIM: Javobni TO'LIQ o'zbek tilida yoz. Har bir gap, xulosa va tavsiya "
              "o'zbekcha bo'lishi SHART. Inglizcha yoki ruscha yozma.",
        "ru": "ВАЖНО: Пиши ответ ПОЛНОСТЬЮ на русском языке. Каждое предложение и "
              "рекомендация должны быть на русском. Не пиши по-английски.",
        "en": "Write the entire answer in clear, professional English.",
    }[lang]
    system = (
        _lang_instr + " "
        "You are a cybersecurity awareness advisor for a SOC. Using ONLY the phishing "
        "simulation statistics provided (do not invent names or numbers), write a short, "
        "board-ready analysis. Cover: which departments are most at risk, which phishing "
        "lure types fool them, and concrete awareness-training recommendations prioritised "
        "by department. Be concise and practical. "
        "Use exactly two headers on their own lines — 'CONCLUSION:' and 'RECOMMENDATIONS:' — "
        f"but write ALL the content after them in {_LANG_NAME[lang]}. " + _lang_instr
    )
    user = facts + "\n\n" + _lang_instr

    # The 3b base model writes fluent English but garbled O'zbek/Русский, so we only
    # let it free-write for English. For uz/ru we use the rich, data-grounded
    # template below — clean, correct grammar. (A 7b+ multilingual model could be
    # allowed to free-write uz/ru here via ALLOW_LLM_MULTILINGUAL=1.)
    allow_llm = use_llm and (lang == "en" or os.getenv("ALLOW_LLM_MULTILINGUAL") == "1")
    text = _llm_text(system, user) if allow_llm else None

    conclusion = recommendations = None
    if text:
        up = text
        import re
        m = re.split(r"(?i)recommendations?\s*:", up, maxsplit=1)
        if len(m) == 2:
            conclusion = re.sub(r"(?i)^.*?conclusion\s*:", "", m[0], count=1).strip() or m[0].strip()
            recommendations = m[1].strip()
        else:
            conclusion = up.strip()
    if not conclusion:
        det = _deterministic_conclusion(dept_ranked, lures, lang, totals)
        conclusion, recommendations, used_llm = det["conclusion"], det["recommendations"], False
    else:
        used_llm = True
        if not recommendations:
            recommendations = _deterministic_conclusion(dept_ranked, lures, lang, totals)["recommendations"]

    return {
        "conclusion": conclusion,
        "recommendations": recommendations,
        "department_ranking": dept_ranked,
        "lure_breakdown": lures,
        "totals": totals,
        "lang": lang,
        "llm": used_llm,
    }
