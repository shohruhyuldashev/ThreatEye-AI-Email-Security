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


def _deterministic_conclusion(dept_ranked: list[dict], lures: list[dict], lang: str) -> dict:
    top = [d["department"] for d in dept_ranked[:3] if d["caught"] > 0]
    worst_lure = lures[0]["lure"] if lures and lures[0]["caught"] else None
    headlines = {
        "uz": {
            "con": "Simulyatsiya natijalariga ko'ra eng ko'p aldangan bo'limlar: "
                   + (", ".join(top) if top else "sezilarli zaiflik aniqlanmadi") + ".",
            "rec": "Awareness treningini birinchi navbatda yuqoridagi bo'limlarда o'tkazish tavsiya etiladi"
                   + (f"; ayniqsa '{worst_lure}' turidagi phishingga qarshi." if worst_lure else "."),
        },
        "ru": {
            "con": "По результатам симуляции наиболее уязвимые отделы: "
                   + (", ".join(top) if top else "заметной уязвимости не выявлено") + ".",
            "rec": "Рекомендуется провести обучение в первую очередь в указанных отделах"
                   + (f"; особенно против фишинга типа «{worst_lure}»." if worst_lure else "."),
        },
        "en": {
            "con": "Based on the simulation, the most susceptible departments are: "
                   + (", ".join(top) if top else "no significant weakness found") + ".",
            "rec": "Run awareness training in the departments above first"
                   + (f"; especially against '{worst_lure}' style phishing." if worst_lure else "."),
        },
    }
    h = headlines.get(lang, headlines["en"])
    return {"conclusion": h["con"], "recommendations": h["rec"], "llm": False}


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
    system = (
        "You are a cybersecurity awareness advisor for a SOC. Using ONLY the phishing "
        "simulation statistics provided (do not invent names or numbers), write a short, "
        "board-ready analysis. Cover: which departments are most at risk, which phishing "
        "lure types fool them, and concrete awareness-training recommendations prioritised "
        "by department. Be concise and practical. "
        f"Write the entire answer in {_LANG_NAME[lang]}. "
        "Return two clearly separated parts with these exact headers on their own lines: "
        "CONCLUSION: then the analysis, and RECOMMENDATIONS: then a short prioritised list."
    )
    text = _llm_text(system, facts) if use_llm else None

    conclusion = recommendations = None
    if text:
        up = text
        # Split on the headers the prompt asked for (robust to case / translation echo).
        import re
        m = re.split(r"(?i)recommendations?\s*:", up, maxsplit=1)
        if len(m) == 2:
            conclusion = re.sub(r"(?i)^.*?conclusion\s*:", "", m[0], count=1).strip() or m[0].strip()
            recommendations = m[1].strip()
        else:
            conclusion = up.strip()
    if not conclusion:
        det = _deterministic_conclusion(dept_ranked, lures, lang)
        conclusion, recommendations, used_llm = det["conclusion"], det["recommendations"], False
    else:
        used_llm = True
        if not recommendations:
            recommendations = _deterministic_conclusion(dept_ranked, lures, lang)["recommendations"]

    return {
        "conclusion": conclusion,
        "recommendations": recommendations,
        "department_ranking": dept_ranked,
        "lure_breakdown": lures,
        "totals": totals,
        "lang": lang,
        "llm": used_llm,
    }
