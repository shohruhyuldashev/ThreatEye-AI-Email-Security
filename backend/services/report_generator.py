"""
PDF reports. Uses a bundled DejaVu Unicode font so O'zbek and Русский text render
correctly (the built-in PDF fonts are Latin-1 only). Two reports:
  - generate_analytics_pdf: detections summary + simulation victims (legacy).
  - generate_awareness_pdf: the AI security-awareness report — department risk
    ranking, lure effectiveness, and the local LLM's conclusion + training
    recommendations, in the requested language.
"""
import datetime
import os

from fpdf import FPDF

_FONT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets", "fonts")

_T = {
    "uz": {
        "title": "ThreatEye — Xavfsizlik va Phishing hisoboti",
        "generated": "Yaratilgan sana",
        "exec": "1. UMUMIY XULOSA",
        "sim": "2. PHISHING SIMULYATSIYA NATIJALARI",
        "analysis": "3. AI AWARENESS TAHLILI",
        "conclusion": "Xulosa",
        "recommend": "Tavsiyalar",
        "dept": "Bo'limlar bo'yicha zaiflik",
        "lures": "Phishing turlari samaradorligi",
        "totals_emails": "Tekshirilgan xatlar",
        "totals_threats": "Aniqlangan tahdidlar",
        "totals_quar": "Karantindagilar",
        "col_dept": "Bo'lim", "col_caught": "Aldangan", "col_total": "Jami", "col_rate": "Foiz",
        "col_lure": "Tur",
        "no_sim": "Simulyatsiya ma'lumoti yo'q.",
        "ai_note": "Tahlil local LLM tomonidan yozildi.",
        "det_note": "Tahlil deterministik qoidalar bilan yozildi (LLM mavjud emas).",
    },
    "ru": {
        "title": "ThreatEye — Отчёт по безопасности и фишингу",
        "generated": "Дата создания",
        "exec": "1. ОБЩАЯ СВОДКА",
        "sim": "2. РЕЗУЛЬТАТЫ ФИШИНГ-СИМУЛЯЦИИ",
        "analysis": "3. AI-АНАЛИЗ ОСВЕДОМЛЁННОСТИ",
        "conclusion": "Вывод",
        "recommend": "Рекомендации",
        "dept": "Уязвимость по отделам",
        "lures": "Эффективность типов фишинга",
        "totals_emails": "Проверено писем",
        "totals_threats": "Обнаружено угроз",
        "totals_quar": "В карантине",
        "col_dept": "Отдел", "col_caught": "Попались", "col_total": "Всего", "col_rate": "%",
        "col_lure": "Тип",
        "no_sim": "Нет данных симуляции.",
        "ai_note": "Анализ подготовлен локальной LLM.",
        "det_note": "Анализ подготовлен детерминированными правилами (LLM недоступна).",
    },
    "en": {
        "title": "ThreatEye — Security & Phishing Report",
        "generated": "Generated on",
        "exec": "1. EXECUTIVE SUMMARY",
        "sim": "2. PHISHING SIMULATION RESULTS",
        "analysis": "3. AI AWARENESS ANALYSIS",
        "conclusion": "Conclusion",
        "recommend": "Recommendations",
        "dept": "Department vulnerability",
        "lures": "Lure effectiveness",
        "totals_emails": "Emails scanned",
        "totals_threats": "Threats detected",
        "totals_quar": "Quarantined",
        "col_dept": "Department", "col_caught": "Caught", "col_total": "Total", "col_rate": "%",
        "col_lure": "Lure",
        "no_sim": "No simulation data available.",
        "ai_note": "Analysis written by the local LLM.",
        "det_note": "Analysis written by deterministic rules (no LLM available).",
    },
}


class _Report(FPDF):
    def __init__(self, title: str):
        super().__init__()
        self._title = title
        self.add_font("DejaVu", "", os.path.join(_FONT_DIR, "DejaVuSans.ttf"))
        self.add_font("DejaVu", "B", os.path.join(_FONT_DIR, "DejaVuSans-Bold.ttf"))

    def header(self):
        self.set_font("DejaVu", "B", 14)
        self.cell(0, 10, self._title, align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("DejaVu", "", 8)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")


def _section(pdf, text, rgb=(0, 50, 150)):
    pdf.set_font("DejaVu", "B", 12)
    pdf.set_text_color(*rgb)
    pdf.cell(0, 10, text, new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("DejaVu", "", 10)


def generate_awareness_pdf(general_stats: dict, results: dict, analysis: dict, lang: str = "uz") -> bytes:
    lang = lang if lang in _T else "uz"
    tr = _T[lang]
    pdf = _Report(tr["title"])
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_font("DejaVu", "", 9)
    pdf.cell(0, 6, f"{tr['generated']}: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}",
             align="R", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    # 1. Executive summary
    _section(pdf, tr["exec"])
    pdf.cell(0, 7, f"{tr['totals_emails']}: {general_stats.get('total_emails_scanned', 0)}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, f"{tr['totals_threats']}: {general_stats.get('suspicious_emails', 0)}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, f"{tr['totals_quar']}: {general_stats.get('quarantined_emails', 0)}", new_x="LMARGIN", new_y="NEXT")
    totals = analysis.get("totals", {})
    pdf.cell(0, 7, f"Simulation — targets: {totals.get('total', 0)}, clicked: {totals.get('clicked', 0)}, "
                   f"submitted: {totals.get('submitted', 0)}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    # 2. AI awareness analysis (conclusion + recommendations)
    _section(pdf, tr["analysis"], rgb=(200, 0, 50))
    note = tr["ai_note"] if analysis.get("llm") else tr["det_note"]
    pdf.set_font("DejaVu", "", 8); pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 5, note, new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0); pdf.set_font("DejaVu", "B", 10)
    pdf.cell(0, 7, tr["conclusion"] + ":", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("DejaVu", "", 10)
    pdf.multi_cell(0, 6, (analysis.get("conclusion") or "").strip())
    pdf.ln(1)
    pdf.set_font("DejaVu", "B", 10)
    pdf.cell(0, 7, tr["recommend"] + ":", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("DejaVu", "", 10)
    pdf.multi_cell(0, 6, (analysis.get("recommendations") or "").strip())
    pdf.ln(3)

    # Department ranking table
    dept = analysis.get("department_ranking", [])
    if dept:
        pdf.set_font("DejaVu", "B", 11)
        pdf.cell(0, 8, tr["dept"], new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("DejaVu", "B", 9)
        w = [70, 30, 25, 25]
        for label, width in zip([tr["col_dept"], tr["col_caught"], tr["col_total"], tr["col_rate"]], w):
            pdf.cell(width, 7, label, border=1)
        pdf.ln()
        pdf.set_font("DejaVu", "", 9)
        for d in dept[:20]:
            pdf.cell(w[0], 6, str(d.get("department", ""))[:40], border=1)
            pdf.cell(w[1], 6, str(d.get("caught", 0)), border=1)
            pdf.cell(w[2], 6, str(d.get("total", 0)), border=1)
            pdf.cell(w[3], 6, f"{d.get('failure_rate', 0)}%", border=1)
            pdf.ln()
            if pdf.get_y() > 255:
                pdf.add_page()
        pdf.ln(3)

    # Lure breakdown
    lures = analysis.get("lure_breakdown", [])
    if lures:
        if pdf.get_y() > 230:
            pdf.add_page()
        pdf.set_font("DejaVu", "B", 11)
        pdf.cell(0, 8, tr["lures"], new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("DejaVu", "B", 9)
        w = [95, 30, 25]
        for label, width in zip([tr["col_lure"], tr["col_caught"], tr["col_rate"]], w):
            pdf.cell(width, 7, label, border=1)
        pdf.ln()
        pdf.set_font("DejaVu", "", 9)
        for l in lures[:15]:
            pdf.cell(w[0], 6, str(l.get("lure", ""))[:55], border=1)
            pdf.cell(w[1], 6, str(l.get("caught", 0)), border=1)
            pdf.cell(w[2], 6, f"{l.get('failure_rate', 0)}%", border=1)
            pdf.ln()

    return bytes(pdf.output())


def generate_analytics_pdf(general_stats: dict, campaign_results: list) -> bytes:
    """Legacy detections + simulation-victims report (English, Unicode-safe font)."""
    tr = _T["en"]
    pdf = _Report(tr["title"])
    pdf.alias_nb_pages()
    pdf.add_page()

    _section(pdf, tr["exec"])
    pdf.cell(0, 7, f"{tr['totals_emails']}: {general_stats.get('total_emails_scanned', 0)}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, f"{tr['totals_threats']}: {general_stats.get('suspicious_emails', 0)}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, f"{tr['totals_quar']}: {general_stats.get('quarantined_emails', 0)}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    _section(pdf, tr["sim"], rgb=(200, 0, 50))
    if not campaign_results:
        pdf.cell(0, 7, tr["no_sim"], new_x="LMARGIN", new_y="NEXT")
    else:
        for idx, camp in enumerate(campaign_results):
            results = camp.get("results", {})
            total = results.get("total", 0)
            clicked = results.get("clicked", 0)
            rate = round((clicked / total) * 100, 1) if total else 0
            pdf.set_font("DejaVu", "B", 10)
            pdf.cell(0, 7, f"Campaign {idx+1}: {camp.get('name', 'N/A')} ({camp.get('launch_date', '')})",
                     new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("DejaVu", "", 10)
            pdf.cell(0, 6, f"   Targets: {total}  |  Caught: {clicked} ({rate}%)", new_x="LMARGIN", new_y="NEXT")
            for victim in camp.get("victims", []):
                pdf.cell(0, 5, f"     - {victim.get('email')} "
                               f"({victim.get('first_name', '')} {victim.get('last_name', '')})",
                         new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)
            if pdf.get_y() > 255:
                pdf.add_page()
    return bytes(pdf.output())
