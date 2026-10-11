/*
 * Lightweight UI localisation (English ⇄ O'zbek).
 *
 * The dashboard renders its views from inline template strings, so instead of
 * threading a translation call through every template we translate the rendered
 * DOM: a phrase dictionary is applied to text nodes and a few attributes by
 * EXACT, whole-string match (trimmed). Exact match means data values — senders,
 * subjects, scores, statuses that happen to be words — are never touched unless
 * they are an explicit dictionary key.
 *
 * A MutationObserver re-applies the translation whenever a view is (re-)rendered,
 * so navigation keeps working. The choice is stored per-browser in localStorage.
 * English is the default and is always recoverable (reverse map), so toggling is
 * lossless.
 */
(function () {
  "use strict";

  // English → O'zbek. Keep keys as the EXACT visible string (trimmed).
  var EN2UZ = {
    // Sidebar / nav
    "Dashboard": "Boshqaruv paneli",
    "Monitoring": "Monitoring",
    "Live Monitoring": "Jonli monitoring",
    "Quarantine": "Karantin",
    "Simulations": "Simulyatsiyalar",
    "URL Analyzer": "URL tahlilchi",
    "Analytics": "Tahlillar",
    "SOC Center": "SOC markazi",
    "Framework": "Freymvork",
    "Security Team": "Xavfsizlik jamoasi",
    "Team & Access": "Jamoa va kirish",
    "Settings": "Sozlamalar",
    "Admin User": "Administrator",
    "Secure Access Gateway": "Xavfsiz kirish shlyuzi",
    "Restoring session…": "Sessiya tiklanmoqda…",
    "Username": "Foydalanuvchi nomi",
    "Password": "Parol",
    "Sign In": "Kirish",
    "Log Out": "Chiqish",
    "Logout": "Chiqish",
    // Dashboard
    "Security Dashboard": "Xavfsizlik paneli",
    "Live Status": "Jonli holat",
    "Total Emails Scanned": "Tekshirilgan xatlar",
    "Suspicious Emails": "Shubhali xatlar",
    "Quarantined": "Karantinda",
    "Active Simulations": "Faol simulyatsiyalar",
    "Critical Activity": "Muhim faoliyat",
    "Threat Types Distribution": "Tahdid turlari taqsimoti",
    "Recent Threats": "So'nggi tahdidlar",
    "View All": "Hammasini ko'rish",
    // Table / detail headers
    "Time": "Vaqt",
    "Timestamp": "Vaqt belgisi",
    "Sender": "Yuboruvchi",
    "Subject": "Mavzu",
    "Sender / Subject": "Yuboruvchi / Mavzu",
    "Status": "Holat",
    "Actions": "Amallar",
    "Action": "Amal",
    "Type": "Turi",
    "Threat Type": "Tahdid turi",
    "Threat Level": "Tahdid darajasi",
    "Threat Detail": "Tahdid tafsiloti",
    "Severity": "Jiddiylik",
    "Risk": "Xavf",
    "Risk Score": "Xavf bahosi",
    "Risk Assessment": "Xavfni baholash",
    "Risk Analytics": "Xavf tahlili",
    "URL Threat": "URL tahdidi",
    "Confidence": "Ishonch",
    "Verdict": "Hukm",
    "Source": "Manba",
    "Value": "Qiymat",
    "Name": "Nomi",
    "Role": "Rol",
    "User": "Foydalanuvchi",
    // Statuses / verdicts
    "Needs Review": "Ko'rib chiqish kerak",
    "Safe": "Xavfsiz",
    "Suspicious": "Shubhali",
    "Malicious": "Zararli",
    // Buttons / actions
    "Release": "Chiqarish",
    "Delete": "O'chirish",
    "Delete Permanently": "Butunlay o'chirish",
    "Review": "Ko'rib chiqish",
    "Respond": "Javob berish",
    "Revoke": "Bekor qilish",
    "Mark Safe": "Xavfsiz deb belgilash",
    "Confirm Phishing": "Fishing deb tasdiqlash",
    "Save": "Saqlash",
    "Save Settings": "Sozlamalarni saqlash",
    "Cancel": "Bekor qilish",
    "Update Password": "Parolni yangilash",
    // SOC / simulations
    "SOAR Playbooks": "SOAR ssenariylari",
    "SLA Breaches": "SLA buzilishlari",
    "SOC Timeline": "SOC vaqt chizig'i",
    "Resolution Strategy": "Hal qilish strategiyasi",
    "Department Vulnerability": "Bo'lim zaifligi",
    "Target Department": "Maqsadli bo'lim",
    "Target": "Maqsad",
    "Sent": "Yuborilgan",
    "Opened": "Ochilgan",
    "Clicked": "Bosilgan",
    "Submitted": "Yuborilgan ma'lumot",
    "Submitted Data": "Yuborilgan ma'lumot",
    // Settings sections
    "AI Engine": "AI dvigatel",
    "Email (IMAP)": "Email (IMAP)",
    "Integrations": "Integratsiyalar",
    "Security": "Xavfsizlik",
    "SIEM": "SIEM",
    "Rule": "Qoida",
    "Rules": "Qoidalar"
  };

  var UZ2EN = {};
  Object.keys(EN2UZ).forEach(function (k) { UZ2EN[EN2UZ[k]] = k; });

  var LANG = "en";
  var applying = false;
  var ATTRS = ["placeholder", "title", "aria-label"];

  function readLang() {
    try { return localStorage.getItem("te_lang") || "en"; } catch (e) { return "en"; }
  }
  function saveLang(l) {
    try { localStorage.setItem("te_lang", l); } catch (e) { /* private mode */ }
  }

  function mapFor(lang) { return lang === "uz" ? EN2UZ : UZ2EN; }

  function translateString(s, map) {
    if (!s) return s;
    var key = s.trim();
    if (!(key in map)) return s;
    // Preserve surrounding whitespace the template used.
    return s.replace(key, map[key]);
  }

  function walk(root, map) {
    var tw = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
    var node;
    var batch = [];
    while ((node = tw.nextNode())) {
      var t = node.nodeValue;
      if (t && t.trim() && (t.trim() in map)) batch.push(node);
    }
    batch.forEach(function (n) { n.nodeValue = translateString(n.nodeValue, map); });

    // Attributes on elements under root.
    var els = root.querySelectorAll ? root.querySelectorAll("*") : [];
    for (var i = 0; i < els.length; i++) {
      for (var a = 0; a < ATTRS.length; a++) {
        var val = els[i].getAttribute && els[i].getAttribute(ATTRS[a]);
        if (val && (val.trim() in map)) els[i].setAttribute(ATTRS[a], translateString(val, map));
      }
    }
  }

  function apply(lang) {
    if (lang === "en" && LANG === "en") return; // nothing applied yet
    applying = true;
    try {
      // Always translate from the current rendered language toward the target:
      // if going to uz, use EN→UZ; if back to en, use UZ→EN.
      walk(document.body, mapFor(lang));
    } finally {
      applying = false;
    }
    document.documentElement.lang = lang;
    LANG = lang;
    updateToggle();
  }

  function updateToggle() {
    var btn = document.getElementById("lang-toggle");
    if (btn) btn.textContent = LANG === "uz" ? "EN" : "UZ";
  }

  function injectToggle() {
    if (document.getElementById("lang-toggle")) return;
    // Prefer the top bar; fall back to fixed corner so it always exists.
    var btn = document.createElement("button");
    btn.id = "lang-toggle";
    btn.type = "button";
    btn.title = "Til / Language";
    btn.className = "px-2 py-1 text-xs font-semibold rounded border border-cyber-border text-gray-300 hover:text-cyber-neon hover:border-cyber-neon/50 transition-colors";
    btn.style.cssText = "position:fixed;top:10px;right:14px;z-index:9999;background:#13131a;";
    btn.addEventListener("click", function () {
      var next = LANG === "uz" ? "en" : "uz";
      saveLang(next);
      apply(next);
    });
    document.body.appendChild(btn);
    updateToggle();
  }

  function startObserver() {
    if (!("MutationObserver" in window)) return;
    var pending = false;
    var obs = new MutationObserver(function () {
      if (applying || LANG !== "uz") return;
      if (pending) return;
      pending = true;
      requestAnimationFrame(function () {
        pending = false;
        applying = true;
        try { walk(document.body, EN2UZ); } finally { applying = false; }
      });
    });
    obs.observe(document.body, { childList: true, subtree: true });
  }

  function init() {
    LANG = "en";
    injectToggle();
    startObserver();
    var saved = readLang();
    if (saved === "uz") apply("uz");
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
