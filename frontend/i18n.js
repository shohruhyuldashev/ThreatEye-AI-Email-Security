/*
 * UI localisation — O'zbek (default) · Русский · English.
 *
 * The dashboard renders views from inline template strings, so we translate the
 * rendered DOM instead of threading a t() through every template: each text node
 * and a few attributes are matched by EXACT, whole-string key (trimmed) against a
 * per-language dictionary. The ENGLISH source string is the key; the first time a
 * node is seen its English text is cached, so switching between any two languages
 * (and re-translating re-rendered views) is lossless.
 *
 * Primary language is O'zbek. On first run a setup picker asks for uz/ru/en and
 * the choice is stored per-browser; it can be changed from the top-right switch.
 * A MutationObserver re-applies after every view (re-)render.
 */
(function () {
  "use strict";

  // English source → { uz, ru }. English needs no entry (it is the source).
  var DICT = {
    "Dashboard":            { uz: "Boshqaruv paneli",     ru: "Панель" },
    "Monitoring":           { uz: "Monitoring",           ru: "Мониторинг" },
    "Live Monitoring":      { uz: "Jonli monitoring",     ru: "Живой мониторинг" },
    "Quarantine":           { uz: "Karantin",             ru: "Карантин" },
    "Simulations":          { uz: "Simulyatsiyalar",      ru: "Симуляции" },
    "URL Analyzer":         { uz: "URL tahlilchi",        ru: "Анализ URL" },
    "Analytics":            { uz: "Tahlillar",            ru: "Аналитика" },
    "SOC Center":           { uz: "SOC markazi",          ru: "SOC центр" },
    "Framework":            { uz: "Freymvork",            ru: "Фреймворк" },
    "Security Team":        { uz: "Xavfsizlik jamoasi",   ru: "Команда безопасности" },
    "Team & Access":        { uz: "Jamoa va kirish",      ru: "Команда и доступ" },
    "Settings":             { uz: "Sozlamalar",           ru: "Настройки" },
    "Admin User":           { uz: "Administrator",        ru: "Администратор" },
    "Secure Access Gateway":{ uz: "Xavfsiz kirish shlyuzi", ru: "Шлюз безопасного доступа" },
    "Restoring session…":   { uz: "Sessiya tiklanmoqda…", ru: "Восстановление сессии…" },
    "Username":             { uz: "Foydalanuvchi nomi",   ru: "Имя пользователя" },
    "Password":             { uz: "Parol",                ru: "Пароль" },
    "Sign In":              { uz: "Kirish",               ru: "Войти" },
    "Log Out":              { uz: "Chiqish",              ru: "Выход" },
    "Logout":               { uz: "Chiqish",              ru: "Выход" },

    "Security Dashboard":   { uz: "Xavfsizlik paneli",    ru: "Панель безопасности" },
    "Live Status":          { uz: "Jonli holat",          ru: "Живой статус" },
    "Total Emails Scanned": { uz: "Tekshirilgan xatlar",  ru: "Проверено писем" },
    "Suspicious Emails":    { uz: "Shubhali xatlar",      ru: "Подозрительные письма" },
    "Quarantined":          { uz: "Karantinda",           ru: "В карантине" },
    "Active Simulations":   { uz: "Faol simulyatsiyalar", ru: "Активные симуляции" },
    "Critical Activity":    { uz: "Muhim faoliyat",       ru: "Критическая активность" },
    "Threat Types Distribution": { uz: "Tahdid turlari taqsimoti", ru: "Распределение типов угроз" },
    "Recent Threats":       { uz: "So'nggi tahdidlar",    ru: "Недавние угрозы" },
    "View All":             { uz: "Hammasini ko'rish",    ru: "Показать все" },

    "Time":                 { uz: "Vaqt",                 ru: "Время" },
    "Timestamp":            { uz: "Vaqt belgisi",         ru: "Метка времени" },
    "Sender":               { uz: "Yuboruvchi",           ru: "Отправитель" },
    "Subject":              { uz: "Mavzu",                ru: "Тема" },
    "Sender / Subject":     { uz: "Yuboruvchi / Mavzu",   ru: "Отправитель / Тема" },
    "Status":               { uz: "Holat",                ru: "Статус" },
    "Actions":              { uz: "Amallar",              ru: "Действия" },
    "Action":               { uz: "Amal",                 ru: "Действие" },
    "Type":                 { uz: "Turi",                 ru: "Тип" },
    "Threat Type":          { uz: "Tahdid turi",          ru: "Тип угрозы" },
    "Threat Level":         { uz: "Tahdid darajasi",      ru: "Уровень угрозы" },
    "Threat Detail":        { uz: "Tahdid tafsiloti",     ru: "Детали угрозы" },
    "Severity":             { uz: "Jiddiylik",            ru: "Серьёзность" },
    "Risk":                 { uz: "Xavf",                 ru: "Риск" },
    "Risk Score":           { uz: "Xavf bahosi",          ru: "Оценка риска" },
    "Risk Assessment":      { uz: "Xavfni baholash",      ru: "Оценка риска" },
    "Risk Analytics":       { uz: "Xavf tahlili",         ru: "Аналитика риска" },
    "URL Threat":           { uz: "URL tahdidi",          ru: "Угроза URL" },
    "Confidence":           { uz: "Ishonch",              ru: "Уверенность" },
    "Verdict":              { uz: "Hukm",                 ru: "Вердикт" },
    "Source":               { uz: "Manba",                ru: "Источник" },
    "Value":                { uz: "Qiymat",               ru: "Значение" },
    "Name":                 { uz: "Nomi",                 ru: "Имя" },
    "Role":                 { uz: "Rol",                  ru: "Роль" },
    "User":                 { uz: "Foydalanuvchi",        ru: "Пользователь" },

    "Needs Review":         { uz: "Ko'rib chiqish kerak", ru: "Требует проверки" },
    "Safe":                 { uz: "Xavfsiz",              ru: "Безопасно" },
    "Suspicious":           { uz: "Shubhali",             ru: "Подозрительно" },
    "Malicious":            { uz: "Zararli",              ru: "Вредоносно" },

    "Release":              { uz: "Chiqarish",            ru: "Выпустить" },
    "Delete":               { uz: "O'chirish",            ru: "Удалить" },
    "Delete Permanently":   { uz: "Butunlay o'chirish",   ru: "Удалить навсегда" },
    "Review":               { uz: "Ko'rib chiqish",       ru: "Проверить" },
    "Respond":              { uz: "Javob berish",         ru: "Ответить" },
    "Revoke":               { uz: "Bekor qilish",         ru: "Отозвать" },
    "Mark Safe":            { uz: "Xavfsiz deb belgilash", ru: "Пометить безопасным" },
    "Confirm Phishing":     { uz: "Fishing deb tasdiqlash", ru: "Подтвердить фишинг" },
    "Save":                 { uz: "Saqlash",              ru: "Сохранить" },
    "Save Settings":        { uz: "Sozlamalarni saqlash", ru: "Сохранить настройки" },
    "Cancel":               { uz: "Bekor qilish",         ru: "Отмена" },
    "OK":                   { uz: "OK",                   ru: "ОК" },
    "Update Password":      { uz: "Parolni yangilash",    ru: "Обновить пароль" },

    "SOAR Playbooks":       { uz: "SOAR ssenariylari",    ru: "SOAR-плейбуки" },
    "SLA Breaches":         { uz: "SLA buzilishlari",     ru: "Нарушения SLA" },
    "SOC Timeline":         { uz: "SOC vaqt chizig'i",    ru: "Хронология SOC" },
    "Resolution Strategy":  { uz: "Hal qilish strategiyasi", ru: "Стратегия решения" },
    "Department Vulnerability": { uz: "Bo'lim zaifligi",  ru: "Уязвимость отдела" },
    "Target Department":    { uz: "Maqsadli bo'lim",      ru: "Целевой отдел" },
    "Target":               { uz: "Maqsad",               ru: "Цель" },
    "Sent":                 { uz: "Yuborilgan",           ru: "Отправлено" },
    "Opened":               { uz: "Ochilgan",             ru: "Открыто" },
    "Clicked":              { uz: "Bosilgan",             ru: "Переходов" },
    "Submitted":            { uz: "Yuborilgan ma'lumot",  ru: "Отправлено данных" },
    "Submitted Data":       { uz: "Yuborilgan ma'lumot",  ru: "Отправленные данные" },

    "AI Engine":            { uz: "AI dvigatel",          ru: "AI-движок" },
    "Email (IMAP)":         { uz: "Email (IMAP)",         ru: "Email (IMAP)" },
    "Integrations":         { uz: "Integratsiyalar",      ru: "Интеграции" },
    "Security":             { uz: "Xavfsizlik",           ru: "Безопасность" },
    "SIEM":                 { uz: "SIEM",                 ru: "SIEM" },
    "Rule":                 { uz: "Qoida",                ru: "Правило" },
    "Rules":                { uz: "Qoidalar",             ru: "Правила" },

    // UI alert / dialog chrome
    "Success":              { uz: "Muvaffaqiyat",         ru: "Успех" },
    "Error":                { uz: "Xato",                 ru: "Ошибка" },
    "Validation Error":     { uz: "Tekshiruv xatosi",     ru: "Ошибка проверки" },
    "Warning":              { uz: "Ogohlantirish",        ru: "Предупреждение" },
    "Confirm":              { uz: "Tasdiqlash",           ru: "Подтвердить" },
    "Notifications":        { uz: "Bildirishnomalar",     ru: "Уведомления" }
  };

  var LANGS = { uz: "O'zbek", ru: "Русский", en: "English" };
  var DEFAULT_LANG = "uz";
  var LANG = "en";                 // DOM currently shows English until applied
  var applying = false;
  var ATTRS = ["placeholder", "title", "aria-label"];
  var ORIG = new WeakMap();        // text node -> original English string

  function readLang() { try { return localStorage.getItem("te_lang") || ""; } catch (e) { return ""; } }
  function saveLang(l) { try { localStorage.setItem("te_lang", l); } catch (e) {} }

  function t(englishKey, lang) {
    if (lang === "en") return englishKey;
    var e = DICT[englishKey];
    return (e && e[lang]) ? e[lang] : englishKey;
  }

  function translateTextNode(node, lang) {
    var original = ORIG.has(node) ? ORIG.get(node) : node.nodeValue;
    var key = (original || "").trim();
    if (!key || !(key in DICT)) return;
    if (!ORIG.has(node)) ORIG.set(node, node.nodeValue);
    node.nodeValue = (original || "").replace(key, t(key, lang));
  }

  function translateAttr(el, attr, lang) {
    var dataKey = "i18nOrig" + attr.replace(/[^a-z]/gi, "");
    var original = el.dataset[dataKey] !== undefined ? el.dataset[dataKey] : el.getAttribute(attr);
    if (original == null) return;
    var key = original.trim();
    if (!(key in DICT)) return;
    if (el.dataset[dataKey] === undefined) el.dataset[dataKey] = original;
    el.setAttribute(attr, original.replace(key, t(key, lang)));
  }

  function walk(root, lang) {
    var tw = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
    var nodes = [], n;
    while ((n = tw.nextNode())) nodes.push(n);
    nodes.forEach(function (node) { translateTextNode(node, lang); });
    var els = root.querySelectorAll ? root.querySelectorAll("*") : [];
    for (var i = 0; i < els.length; i++) {
      for (var a = 0; a < ATTRS.length; a++) translateAttr(els[i], ATTRS[a], lang);
    }
  }

  function apply(lang) {
    applying = true;
    try { walk(document.body, lang); } finally { applying = false; }
    document.documentElement.lang = lang;
    LANG = lang;
    updateToggle();
  }

  function updateToggle() {
    var btn = document.getElementById("lang-toggle");
    if (btn) btn.textContent = (LANG || "en").toUpperCase();
  }

  function cycleLang() {
    var order = ["uz", "ru", "en"];
    var next = order[(order.indexOf(LANG) + 1) % order.length];
    saveLang(next); apply(next);
  }

  function injectToggle() {
    if (document.getElementById("lang-toggle")) return;
    var btn = document.createElement("button");
    btn.id = "lang-toggle";
    btn.type = "button";
    btn.title = "Til / Язык / Language";
    btn.className = "px-2 py-1 text-xs font-semibold rounded border border-cyber-border text-gray-300 hover:text-cyber-neon hover:border-cyber-neon/50 transition-colors";
    btn.style.cssText = "position:fixed;top:10px;right:14px;z-index:9999;background:#13131a;";
    btn.addEventListener("click", cycleLang);
    document.body.appendChild(btn);
    updateToggle();
  }

  function showSetupPicker() {
    return new Promise(function (resolve) {
      var ov = document.createElement("div");
      ov.style.cssText = "position:fixed;inset:0;z-index:10000;background:rgba(10,10,15,0.92);display:flex;align-items:center;justify-content:center;";
      ov.innerHTML =
        '<div style="background:#13131a;border:1px solid #1f1f2e;border-radius:14px;padding:28px 30px;max-width:360px;width:90%;text-align:center;font-family:Inter,sans-serif;">' +
          '<div style="font-size:20px;font-weight:700;color:#fff;margin-bottom:4px;">ThreatEye</div>' +
          '<div style="color:#8a8a9a;font-size:13px;margin-bottom:20px;">Tilni tanlang · Выберите язык · Choose language</div>' +
          '<div id="te-lang-opts" style="display:flex;flex-direction:column;gap:10px;"></div>' +
        '</div>';
      var opts = ov.querySelector("#te-lang-opts");
      Object.keys(LANGS).forEach(function (code) {
        var b = document.createElement("button");
        b.textContent = LANGS[code];
        b.style.cssText = "padding:11px;border-radius:9px;border:1px solid #1f1f2e;background:#0a0a0f;color:#e6e6ef;font-size:15px;font-weight:600;cursor:pointer;";
        b.onmouseenter = function () { b.style.borderColor = "#00ff9d"; b.style.color = "#00ff9d"; };
        b.onmouseleave = function () { b.style.borderColor = "#1f1f2e"; b.style.color = "#e6e6ef"; };
        b.onclick = function () { saveLang(code); document.body.removeChild(ov); resolve(code); };
        opts.appendChild(b);
      });
      document.body.appendChild(ov);
    });
  }

  function startObserver() {
    if (!("MutationObserver" in window)) return;
    var pending = false;
    new MutationObserver(function () {
      if (applying || LANG === "en") return;
      if (pending) return;
      pending = true;
      requestAnimationFrame(function () {
        pending = false;
        applying = true;
        try { walk(document.body, LANG); } finally { applying = false; }
      });
    }).observe(document.body, { childList: true, subtree: true });
  }

  function init() {
    injectToggle();
    startObserver();
    var saved = readLang();
    if (saved && LANGS[saved]) {
      apply(saved);
    } else {
      // First run → ask once, defaulting the experience to O'zbek.
      showSetupPicker().then(function (code) { apply(code || DEFAULT_LANG); });
    }
  }

  // Expose for the Settings screen / app code.
  window.ThreatEyeI18n = { apply: apply, get: function () { return LANG; }, langs: LANGS, t: t };

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
