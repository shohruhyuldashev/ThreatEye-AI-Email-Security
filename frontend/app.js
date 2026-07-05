// Navigation and SPA Logic
document.addEventListener('DOMContentLoaded', () => {
    const navButtons = document.querySelectorAll('.nav-btn');
    const viewContainer = document.getElementById('view-container');
    const loginOverlay = document.getElementById('login-overlay');
    const mainApp = document.getElementById('main-app-content');
    const loginForm = document.getElementById('login-form');
    const loginError = document.getElementById('login-error');
    let appInitialized = false;

    // Auth: the session lives in httpOnly JWT cookies (access + refresh). We keep the
    // CSRF token (returned by login/refresh) in memory to echo on mutating requests —
    // this cross-origin page can't read the backend's csrf_token cookie directly.
    let csrfToken = '';

    function showApp(authed) {
        if (authed) {
            loginOverlay.classList.add('opacity-0', 'pointer-events-none');
            setTimeout(() => {
                loginOverlay.classList.add('hidden');
                mainApp.classList.remove('opacity-0', 'pointer-events-none');
            }, 300);
        } else {
            loginOverlay.classList.remove('hidden', 'opacity-0', 'pointer-events-none');
            mainApp.classList.add('opacity-0', 'pointer-events-none');
        }
    }
    // Called on 401/logout to drop back to the login overlay.
    function checkAuth() { showApp(false); }

    async function bootstrapAuth() {
        try {
            let res = await fetch(`${API_BASE}/auth/me`, { credentials: 'include' });
            if (!res.ok) {
                const r = await fetch(`${API_BASE}/auth/refresh`, {
                    method: 'POST', credentials: 'include', headers: { 'X-CSRF-Token': csrfToken }
                });
                if (r.ok) { csrfToken = (await r.json()).csrf_token || csrfToken; res = await fetch(`${API_BASE}/auth/me`, { credentials: 'include' }); }
            }
            if (res.ok) { showApp(true); initializeApp(); return; }
        } catch (_) { /* fall through to login */ }
        showApp(false);
    }

    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const user = document.getElementById('login-username').value;
            const pass = document.getElementById('login-password').value;
            try {
                const res = await fetch(`${API_BASE}/auth/login`, {
                    method: 'POST',
                    credentials: 'include',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: user, password: pass })
                });
                if (res.ok) {
                    csrfToken = (await res.json()).csrf_token || '';
                    loginError.classList.add('hidden');
                    showApp(true);
                    initializeApp();
                } else {
                    loginError.classList.remove('hidden');
                }
            } catch (err) {
                loginError.classList.remove('hidden');
            }
        });
    }

    // Define the HTML content for each view
    const views = {
        dashboard: `
            <div class="view-section active" id="dashboard-view">
                <div class="flex justify-between items-center mb-6">
                    <h2 class="text-2xl font-bold text-white">Security Dashboard <span class="text-xs font-normal text-gray-400 ml-2">Live Status</span></h2>
                    <div class="text-sm text-gray-400">Last updated: Just now</div>
                </div>

                <!-- Stats Cards -->
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                    <!-- Total Emails -->
                    <div class="glass-card rounded-xl p-5 border-t-4 border-t-cyber-info relative overflow-hidden">
                        <div class="absolute -right-4 -top-4 w-16 h-16 bg-cyber-info/10 rounded-full blur-xl"></div>
                        <div class="flex justify-between items-start">
                            <div>
                                <p class="text-gray-400 text-sm font-medium mb-1">Total Emails Scanned</p>
                                <h3 class="text-3xl font-bold text-white">&mdash;</h3>
                            </div>
                            <div class="w-10 h-10 rounded-lg bg-cyber-info/20 flex items-center justify-center text-cyber-info">
                                <i class="fa-solid fa-envelope-open-text"></i>
                            </div>
                        </div>
                        <div class="mt-4 text-xs text-cyber-neon flex items-center"><i class="fa-solid fa-arrow-trend-up mr-1"></i> +1.2% from yesterday</div>
                    </div>
                    
                    <!-- Suspicious E-mails -->
                    <div class="glass-card rounded-xl p-5 border-t-4 border-t-cyber-warning relative overflow-hidden">
                        <div class="absolute -right-4 -top-4 w-16 h-16 bg-cyber-warning/10 rounded-full blur-xl"></div>
                        <div class="flex justify-between items-start">
                            <div>
                                <p class="text-gray-400 text-sm font-medium mb-1">Suspicious Emails</p>
                                <h3 class="text-3xl font-bold text-white">&mdash;</h3>
                            </div>
                            <div class="w-10 h-10 rounded-lg bg-cyber-warning/20 flex items-center justify-center text-cyber-warning">
                                <i class="fa-solid fa-triangle-exclamation"></i>
                            </div>
                        </div>
                        <div class="mt-4 text-xs text-cyber-warning flex items-center"><i class="fa-solid fa-arrow-right mr-1"></i> Under investigation</div>
                    </div>

                    <!-- Quarantined Emails -->
                    <div class="glass-card rounded-xl p-5 border-t-4 border-t-cyber-danger relative overflow-hidden">
                        <div class="absolute -right-4 -top-4 w-16 h-16 bg-cyber-danger/10 rounded-full blur-xl"></div>
                        <div class="flex justify-between items-start">
                            <div>
                                <p class="text-gray-400 text-sm font-medium mb-1">Quarantined Emails</p>
                                <h3 class="text-3xl font-bold text-white">&mdash;</h3>
                            </div>
                            <div class="w-10 h-10 rounded-lg bg-cyber-danger/20 flex items-center justify-center text-cyber-danger">
                                <i class="fa-solid fa-ban"></i>
                            </div>
                        </div>
                        <div class="mt-4 text-xs text-cyber-danger flex items-center"><i class="fa-solid fa-arrow-trend-up mr-1"></i> Action Required</div>
                    </div>

                    <!-- Active Simulations -->
                    <div class="glass-card rounded-xl p-5 border-t-4 border-t-cyber-neon relative overflow-hidden">
                        <div class="absolute -right-4 -top-4 w-16 h-16 bg-cyber-neon/10 rounded-full blur-xl"></div>
                        <div class="flex justify-between items-start">
                            <div>
                                <p class="text-gray-400 text-sm font-medium mb-1">Active Simulations</p>
                                <h3 class="text-3xl font-bold text-white">&mdash;</h3>
                            </div>
                            <div class="w-10 h-10 rounded-lg bg-cyber-neon/20 flex items-center justify-center text-cyber-neon">
                                <i class="fa-solid fa-vial-virus"></i>
                            </div>
                        </div>
                        <div class="mt-4 text-xs text-cyber-neon flex items-center"><i class="fa-solid fa-check mr-1"></i> Running normally</div>
                    </div>
                </div>

                <!-- Charts & Gauges Area -->
                <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
                    <!-- Gauge -->
                    <div class="glass-card rounded-xl p-6 flex flex-col items-center justify-center lg:col-span-1">
                        <h3 class="text-lg font-semibold text-white mb-4 w-full text-left">Current Risk Level</h3>
                        <div class="relative w-48 h-48">
                            <canvas id="riskGauge"></canvas>
                            <div class="absolute inset-0 flex flex-col items-center justify-center pt-8">
                                <span class="text-4xl font-bold text-cyber-danger">72</span>
                                <span class="text-xs text-gray-400">/100</span>
                            </div>
                        </div>
                        <p class="mt-4 text-sm text-center text-gray-400">High volume of phishing attempts detected targeting Sales department.</p>
                    </div>

                    <!-- Trend Chart -->
                    <div class="glass-card rounded-xl p-6 lg:col-span-2">
                        <div class="flex justify-between items-center mb-4 border-b border-cyber-border/50 pb-2">
                            <div class="flex items-center space-x-3">
                                <h3 id="dashboard-trend-title" class="text-lg font-semibold text-white">7-Day Threat Trend</h3>
                                <span id="dashboard-critical-badge" class="bg-cyber-danger/20 text-cyber-danger text-[10px] px-2 py-0.5 rounded font-bold uppercase tracking-wider hidden">Critical Activity</span>
                            </div>
                            <select id="dashboard-trend-range" class="bg-cyber-dark border border-cyber-border text-xs rounded px-2 py-1 outline-none text-gray-300 focus:border-cyber-neon cursor-pointer">
                                <option value="7">7-Day</option>
                                <option value="30">1 Month</option>
                                <option value="90">3 Months</option>
                                <option value="365">1 Year</option>
                            </select>
                        </div>
                        <div class="h-64 w-full relative pt-2">
                            <canvas id="trendChart"></canvas>
                        </div>
                    </div>
                </div>

                <!-- Recent Threats Table -->
                <div class="glass-card rounded-xl p-6">
                    <div class="flex justify-between items-center mb-6">
                        <h3 class="text-lg font-semibold text-white">Recent Threats Detected</h3>
                        <a href="#" data-target="monitoring" class="nav-btn text-xs text-cyber-neon hover:underline">View All <i class="fa-solid fa-arrow-right ml-1"></i></a>
                    </div>
                    
                    <div class="overflow-x-auto">
                        <table class="w-full text-left border-collapse">
                            <thead>
                                <tr class="text-xs text-gray-400 uppercase tracking-wider border-b border-cyber-border/80">
                                    <th class="pb-3 px-4 font-medium">Time</th>
                                    <th class="pb-3 px-4 font-medium">Subject</th>
                                    <th class="pb-3 px-4 font-medium">Sender</th>
                                    <th class="pb-3 px-4 font-medium">Risk Score</th>
                                    <th class="pb-3 px-4 font-medium">Action Taken</th>
                                </tr>
                            </thead>
                            <tbody class="text-sm" id="dashboard-recent-table">
                                <!-- JS injected rows -->
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        `,
        monitoring: `
            <div class="view-section" id="monitoring-view">
                <div class="flex justify-between items-center mb-6">
                    <div>
                        <h2 class="text-2xl font-bold text-white flex items-center">Real-Time Monitor <span class="flex h-3 w-3 relative ml-3"><span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyber-neon opacity-75"></span><span class="relative inline-flex rounded-full h-3 w-3 bg-cyber-neon"></span></span></h2>
                        <p class="text-sm text-gray-400 mt-1">Live analysis of all incoming corporate emails.</p>
                    </div>
                    <div class="flex space-x-3">
                        <div class="relative">
                            <i class="fa-solid fa-search absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-500 text-sm"></i>
                            <input type="text" id="monitor-search" placeholder="Search sender, subject..." class="cyber-input rounded-lg pl-9 pr-4 py-2 text-sm w-64">
                        </div>
                        <select id="monitor-risk-filter" class="cyber-input rounded-lg px-4 py-2 text-sm bg-cyber-dark">
                            <option value="all">All Risk Levels</option>
                            <option value="high">High Risk (>70%)</option>
                            <option value="medium">Medium Risk (30-70%)</option>
                            <option value="low">Low Risk (<30%)</option>
                        </select>
                    </div>
                </div>

                <div class="grid grid-cols-1 xl:grid-cols-3 gap-6">
                    <!-- Data Table -->
                    <div class="xl:col-span-2 glass-card rounded-xl overflow-hidden border border-cyber-border">
                        <div class="overflow-x-auto max-h-[calc(100vh-15rem)] custom-scrollbar">
                            <table class="w-full text-left">
                                <thead class="bg-cyber-dark/50 text-xs text-gray-400 uppercase tracking-wider sticky top-0 z-10 backdrop-blur-md">
                                    <tr>
                                        <th class="py-4 px-6 font-medium">Timestamp</th>
                                        <th class="py-4 px-6 font-medium">Sender</th>
                                        <th class="py-4 px-6 font-medium">Subject</th>
                                        <th class="py-4 px-6 font-medium">URL Threat</th>
                                        <th class="py-4 px-6 font-medium">Overall Risk</th>
                                        <th class="py-4 px-6 font-medium">Status</th>
                                        <th class="py-4 px-6 font-medium"></th>
                                    </tr>
                                </thead>
                                <tbody class="text-sm divide-y divide-cyber-border/50" id="monitor-table-body">
                                    <!-- Items injected via JS -->
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <!-- Detail View (Sidebar) -->
                    <div class="glass-card rounded-xl border border-cyber-border p-5 flex flex-col max-h-[calc(100vh-15rem)] xl:sticky xl:top-6">
                        <h3 class="font-medium text-white mb-4 border-b border-cyber-border/50 pb-2 flex justify-between items-center">
                            <span>Threat Detail</span>
                            <span class="text-xs font-normal text-gray-500 bg-cyber-dark px-2 py-1 rounded">Select a row</span>
                        </h3>
                        <div class="flex-1 overflow-y-auto pr-2 custom-scrollbar space-y-4" id="monitor-detail-content">
                            <div class="h-full flex flex-col items-center justify-center text-gray-500 space-y-4">
                                <i class="fa-solid fa-envelope-open-text text-4xl opacity-50"></i>
                                <p class="text-sm text-center">Click on any email in the monitoring table to view its full AI analysis and headers.</p>
                            </div>
                        </div>
                        <div class="mt-4 pt-4 border-t border-cyber-border space-y-2 hidden" id="monitor-detail-actions">
                            <button class="w-full py-2 bg-cyber-danger/80 hover:bg-cyber-danger text-white rounded font-medium transition-colors shadow-lg shadow-cyber-danger/20">Delete Permanently</button>
                            <button class="w-full py-2 bg-transparent border border-cyber-border text-gray-400 hover:text-white hover:border-gray-500 rounded font-medium transition-colors">Release to Inbox (Admin)</button>
                        </div>
                    </div>
                </div>
            </div>
        `,
        quarantine: `
            <div class="view-section" id="quarantine-view">
                <div class="flex justify-between items-center mb-6">
                    <div>
                        <h2 class="text-2xl font-bold text-cyber-danger flex items-center">Quarantine Manager</h2>
                        <p class="text-sm text-gray-400 mt-1">Review and manage isolated threats to protect the network.</p>
                    </div>
                    <button onclick="emptyQuarantine()" id="empty-quarantine-btn" class="bg-cyber-danger/10 hover:bg-cyber-danger/20 text-cyber-danger border border-cyber-danger/50 px-4 py-2 rounded-lg text-sm font-medium transition-colors">
                        <i class="fa-solid fa-trash mr-2"></i> Empty Quarantine
                    </button>
                </div>

                <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    <!-- List -->
                    <div class="lg:col-span-2 glass-card rounded-xl border border-cyber-border overflow-hidden">
                        <div class="p-4 border-b border-cyber-border/50 bg-cyber-dark/30">
                            <h3 class="font-medium text-white">Isolated Items (47)</h3>
                        </div>
                        <div class="max-h-[calc(100vh-16rem)] overflow-y-auto custom-scrollbar">
                            <table class="w-full text-left">
                                <thead class="text-xs text-gray-500 uppercase bg-cyber-dark/80 sticky top-0 z-10 backdrop-blur-md">
                                    <tr>
                                        <th class="p-4 font-medium">Recipient</th>
                                        <th class="p-4 font-medium">Threat Level</th>
                                        <th class="p-4 font-medium">AI Reason</th>
                                        <th class="p-4 font-medium text-right">Actions</th>
                                    </tr>
                                </thead>
                                <tbody class="text-sm divide-y divide-cyber-border/50">
                                    <!-- JS Injected rows -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                    
                    <!-- Detail View -->
                    <div class="glass-card rounded-xl border border-cyber-border p-5 flex flex-col max-h-[calc(100vh-16rem)] overflow-y-auto custom-scrollbar xl:sticky xl:top-6">
                        <h3 class="font-medium text-white mb-4 border-b border-cyber-border/50 pb-2">Threat Detail</h3>
                        <div class="flex-1 flex flex-col items-center justify-center text-gray-500 space-y-4 py-10">
                            <i class="fa-solid fa-shield-halved text-4xl opacity-40"></i>
                            <p class="text-sm text-center">Select an item to view its full AI analysis and headers.</p>
                        </div>
                    </div>
                </div>
            </div>
        `,
        simulation: `
            <div class="view-section" id="simulation-view">
                <div class="flex justify-between items-center mb-6">
                    <div>
                        <h2 class="text-2xl font-bold text-white">Phishing Simulation</h2>
                        <p class="text-sm text-gray-400 mt-1">Upload employees, launch AI or manual GoPhish campaigns, and track who clicks — by department.</p>
                    </div>
                    <span id="sim-gophish-status" class="text-xs px-3 py-1.5 rounded-full border border-cyber-border text-gray-400">GoPhish: checking…</span>
                </div>

                <!-- Results (top KPI row) -->
                <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8" id="sim-result-tiles">
                    <div class="glass-card rounded-xl p-5"><p class="text-xs text-gray-400 uppercase tracking-widest mb-1">Emails Sent</p><h3 class="text-3xl font-bold text-white" id="sr-sent">—</h3></div>
                    <div class="glass-card rounded-xl p-5"><p class="text-xs text-gray-400 uppercase tracking-widest mb-1">Opened</p><h3 class="text-3xl font-bold text-cyber-info" id="sr-opened">—</h3></div>
                    <div class="glass-card rounded-xl p-5"><p class="text-xs text-gray-400 uppercase tracking-widest mb-1">Clicked</p><h3 class="text-3xl font-bold text-cyber-warning" id="sr-clicked">—</h3></div>
                    <div class="glass-card rounded-xl p-5"><p class="text-xs text-gray-400 uppercase tracking-widest mb-1">Submitted Data</p><h3 class="text-3xl font-bold text-cyber-danger" id="sr-submitted">—</h3></div>
                </div>

                <div class="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
                    <!-- Launch panel -->
                    <div class="glass-card rounded-xl p-6">
                        <div class="flex bg-cyber-dark rounded-lg p-1 mb-6">
                            <button type="button" id="sim-mode-ai" class="flex-1 py-1.5 text-sm font-medium rounded-md bg-cyber-neon/20 text-cyber-neon transition-colors" onclick="switchSimMode('AI')">AI Automated</button>
                            <button type="button" id="sim-mode-manual" class="flex-1 py-1.5 text-sm font-medium rounded-md text-gray-400 hover:text-white transition-colors" onclick="switchSimMode('Manual')">Manual</button>
                        </div>

                        <div class="space-y-5">
                            <div>
                                <label class="block text-xs text-gray-400 uppercase tracking-widest mb-1">Target Department</label>
                                <select id="sim-department" class="cyber-input w-full rounded-lg px-4 py-2 text-sm text-gray-300">
                                    <option value="">All departments (whole roster)</option>
                                </select>
                            </div>
                            <div id="sim-ai-settings" class="space-y-5">
                                <div>
                                    <label class="block text-xs text-gray-400 uppercase tracking-widest mb-1">Targets CSV (optional — else uses roster/department)</label>
                                    <input type="file" id="sim-ai-file" accept=".txt,.csv" class="cyber-input w-full rounded-lg px-4 py-2 text-sm text-gray-300 file:mr-3 file:py-1.5 file:px-3 file:rounded file:border-0 file:text-xs file:font-semibold file:bg-cyber-neon/20 file:text-cyber-neon cursor-pointer">
                                    <p class="text-[11px] text-gray-500 mt-1">Uploaded employees are also saved to the roster and get an AI-crafted lure.</p>
                                </div>
                                <div>
                                    <label class="block text-xs text-gray-400 uppercase tracking-widest mb-1">Random sample size (optional)</label>
                                    <input type="number" id="sim-sample" min="0" placeholder="0 = everyone" class="cyber-input w-full rounded-lg px-4 py-2 text-sm text-gray-300">
                                </div>
                                <div>
                                    <label class="block text-xs text-gray-400 uppercase tracking-widest mb-1">Lure theme / context (optional)</label>
                                    <input type="text" id="sim-theme" placeholder="e.g. Payroll update, VPN reset…" class="cyber-input w-full rounded-lg px-4 py-2 text-sm text-gray-300">
                                </div>
                            </div>
                            <div id="sim-manual-settings" class="hidden space-y-5">
                                <div>
                                    <label class="block text-xs text-gray-400 uppercase tracking-widest mb-1">Targets CSV (optional — else uses roster)</label>
                                    <input type="file" id="sim-file" accept=".txt,.csv" class="cyber-input w-full rounded-lg px-4 py-2 text-sm text-gray-300 file:mr-3 file:py-1.5 file:px-3 file:rounded file:border-0 file:text-xs file:font-semibold file:bg-cyber-neon/20 file:text-cyber-neon cursor-pointer">
                                </div>
                            </div>
                            <button type="button" id="sim-launch-btn" onclick="triggerSimulation()" class="w-full py-2.5 bg-cyber-neon text-black font-bold rounded-lg hover:bg-[#00cc7a] transition-colors">
                                <i class="fa-solid fa-paper-plane mr-1"></i> Launch Campaign
                            </button>
                            <div class="flex items-center justify-between pt-3 border-t border-cyber-border">
                                <div>
                                    <p class="text-sm text-white font-medium">Automated scheduled campaigns</p>
                                    <p class="text-xs text-gray-500">AI sends to the roster every 24h when enabled</p>
                                </div>
                                <label class="inline-flex items-center cursor-pointer">
                                    <input type="checkbox" id="sim-auto-toggle" class="sr-only peer">
                                    <div class="relative w-11 h-6 bg-cyber-dark border border-cyber-border peer-checked:bg-cyber-neon/30 peer-checked:border-cyber-neon rounded-full peer transition-colors after:content-[''] after:absolute after:top-0.5 after:left-0.5 after:bg-gray-400 peer-checked:after:bg-cyber-neon after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:after:translate-x-5"></div>
                                </label>
                            </div>
                        </div>
                    </div>

                    <!-- Roster panel -->
                    <div class="glass-card rounded-xl p-6">
                        <h3 class="text-lg font-semibold text-white mb-1"><i class="fa-solid fa-address-book mr-2 text-cyber-info"></i> Employee Roster</h3>
                        <p class="text-xs text-gray-500 mb-4">CSV columns: <code class="text-cyber-neon">email, first_name, last_name, department</code> (a plain email-per-line list also works).</p>
                        <form id="roster-upload-form" class="flex gap-3 mb-4">
                            <input type="file" id="roster-file" accept=".txt,.csv" required class="cyber-input flex-1 rounded-lg px-3 py-2 text-sm text-gray-300 file:mr-3 file:py-1.5 file:px-3 file:rounded file:border-0 file:text-xs file:font-semibold file:bg-cyber-info/20 file:text-cyber-info cursor-pointer">
                            <button type="submit" class="py-2 px-4 bg-cyber-info/10 border border-cyber-info text-cyber-info hover:bg-cyber-info/20 rounded-lg text-sm font-medium whitespace-nowrap">Import</button>
                        </form>
                        <div id="roster-summary" class="text-sm text-gray-400">Loading roster…</div>
                    </div>
                </div>

                <div class="grid grid-cols-1 xl:grid-cols-2 gap-8 mb-8">
                    <div class="glass-card rounded-xl p-6">
                        <h3 class="text-lg font-semibold text-white mb-4">Department Vulnerability</h3>
                        <div class="overflow-x-auto">
                            <table class="w-full text-sm">
                                <thead class="text-xs text-gray-500 uppercase tracking-wider border-b border-cyber-border">
                                    <tr><th class="text-left py-2">Department</th><th class="text-left py-2">Sent</th><th class="text-left py-2">Opened</th><th class="text-left py-2">Clicked</th><th class="text-left py-2">Submitted</th><th class="text-left py-2">Click%</th></tr>
                                </thead>
                                <tbody id="sim-dept-table"></tbody>
                            </table>
                        </div>
                    </div>
                    <div class="glass-card rounded-xl p-6">
                        <h3 class="text-lg font-semibold text-white mb-4">Employees Who Clicked</h3>
                        <div class="overflow-y-auto max-h-72 custom-scrollbar" id="sim-caught-list"></div>
                    </div>
                </div>

                <div class="glass-card rounded-xl p-6">
                    <h3 class="text-lg font-semibold text-white mb-4">Campaign History</h3>
                    <div class="overflow-x-auto">
                        <table class="w-full text-sm">
                            <thead class="text-xs text-gray-500 uppercase tracking-wider border-b border-cyber-border">
                                <tr><th class="text-left py-2">Campaign</th><th class="text-left py-2">Status</th><th class="text-left py-2">Sent</th><th class="text-left py-2">Click Rate</th></tr>
                            </thead>
                            <tbody id="sim-history-table"></tbody>
                        </table>
                    </div>
                </div>
            </div>
        `,
        urlanalyzer: `
            <div class="view-section" id="urlanalyzer-view">
                 <div class="max-w-4xl mx-auto mt-10 text-center">
                    <i class="fa-solid fa-link text-4xl text-cyber-neon mb-4"></i>
                    <h2 class="text-3xl font-bold text-white mb-2">Deep URL Threat Analyzer</h2>
                    <p class="text-gray-400 mb-6">Scan any URL for typosquatting, hidden redirections, and known malicious domains using the AI Engine.</p>
                    
                    <!-- URL Mode Selector Tabs -->
                    <div class="flex max-w-sm mx-auto bg-cyber-dark rounded-lg p-1 mb-8">
                        <button type="button" id="url-mode-ai" class="flex-1 py-1.5 text-sm font-medium rounded-md bg-cyber-neon/20 text-cyber-neon transition-colors" onclick="switchUrlMode('AI')">AI Analyzer</button>
                        <button type="button" id="url-mode-os" class="flex-1 py-1.5 text-sm font-medium rounded-md text-gray-400 hover:text-white transition-colors" onclick="switchUrlMode('OpenSource')">OpenSource</button>
                    </div>

                    <div class="relative max-w-2xl mx-auto flex mb-12">
                        <div class="absolute inset-y-0 left-0 flex items-center pl-4 pointer-events-none">
                            <i class="fa-solid fa-globe text-gray-500 text-lg"></i>
                        </div>
                        <input type="text" placeholder="https://example-login.com/auth..." class="cyber-input w-full rounded-l-xl pl-12 pr-4 py-4 text-lg focus:shadow-[0_0_20px_rgba(0,255,157,0.2)]">
                        <button id="url-scan-btn" class="bg-cyber-neon text-black font-bold px-8 py-4 rounded-r-xl hover:bg-[#00cc7a] transition-colors whitespace-nowrap">
                            Scan URL
                        </button>
                    </div>

                    <!-- Scan Results (Dynamic) -->
                    <div id="url-scan-result-card" class="glass-card rounded-xl text-left border-t-4 overflow-hidden text-sm" style="display: none;">
                        <div class="bg-cyber-dark/50 p-4 border-b border-cyber-border flex justify-between items-center">
                            <span class="font-mono text-gray-300" id="url-scan-result-text"></span>
                            <span id="url-scan-badge" class="px-3 py-1 rounded-full font-bold"></span>
                        </div>
                        <div class="p-6 grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div>
                                <h4 id="url-scan-findings-title" class="text-white font-medium mb-3 border-b border-cyber-border pb-1">Findings</h4>
                                <ul id="url-scan-findings-list" class="space-y-2 text-gray-400">
                                </ul>
                            </div>
                            <div id="url-scan-resolution-div">
                                <h4 class="text-white font-medium mb-3 border-b border-cyber-border pb-1">Resolution Strategy</h4>
                                <p id="url-scan-resolution-desc" class="text-gray-400 mb-2"></p>
                                <div id="url-scan-resolution-action"></div>
                            </div>
                        </div>
                    </div>
                 </div>
            </div>
        `,
        analytics: `
            <div class="view-section" id="analytics-view">
                <div class="flex justify-between items-center mb-6">
                    <h2 class="text-2xl font-bold text-white">Risk Analytics</h2>
                    <button id="download-report-btn" class="px-4 py-2 bg-cyber-neon/10 border border-cyber-neon text-cyber-neon hover:bg-cyber-neon/20 rounded-lg flex items-center transition-all">
                        <i class="fa-solid fa-file-pdf mr-2"></i> Export PDF Intelligence
                    </button>
                </div>
                
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <!-- Pie Chart -->
                    <div class="glass-card rounded-xl p-6 flex flex-col items-center">
                        <h3 class="text-lg font-semibold text-white mb-4 w-full text-left">Threat Types Distribution</h3>
                        <div class="relative w-64 h-64">
                            <canvas id="threatPieChart"></canvas>
                        </div>
                    </div>

                    <!-- Department Heatmap / Table -->
                    <div class="glass-card rounded-xl p-6">
                        <h3 class="text-lg font-semibold text-white mb-4">Department Vulnerability</h3>
                        <div class="space-y-4" id="analytics-dept-list">
                            <!-- JS Injected rows -->
                        </div>
                    </div>
                </div>
            </div>
        `,
        framework: `
            <div class="view-section" id="framework-view">
                <div class="flex justify-between items-center mb-6">
                    <div>
                        <h2 class="text-2xl font-bold text-white">Framework Center</h2>
                        <p class="text-sm text-gray-400 mt-1">Policy engine, cases, audit trail, and platform modules.</p>
                    </div>
                    <button id="refresh-framework-btn" class="px-4 py-2 bg-cyber-neon/10 border border-cyber-neon text-cyber-neon hover:bg-cyber-neon/20 rounded-lg text-sm">
                        <i class="fa-solid fa-rotate mr-2"></i>Refresh
                    </button>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-3 xl:grid-cols-9 gap-4 mb-6" id="framework-status-cards">
                    <div class="glass-card rounded-xl p-4"><div class="text-xs text-gray-500 uppercase">Policies</div><div class="text-2xl text-white font-bold" data-fw-count="policies">0</div></div>
                    <div class="glass-card rounded-xl p-4"><div class="text-xs text-gray-500 uppercase">Cases</div><div class="text-2xl text-white font-bold" data-fw-count="cases">0</div></div>
                    <div class="glass-card rounded-xl p-4"><div class="text-xs text-gray-500 uppercase">Audit Events</div><div class="text-2xl text-white font-bold" data-fw-count="audit_log">0</div></div>
                    <div class="glass-card rounded-xl p-4"><div class="text-xs text-gray-500 uppercase">Domain Cache</div><div class="text-2xl text-white font-bold" data-fw-count="domain_intel_cache">0</div></div>
                    <div class="glass-card rounded-xl p-4"><div class="text-xs text-gray-500 uppercase">Attachments</div><div class="text-2xl text-white font-bold" data-fw-count="attachments">0</div></div>
                    <div class="glass-card rounded-xl p-4"><div class="text-xs text-gray-500 uppercase">IOCs</div><div class="text-2xl text-white font-bold" data-fw-count="iocs">0</div></div>
                    <div class="glass-card rounded-xl p-4"><div class="text-xs text-gray-500 uppercase">SIEM</div><div class="text-2xl text-white font-bold" data-fw-count="siem_events">0</div></div>
                    <div class="glass-card rounded-xl p-4"><div class="text-xs text-gray-500 uppercase">Playbooks</div><div class="text-2xl text-white font-bold" data-fw-count="playbooks">0</div></div>
                    <div class="glass-card rounded-xl p-4"><div class="text-xs text-gray-500 uppercase">Rules</div><div class="text-2xl text-white font-bold" data-fw-count="detection_rules">0</div></div>
                </div>

                <div class="grid grid-cols-1 xl:grid-cols-2 gap-6">
                    <div class="glass-card rounded-xl p-6">
                        <div class="flex justify-between items-center mb-4">
                            <h3 class="text-lg font-semibold text-white">Policy Engine</h3>
                            <span class="text-xs text-cyber-neon">Plugin-ready</span>
                        </div>
                        <div class="overflow-x-auto">
                            <table class="w-full text-left text-sm">
                                <thead class="text-xs text-gray-500 uppercase border-b border-cyber-border">
                                    <tr><th class="py-2">Name</th><th class="py-2">Action</th><th class="py-2">Severity</th><th class="py-2">Enabled</th></tr>
                                </thead>
                                <tbody id="framework-policies-table"></tbody>
                            </table>
                        </div>
                    </div>

                    <div class="glass-card rounded-xl p-6">
                        <h3 class="text-lg font-semibold text-white mb-4">Case Management</h3>
                        <div class="overflow-x-auto">
                            <table class="w-full text-left text-sm">
                                <thead class="text-xs text-gray-500 uppercase border-b border-cyber-border">
                                    <tr><th class="py-2">Case</th><th class="py-2">Severity</th><th class="py-2">Status</th><th class="py-2">Risk</th></tr>
                                </thead>
                                <tbody id="framework-cases-table"></tbody>
                            </table>
                        </div>
                    </div>

                    <div class="glass-card rounded-xl p-6 xl:col-span-2">
                        <h3 class="text-lg font-semibold text-white mb-4">Audit Log</h3>
                        <div class="overflow-x-auto max-h-80 custom-scrollbar">
                            <table class="w-full text-left text-sm">
                                <thead class="text-xs text-gray-500 uppercase border-b border-cyber-border sticky top-0 bg-cyber-panel">
                                    <tr><th class="py-2">Time</th><th class="py-2">Actor</th><th class="py-2">Action</th><th class="py-2">Target</th><th class="py-2">Details</th></tr>
                                </thead>
                                <tbody id="framework-audit-table"></tbody>
                            </table>
                        </div>
                    </div>

                    <div class="glass-card rounded-xl p-6">
                        <h3 class="text-lg font-semibold text-white mb-4">Recent IOCs</h3>
                        <div class="overflow-x-auto max-h-80 custom-scrollbar">
                            <table class="w-full text-left text-sm">
                                <thead class="text-xs text-gray-500 uppercase border-b border-cyber-border"><tr><th class="py-2">Type</th><th class="py-2">Value</th><th class="py-2">Confidence</th></tr></thead>
                                <tbody id="framework-iocs-table"></tbody>
                            </table>
                        </div>
                    </div>

                    <div class="glass-card rounded-xl p-6">
                        <h3 class="text-lg font-semibold text-white mb-4">Detection-as-Code Rules</h3>
                        <div class="overflow-x-auto max-h-80 custom-scrollbar">
                            <table class="w-full text-left text-sm">
                                <thead class="text-xs text-gray-500 uppercase border-b border-cyber-border"><tr><th class="py-2">Rule</th><th class="py-2">Severity</th><th class="py-2">Enabled</th></tr></thead>
                                <tbody id="framework-rules-table"></tbody>
                            </table>
                        </div>
                    </div>

                    <div class="glass-card rounded-xl p-6 xl:col-span-2">
                        <h3 class="text-lg font-semibold text-white mb-4">SOAR Playbooks</h3>
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-3" id="framework-playbooks-list"></div>
                    </div>
                </div>
            </div>
        `,
        soc: `
            <div class="view-section" id="soc-view">
                <div class="flex justify-between items-center mb-6">
                    <h2 class="text-2xl font-bold text-white">SOC Center <span class="text-xs font-normal text-gray-400 ml-2">Triage · SLA · Intel · ATT&amp;CK</span></h2>
                    <button id="soc-refresh" class="text-xs text-gray-400 hover:text-cyber-neon border border-cyber-border rounded px-3 py-1.5"><i class="fa-solid fa-rotate mr-1"></i> Refresh</button>
                </div>
                <!-- Metric tiles -->
                <div class="grid grid-cols-2 lg:grid-cols-5 gap-4 mb-8" id="soc-metrics">
                    <div class="glass-card rounded-xl p-4"><p class="text-xs text-gray-400 mb-1">Open Cases</p><h3 class="text-2xl font-bold text-white" id="m-open">&mdash;</h3></div>
                    <div class="glass-card rounded-xl p-4"><p class="text-xs text-gray-400 mb-1">SLA Breaches</p><h3 class="text-2xl font-bold text-cyber-danger" id="m-sla">&mdash;</h3></div>
                    <div class="glass-card rounded-xl p-4"><p class="text-xs text-gray-400 mb-1">MTTD (min)</p><h3 class="text-2xl font-bold text-white" id="m-mttd">&mdash;</h3></div>
                    <div class="glass-card rounded-xl p-4"><p class="text-xs text-gray-400 mb-1">MTTR (min)</p><h3 class="text-2xl font-bold text-white" id="m-mttr">&mdash;</h3></div>
                    <div class="glass-card rounded-xl p-4"><p class="text-xs text-gray-400 mb-1">ATT&amp;CK Coverage</p><h3 class="text-2xl font-bold text-cyber-neon" id="m-cov">&mdash;</h3></div>
                </div>
                <div class="grid grid-cols-1 xl:grid-cols-3 gap-8">
                    <!-- Triage queue -->
                    <div class="glass-card rounded-xl p-6 xl:col-span-2">
                        <h3 class="text-lg font-semibold text-white mb-4"><i class="fa-solid fa-list-check mr-2 text-cyber-info"></i> Triage Queue</h3>
                        <div class="overflow-x-auto">
                            <table class="w-full text-sm">
                                <thead class="text-xs text-gray-500 uppercase tracking-wider border-b border-cyber-border">
                                    <tr><th class="text-left py-2">Pri</th><th class="text-left py-2">Sender / Subject</th><th class="text-left py-2">Risk</th><th class="text-left py-2">Type</th><th class="text-right py-2">Respond</th></tr>
                                </thead>
                                <tbody id="triage-table-body"></tbody>
                            </table>
                        </div>
                    </div>
                    <!-- ATT&CK coverage -->
                    <div class="glass-card rounded-xl p-6">
                        <h3 class="text-lg font-semibold text-white mb-4"><i class="fa-solid fa-shield-halved mr-2 text-cyber-neon"></i> ATT&amp;CK Coverage</h3>
                        <div id="attack-coverage" class="space-y-3"></div>
                    </div>
                    <!-- Threat intel -->
                    <div class="glass-card rounded-xl p-6 xl:col-span-3">
                        <h3 class="text-lg font-semibold text-white mb-4"><i class="fa-solid fa-diagram-project mr-2 text-cyber-warning"></i> Threat Intelligence (Blocklist / Allowlist)</h3>
                        <form id="add-intel-form" class="grid grid-cols-2 md:grid-cols-5 gap-3 mb-4">
                            <select id="intel-type" class="cyber-input p-2 rounded text-sm">
                                <option value="domain">domain</option><option value="url">url</option><option value="ip">ip</option><option value="email">email</option><option value="sha256">sha256</option>
                            </select>
                            <input type="text" id="intel-value" class="cyber-input p-2 rounded text-sm md:col-span-2" placeholder="indicator value" required>
                            <select id="intel-verdict" class="cyber-input p-2 rounded text-sm">
                                <option value="block">block</option><option value="suspicious">suspicious</option><option value="allow">allow</option>
                            </select>
                            <button type="submit" class="py-2 bg-cyber-warning/10 border border-cyber-warning text-cyber-warning hover:bg-cyber-warning/20 rounded text-sm font-medium">Add</button>
                        </form>
                        <div class="overflow-x-auto">
                            <table class="w-full text-sm">
                                <thead class="text-xs text-gray-500 uppercase tracking-wider border-b border-cyber-border">
                                    <tr><th class="text-left py-2">Type</th><th class="text-left py-2">Value</th><th class="text-left py-2">Verdict</th><th class="text-left py-2">Hits</th><th class="text-left py-2">Source</th><th class="text-right py-2">Actions</th></tr>
                                </thead>
                                <tbody id="intel-table-body"></tbody>
                            </table>
                        </div>
                    </div>
                    <!-- AI SOC Copilot -->
                    <div class="glass-card rounded-xl p-6 xl:col-span-2">
                        <h3 class="text-lg font-semibold text-white mb-1"><i class="fa-solid fa-robot mr-2 text-cyber-neon"></i> AI SOC Copilot</h3>
                        <p class="text-xs text-gray-500 mb-4">Ask about your detections — grounded in this tenant's data. e.g. "show high-risk emails from microsoft this week".</p>
                        <div id="copilot-log" class="space-y-3 mb-4 max-h-60 overflow-y-auto custom-scrollbar text-sm"></div>
                        <form id="copilot-form" class="flex gap-3">
                            <input type="text" id="copilot-input" placeholder="Ask the SOC copilot…" class="cyber-input flex-1 rounded-lg px-4 py-2 text-sm text-gray-300">
                            <button type="submit" class="py-2 px-4 bg-cyber-neon/10 border border-cyber-neon text-cyber-neon hover:bg-cyber-neon/20 rounded-lg text-sm font-medium">Ask</button>
                        </form>
                    </div>
                    <!-- Campaign clusters -->
                    <div class="glass-card rounded-xl p-6">
                        <h3 class="text-lg font-semibold text-white mb-4"><i class="fa-solid fa-object-group mr-2 text-cyber-warning"></i> Campaign Clusters</h3>
                        <div id="clusters-list" class="space-y-2 max-h-72 overflow-y-auto custom-scrollbar"></div>
                    </div>
                    <!-- Adaptive learning -->
                    <div class="glass-card rounded-xl p-6 xl:col-span-3">
                        <div class="flex justify-between items-center mb-4">
                            <h3 class="text-lg font-semibold text-white"><i class="fa-solid fa-brain mr-2 text-cyber-neon"></i> Adaptive Learning <span class="text-xs font-normal text-gray-500 ml-2">verdicts &amp; sim outcomes tune future scoring</span></h3>
                            <button id="sync-behavior-btn" class="text-xs text-gray-400 hover:text-cyber-neon border border-cyber-border rounded px-3 py-1.5"><i class="fa-solid fa-arrows-rotate mr-1"></i> Sync sim behaviour</button>
                        </div>
                        <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-5">
                            <div class="bg-cyber-dark rounded-lg p-3 border border-cyber-border"><p class="text-xs text-gray-400 mb-1">Confirmed Phishing</p><h4 class="text-xl font-bold text-cyber-danger" id="l-confirmed">—</h4></div>
                            <div class="bg-cyber-dark rounded-lg p-3 border border-cyber-border"><p class="text-xs text-gray-400 mb-1">False Positives</p><h4 class="text-xl font-bold text-cyber-warning" id="l-fp">—</h4></div>
                            <div class="bg-cyber-dark rounded-lg p-3 border border-cyber-border"><p class="text-xs text-gray-400 mb-1">Learned Bad</p><h4 class="text-xl font-bold text-cyber-danger" id="l-bad">—</h4></div>
                            <div class="bg-cyber-dark rounded-lg p-3 border border-cyber-border"><p class="text-xs text-gray-400 mb-1">Learned Trusted</p><h4 class="text-xl font-bold text-cyber-neon" id="l-trusted">—</h4></div>
                        </div>
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div>
                                <div class="text-xs text-gray-400 uppercase tracking-wider mb-2">Repeat Clickers</div>
                                <div id="l-clickers" class="space-y-1 max-h-40 overflow-y-auto custom-scrollbar"></div>
                            </div>
                            <div>
                                <div class="text-xs text-gray-400 uppercase tracking-wider mb-2">Learned Reputation</div>
                                <div id="l-reputation" class="space-y-1 max-h-40 overflow-y-auto custom-scrollbar"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `,
        team: `
            <div class="view-section" id="team-view">
                <div class="flex justify-between items-center mb-6">
                    <h2 class="text-2xl font-bold text-white">Team &amp; Access <span class="text-xs font-normal text-gray-400 ml-2">Users, roles &amp; API keys</span></h2>
                </div>
                <div class="grid grid-cols-1 xl:grid-cols-2 gap-8">
                    <!-- Users -->
                    <div class="glass-card rounded-xl p-6">
                        <div class="flex justify-between items-center mb-4">
                            <h3 class="text-lg font-semibold text-white"><i class="fa-solid fa-users mr-2 text-cyber-info"></i> Users</h3>
                        </div>
                        <form id="create-user-form" class="grid grid-cols-2 gap-3 mb-4">
                            <input type="text" id="new-user-username" class="cyber-input p-2 rounded text-sm" placeholder="username" required>
                            <input type="password" id="new-user-password" class="cyber-input p-2 rounded text-sm" placeholder="password (min 8)" required>
                            <input type="text" id="new-user-fullname" class="cyber-input p-2 rounded text-sm" placeholder="full name (optional)">
                            <select id="new-user-role" class="cyber-input p-2 rounded text-sm">
                                <option value="viewer">viewer</option>
                                <option value="analyst">analyst</option>
                                <option value="admin">admin</option>
                                <option value="owner">owner</option>
                            </select>
                            <button type="submit" class="col-span-2 py-2 bg-cyber-neon/10 border border-cyber-neon text-cyber-neon hover:bg-cyber-neon/20 rounded text-sm font-medium transition-colors">
                                <i class="fa-solid fa-user-plus mr-1"></i> Add User
                            </button>
                        </form>
                        <div class="overflow-x-auto">
                            <table class="w-full text-sm">
                                <thead class="text-xs text-gray-500 uppercase tracking-wider border-b border-cyber-border">
                                    <tr><th class="text-left py-2">User</th><th class="text-left py-2">Role</th><th class="text-left py-2">Status</th><th class="text-right py-2">Actions</th></tr>
                                </thead>
                                <tbody id="users-table-body"></tbody>
                            </table>
                        </div>
                    </div>
                    <!-- API Keys -->
                    <div class="glass-card rounded-xl p-6">
                        <div class="flex justify-between items-center mb-4">
                            <h3 class="text-lg font-semibold text-white"><i class="fa-solid fa-key mr-2 text-cyber-warning"></i> API Keys</h3>
                        </div>
                        <p class="text-xs text-gray-500 mb-3">Keys authenticate the ingestion API <code class="text-cyber-neon">POST /api/v1/emails</code> with an <code>X-API-Key</code> header. The full key is shown once at creation.</p>
                        <form id="create-key-form" class="flex gap-3 mb-4">
                            <input type="text" id="new-key-name" class="cyber-input p-2 rounded text-sm flex-1" placeholder="e.g. Mail Gateway Connector" required>
                            <button type="submit" class="py-2 px-4 bg-cyber-warning/10 border border-cyber-warning text-cyber-warning hover:bg-cyber-warning/20 rounded text-sm font-medium transition-colors whitespace-nowrap">
                                <i class="fa-solid fa-plus mr-1"></i> Generate
                            </button>
                        </form>
                        <div id="new-key-reveal" class="hidden mb-4 p-3 rounded bg-cyber-dark border border-cyber-neon/40 text-xs break-all">
                            <div class="text-gray-400 mb-1">Copy this key now &mdash; it won't be shown again:</div>
                            <code id="new-key-value" class="text-cyber-neon"></code>
                        </div>
                        <div class="overflow-x-auto">
                            <table class="w-full text-sm">
                                <thead class="text-xs text-gray-500 uppercase tracking-wider border-b border-cyber-border">
                                    <tr><th class="text-left py-2">Name</th><th class="text-left py-2">Status</th><th class="text-left py-2">Last used</th><th class="text-right py-2">Actions</th></tr>
                                </thead>
                                <tbody id="keys-table-body"></tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        `,
        settings: `
            <div class="view-section" id="settings-view">
                <div class="flex items-center justify-between mb-8 gap-4 flex-wrap">
                    <div>
                        <h2 class="text-2xl font-bold text-white">Settings</h2>
                        <p class="text-sm text-gray-400 mt-1">System configuration, AI, integrations &amp; security</p>
                    </div>
                    <div class="flex items-center gap-4">
                        <button onclick="logout()" class="text-sm text-gray-500 hover:text-cyber-danger transition-colors flex items-center gap-1.5"><i class="fa-solid fa-arrow-right-from-bracket"></i> Log out</button>
                        <button id="save-settings-btn" class="bg-cyber-neon text-black font-semibold px-5 py-2.5 rounded-lg shadow-[0_0_15px_rgba(0,255,157,0.3)] hover:bg-[#00cc7a] transition-all"><i class="fa-solid fa-floppy-disk mr-1.5"></i> Save Changes</button>
                    </div>
                </div>

                <div class="flex flex-col lg:flex-row gap-8">
                    <!-- Section nav -->
                    <nav class="lg:w-56 shrink-0 flex lg:flex-col gap-1 overflow-x-auto pb-1 custom-scrollbar">
                        <button data-settings-tab="ai" onclick="switchSettingsTab('ai')" class="settings-tab flex items-center gap-3 px-4 py-2.5 text-sm font-medium rounded-lg text-left whitespace-nowrap transition-colors"><i class="fa-solid fa-brain w-4"></i> AI Engine</button>
                        <button data-settings-tab="email" onclick="switchSettingsTab('email')" class="settings-tab flex items-center gap-3 px-4 py-2.5 text-sm font-medium rounded-lg text-left whitespace-nowrap transition-colors"><i class="fa-solid fa-envelope w-4"></i> Email (IMAP)</button>
                        <button data-settings-tab="integrations" onclick="switchSettingsTab('integrations')" class="settings-tab flex items-center gap-3 px-4 py-2.5 text-sm font-medium rounded-lg text-left whitespace-nowrap transition-colors"><i class="fa-solid fa-share-nodes w-4"></i> Integrations</button>
                        <button data-settings-tab="plugins" onclick="switchSettingsTab('plugins')" class="settings-tab flex items-center gap-3 px-4 py-2.5 text-sm font-medium rounded-lg text-left whitespace-nowrap transition-colors"><i class="fa-solid fa-puzzle-piece w-4"></i> Plugins</button>
                        <button data-settings-tab="security" onclick="switchSettingsTab('security')" class="settings-tab flex items-center gap-3 px-4 py-2.5 text-sm font-medium rounded-lg text-left whitespace-nowrap transition-colors"><i class="fa-solid fa-lock w-4"></i> Security</button>
                    </nav>

                    <!-- Panels -->
                    <div class="flex-1 min-w-0 max-w-3xl">
                        <!-- AI -->
                        <div data-settings-panel="ai" class="glass-card rounded-xl p-6">
                            <div class="mb-5"><h3 class="text-lg font-semibold text-white">AI Engine</h3><p class="text-xs text-gray-500 mt-1">The model that scores emails and powers the SOC copilot. Any OpenAI-compatible provider works.</p></div>
                            <div class="space-y-5">
                                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                    <div>
                                        <label class="block text-xs text-gray-400 uppercase tracking-widest mb-1.5">Provider</label>
                                        <select id="setting-ai-provider" class="cyber-input w-full p-2.5 rounded-lg text-sm">
                                            <option value="ollama">Ollama (Local LLM)</option>
                                            <option value="openai">OpenAI</option>
                                            <option value="anthropic">Anthropic (Claude)</option>
                                            <option value="groq">Groq</option>
                                            <option value="custom">Custom (OpenAI-compatible)</option>
                                        </select>
                                    </div>
                                    <div>
                                        <label class="block text-xs text-gray-400 uppercase tracking-widest mb-1.5">Model</label>
                                        <input type="text" id="setting-ai-model" list="ai-model-suggestions" class="cyber-input w-full p-2.5 rounded-lg text-sm" placeholder="qwen2.5:3b / gpt-4o-mini">
                                        <datalist id="ai-model-suggestions">
                                            <option value="qwen2.5:3b"></option><option value="llama3.2"></option><option value="llama3.1:8b"></option><option value="phi3"></option>
                                            <option value="gpt-4o-mini"></option><option value="gpt-4o"></option><option value="claude-3-5-haiku-latest"></option><option value="llama-3.1-8b-instant"></option>
                                        </datalist>
                                    </div>
                                </div>
                                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                    <div>
                                        <label class="block text-xs text-gray-400 uppercase tracking-widest mb-1.5">API Key <span class="normal-case text-gray-600 tracking-normal">(cloud)</span></label>
                                        <input type="password" id="setting-ai-key" class="cyber-input w-full p-2.5 rounded-lg text-sm" placeholder="blank for local / unchanged">
                                    </div>
                                    <div id="setting-ai-base-wrap">
                                        <label class="block text-xs text-gray-400 uppercase tracking-widest mb-1.5">Base URL <span class="normal-case text-gray-600 tracking-normal">(local / custom)</span></label>
                                        <input type="text" id="setting-ai-base" class="cyber-input w-full p-2.5 rounded-lg text-sm" placeholder="http://ollama:11434/v1">
                                    </div>
                                </div>
                                <div class="pt-4 border-t border-cyber-border/50">
                                    <div class="flex justify-between mb-2">
                                        <label class="block text-xs text-gray-400 uppercase tracking-widest">Auto-Quarantine Threshold</label>
                                        <span id="setting-ai-threshold-val" class="text-xs text-cyber-danger font-semibold">70%</span>
                                    </div>
                                    <input type="range" id="setting-ai-threshold" class="w-full h-1.5 bg-cyber-border rounded appearance-none cursor-pointer accent-cyber-danger" min="1" max="100" value="70">
                                </div>
                                <button type="button" onclick="testAiConnection()" class="text-xs bg-cyber-panel border border-cyber-border hover:border-cyber-neon hover:text-cyber-neon text-gray-300 px-3 py-2 rounded-lg transition-colors"><i class="fa-solid fa-plug mr-1.5"></i> Test AI Connection</button>
                            </div>
                        </div>

                        <!-- Email / IMAP -->
                        <div data-settings-panel="email" class="hidden glass-card rounded-xl p-6">
                            <div class="mb-5"><h3 class="text-lg font-semibold text-white">Email Interception (IMAP)</h3><p class="text-xs text-gray-500 mt-1">The mailbox ThreatEye monitors for incoming mail to analyse and quarantine.</p></div>
                            <div class="space-y-5">
                                <div>
                                    <label class="block text-xs text-gray-400 uppercase tracking-widest mb-1.5">IMAP Server</label>
                                    <input type="text" id="setting-imap-server" class="cyber-input w-full p-2.5 rounded-lg text-sm" placeholder="imap.corporate.com">
                                </div>
                                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                    <div>
                                        <label class="block text-xs text-gray-400 uppercase tracking-widest mb-1.5">Username</label>
                                        <input type="text" id="setting-imap-user" class="cyber-input w-full p-2.5 rounded-lg text-sm" placeholder="security_bot@corp.com">
                                    </div>
                                    <div>
                                        <label class="block text-xs text-gray-400 uppercase tracking-widest mb-1.5">Password</label>
                                        <input type="password" id="setting-imap-pass" class="cyber-input w-full p-2.5 rounded-lg text-sm" placeholder="•••••••• (unchanged)">
                                    </div>
                                </div>
                                <button type="button" onclick="testImapConnection()" class="text-xs bg-cyber-panel border border-cyber-border hover:border-cyber-info hover:text-cyber-info text-gray-300 px-3 py-2 rounded-lg transition-colors"><i class="fa-solid fa-plug mr-1.5"></i> Test Connection</button>
                            </div>
                        </div>

                        <!-- Integrations: GoPhish + SIEM -->
                        <div data-settings-panel="integrations" class="hidden space-y-6">
                            <div class="glass-card rounded-xl p-6">
                                <div class="mb-5"><h3 class="text-lg font-semibold text-white flex items-center gap-2"><i class="fa-solid fa-fish-fins text-cyber-warning"></i> GoPhish</h3><p class="text-xs text-gray-500 mt-1">Phishing-simulation engine used by the Simulations page.</p></div>
                                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                    <div>
                                        <label class="block text-xs text-gray-400 uppercase tracking-widest mb-1.5">GoPhish URL</label>
                                        <input type="text" id="setting-gophish-url" class="cyber-input w-full p-2.5 rounded-lg text-sm" placeholder="http://gophish:3333">
                                    </div>
                                    <div>
                                        <label class="block text-xs text-gray-400 uppercase tracking-widest mb-1.5">Admin API Key</label>
                                        <input type="password" id="setting-gophish-key" class="cyber-input w-full p-2.5 rounded-lg text-sm" placeholder="•••••••• (unchanged)">
                                    </div>
                                </div>
                            </div>
                            <div class="glass-card rounded-xl p-6">
                                <div class="mb-5"><h3 class="text-lg font-semibold text-white flex items-center gap-2"><i class="fa-solid fa-share-nodes text-cyber-info"></i> SIEM Alert Forwarding</h3><p class="text-xs text-gray-500 mt-1">Quarantine alerts are forwarded in real time (Splunk HEC, Elastic, Sentinel, Datadog, or any webhook). Delivery status shows in Framework → SIEM events.</p></div>
                                <div class="space-y-5">
                                    <div>
                                        <label class="block text-xs text-gray-400 uppercase tracking-widest mb-1.5">Webhook / HEC URL</label>
                                        <input type="text" id="setting-siem-url" class="cyber-input w-full p-2.5 rounded-lg text-sm" placeholder="https://splunk:8088/services/collector/event">
                                    </div>
                                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                        <div>
                                            <label class="block text-xs text-gray-400 uppercase tracking-widest mb-1.5">API Key / Token</label>
                                            <input type="password" id="setting-siem-key" class="cyber-input w-full p-2.5 rounded-lg text-sm" placeholder="•••••••• (unchanged)">
                                        </div>
                                        <div>
                                            <label class="block text-xs text-gray-400 uppercase tracking-widest mb-1.5">Event Format</label>
                                            <select id="setting-siem-format" class="cyber-input w-full p-2.5 rounded-lg text-sm">
                                                <option value="raw">Raw (native JSON)</option>
                                                <option value="ecs">ECS (Elastic)</option>
                                                <option value="ocsf">OCSF</option>
                                            </select>
                                        </div>
                                    </div>
                                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                        <div>
                                            <label class="block text-xs text-gray-400 uppercase tracking-widest mb-1.5">Auth Header</label>
                                            <input type="text" id="setting-siem-auth-header" class="cyber-input w-full p-2.5 rounded-lg text-sm" placeholder="Authorization">
                                        </div>
                                        <div>
                                            <label class="block text-xs text-gray-400 uppercase tracking-widest mb-1.5">Value Prefix</label>
                                            <input type="text" id="setting-siem-auth-prefix" class="cyber-input w-full p-2.5 rounded-lg text-sm" placeholder="Bearer / Splunk / ApiKey">
                                        </div>
                                    </div>
                                    <button type="button" onclick="testSiemConnection()" class="text-xs bg-cyber-panel border border-cyber-border hover:border-cyber-info hover:text-cyber-info text-gray-300 px-3 py-2 rounded-lg transition-colors"><i class="fa-solid fa-paper-plane mr-1.5"></i> Send Test Alert</button>
                                </div>
                            </div>
                        </div>

                        <!-- Plugins -->
                        <div data-settings-panel="plugins" class="hidden glass-card rounded-xl p-6">
                            <div class="mb-4"><h3 class="text-lg font-semibold text-white">Detection Plugins <span class="text-xs font-normal text-gray-500 ml-1">.tap packs</span></h3><p class="text-xs text-gray-500 mt-1">Upload a <code class="text-cyber-neon">.tap</code> pack of detection rules, threat-intel and playbooks. Declarative only — no code runs on the server.</p></div>
                            <form id="plugin-upload-form" class="flex gap-3 mb-5">
                                <input type="file" id="plugin-file" accept=".tap,.json" required class="cyber-input flex-1 p-2 rounded-lg text-sm file:mr-3 file:py-1.5 file:px-3 file:rounded file:border-0 file:text-xs file:font-semibold file:bg-cyber-info/20 file:text-cyber-info cursor-pointer">
                                <button type="submit" class="py-2 px-4 bg-cyber-info/10 border border-cyber-info text-cyber-info hover:bg-cyber-info/20 rounded-lg text-sm font-medium whitespace-nowrap"><i class="fa-solid fa-upload mr-1"></i> Install</button>
                            </form>
                            <div id="plugins-list" class="space-y-2"></div>
                        </div>

                        <!-- Security -->
                        <div data-settings-panel="security" class="hidden glass-card rounded-xl p-6">
                            <div class="mb-5"><h3 class="text-lg font-semibold text-white">Change Password</h3><p class="text-xs text-gray-500 mt-1">Update the credentials for this account.</p></div>
                            <div class="space-y-5 max-w-md">
                                <div>
                                    <label class="block text-xs text-gray-400 uppercase tracking-widest mb-1.5">Current Password</label>
                                    <input type="password" id="setting-auth-current" class="cyber-input w-full p-2.5 rounded-lg text-sm" placeholder="••••••••">
                                </div>
                                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                    <div>
                                        <label class="block text-xs text-gray-400 uppercase tracking-widest mb-1.5">New Password</label>
                                        <input type="password" id="setting-auth-new" class="cyber-input w-full p-2.5 rounded-lg text-sm" placeholder="min 8 characters">
                                    </div>
                                    <div>
                                        <label class="block text-xs text-gray-400 uppercase tracking-widest mb-1.5">Confirm</label>
                                        <input type="password" id="setting-auth-confirm" class="cyber-input w-full p-2.5 rounded-lg text-sm" placeholder="repeat new password">
                                    </div>
                                </div>
                                <button type="button" onclick="changeAdminPassword()" class="text-xs bg-cyber-panel border border-cyber-border hover:border-cyber-danger hover:text-cyber-danger text-gray-300 px-4 py-2 rounded-lg transition-colors">Update Password</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `
    };

    window.logout = async function () {
        try {
            await fetch(`${API_BASE}/auth/logout`, { method: 'POST', credentials: 'include', headers: { 'X-CSRF-Token': csrfToken } });
        } catch (_) { /* ignore */ }
        csrfToken = '';
        appInitialized = false;
        window.location.reload();
    };

    window.changeAdminPassword = async function () {
        const current = document.getElementById('setting-auth-current').value;
        const newPass = document.getElementById('setting-auth-new').value;
        const confirmPass = document.getElementById('setting-auth-confirm').value;

        if (!current || !newPass || !confirmPass) {
            return showCustomAlert("Please fill in all password fields.", "Validation Error", true);
        }
        if (newPass !== confirmPass) {
            return showCustomAlert("New passwords do not match.", "Validation Error", true);
        }

        try {
            const res = await apiFetch(`${API_BASE}/auth/change-password`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ current_password: current, new_password: newPass })
            });

            if (res.ok) {
                showCustomAlert("Password successfully updated.", "Success", false);
                document.getElementById('setting-auth-current').value = '';
                document.getElementById('setting-auth-new').value = '';
                document.getElementById('setting-auth-confirm').value = '';
            } else {
                const data = await res.json();
                showCustomAlert(data.detail || "Failed to update password.", "Error", true);
            }
        } catch (e) {
            showCustomAlert("Could not update password. Please sign in again and retry.", "Error", true);
        }
    };

    // Keep track of charts
    let chartInstances = {};

    function switchView(target) {
        // Update Nav
        navButtons.forEach(btn => {
            btn.classList.remove('active');
            if (btn.dataset.target === target) {
                btn.classList.add('active');
            }
        });

        // Inject View content
        if (views[target]) {
            viewContainer.innerHTML = views[target];

            // Add 'active' class to ensuring visibility
            const viewElement = viewContainer.querySelector('.view-section');
            if (viewElement) {
                viewElement.classList.add('active');
            }

            // Re-initialize scripts specific to injected view
            if (target === 'dashboard') {
                loadDashboardStats();
                loadRecentThreats();

                // Attach View All link to Monitoring view
                const viewAllLink = document.querySelector('#dashboard-view a[data-target="monitoring"]');
                if (viewAllLink) {
                    viewAllLink.addEventListener('click', (e) => {
                        e.preventDefault();
                        switchView('monitoring');
                    });
                }

                // Make dashboard stat cards clickable
                const totalEmailsCard = document.querySelector('#dashboard-view .glass-card.border-t-cyber-info');
                if (totalEmailsCard) {
                    totalEmailsCard.classList.add('cursor-pointer', 'hover:bg-cyber-dark/80', 'transition-colors');
                    totalEmailsCard.addEventListener('click', () => switchView('monitoring'));
                }

                const suspiciousCard = document.querySelector('#dashboard-view .glass-card.border-t-cyber-warning');
                if (suspiciousCard) {
                    suspiciousCard.classList.add('cursor-pointer', 'hover:bg-cyber-dark/80', 'transition-colors');
                    suspiciousCard.addEventListener('click', () => {
                        switchView('monitoring');
                        setTimeout(() => {
                            const riskFilter = document.getElementById('monitor-risk-filter');
                            if (riskFilter) {
                                riskFilter.value = 'suspicious';
                                riskFilter.dispatchEvent(new Event('change', { bubbles: true }));
                            }
                        }, 100);
                    });
                }

                const quarantineCard = document.querySelector('#dashboard-view .glass-card.border-t-cyber-danger');
                if (quarantineCard) {
                    quarantineCard.classList.add('cursor-pointer', 'hover:bg-cyber-dark/80', 'transition-colors');
                    quarantineCard.addEventListener('click', () => switchView('quarantine'));
                }

                const simCard = document.querySelector('#dashboard-view .glass-card.border-t-cyber-neon');
                if (simCard) {
                    simCard.classList.add('cursor-pointer', 'hover:bg-cyber-dark/80', 'transition-colors');
                    simCard.addEventListener('click', () => switchView('simulation'));
                }
            } else if (target === 'monitoring') {
                loadMonitoringEmails();
            } else if (target === 'quarantine') {
                loadQuarantineEmails();
            } else if (target === 'analytics') {
                initAnalyticsCharts();
            } else if (target === 'simulation') {
                setupSimulationTriggers();
                loadActiveSimulations(); // Call the new function here
            } else if (target === 'framework') {
                setupFrameworkCenter();
            } else if (target === 'soc') {
                setupSocCenter();
            } else if (target === 'team') {
                setupTeamView();
            } else if (target === 'settings') {
                setupSettings();
            }
        }
    }

    // Attach listeners
    document.body.addEventListener('click', (e) => {
        const btn = e.target.closest('.nav-btn');
        if (btn) {
            e.preventDefault();
            const target = btn.dataset.target;
            if (target) {
                switchView(target);
            }
        }
    });

    /* --- API Fetch Logic & DOM Updates --- */
    const API_BASE = 'http://localhost:8000/api';

    const MUTATING_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

    async function apiFetch(url, options = {}, _retry = true) {
        const headers = new Headers(options.headers || {});
        const method = (options.method || 'GET').toUpperCase();
        if (MUTATING_METHODS.includes(method)) headers.set('X-CSRF-Token', csrfToken);
        let res = await fetch(url, { ...options, headers, credentials: 'include' });
        // Access token expired → refresh once (rotating cookies) and retry.
        if (res.status === 401 && _retry && !url.includes('/auth/')) {
            const r = await fetch(`${API_BASE}/auth/refresh`, { method: 'POST', credentials: 'include', headers: { 'X-CSRF-Token': csrfToken } });
            if (r.ok) {
                csrfToken = (await r.json()).csrf_token || csrfToken;
                return apiFetch(url, options, false);
            }
        }
        if (res.status === 401) {
            appInitialized = false;
            checkAuth();
        }
        return res;
    }

    function escapeHTML(value) {
        return String(value ?? '').replace(/[&<>"']/g, (ch) => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        }[ch]));
    }

    function parseJSONField(value, fallback) {
        if (!value) return fallback;
        if (typeof value === 'object') return value;
        try {
            return JSON.parse(value);
        } catch (_) {
            return fallback;
        }
    }

    function renderAgentVerdicts(item) {
        const verdicts = parseJSONField(item.agent_verdicts_json, {});
        const entries = Object.entries(verdicts);
        if (!entries.length) return '';
        return `
            <div>
                <label class="text-xs text-gray-500 uppercase tracking-wider block mb-1">AI Mode 2.0 Agents</label>
                <div class="grid grid-cols-1 gap-2">
                    ${entries.map(([name, verdict]) => `
                        <div class="bg-cyber-dark border border-cyber-border rounded p-2">
                            <div class="flex justify-between items-center text-xs">
                                <span class="text-cyber-info font-semibold">${escapeHTML(name.replaceAll('_', ' '))}</span>
                                <span class="text-white">${Number.parseInt(verdict.score, 10) || 0}%</span>
                            </div>
                            <div class="text-xs text-gray-400 mt-1">${escapeHTML(verdict.verdict || 'No verdict')}</div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }

    function renderEvidence(item) {
        const evidence = parseJSONField(item.evidence_json, {});
        const signals = Array.isArray(evidence.signals) ? evidence.signals : [];
        const urls = Array.isArray(evidence.urls) ? evidence.urls : parseJSONField(item.urls_found, []);
        const recommended = item.recommended_action || evidence.recommended_action || 'No action recommendation available.';
        return `
            <div>
                <label class="text-xs text-gray-500 uppercase tracking-wider block mb-1">Evidence-Based Verdict</label>
                <div class="bg-cyber-dark border border-cyber-border rounded p-3 space-y-3">
                    <div class="flex justify-between text-xs">
                        <span class="text-gray-400">Threat Type</span>
                        <span class="text-white font-semibold">${escapeHTML(item.threat_type || 'Unknown')}</span>
                    </div>
                    <div class="flex justify-between text-xs">
                        <span class="text-gray-400">Confidence</span>
                        <span class="text-cyber-neon font-semibold">${Number.parseInt(item.confidence_score, 10) || 0}%</span>
                    </div>
                    <div class="text-xs text-gray-300 border-t border-cyber-border/60 pt-2">${escapeHTML(recommended)}</div>
                    ${signals.length ? `
                        <ul class="text-xs text-gray-400 space-y-1 border-t border-cyber-border/60 pt-2">
                            ${signals.slice(0, 8).map(signal => `<li><i class="fa-solid fa-check text-cyber-neon mr-1"></i>${escapeHTML(signal)}</li>`).join('')}
                        </ul>
                    ` : ''}
                    ${urls.length ? `
                        <div class="text-xs text-gray-500 break-all border-t border-cyber-border/60 pt-2">
                            ${urls.slice(0, 3).map(url => `<div><i class="fa-solid fa-link mr-1"></i>${escapeHTML(url)}</div>`).join('')}
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
    }

    // ---------------- SOC Center (metrics, triage, coverage, intel) ----------------
    async function setupSocCenter() {
        const refresh = document.getElementById('soc-refresh');
        if (refresh) refresh.addEventListener('click', loadSocCenter);
        const intelForm = document.getElementById('add-intel-form');
        if (intelForm) {
            intelForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                const payload = {
                    type: document.getElementById('intel-type').value,
                    value: document.getElementById('intel-value').value.trim(),
                    verdict: document.getElementById('intel-verdict').value
                };
                try {
                    const res = await apiFetch(`${API_BASE}/intel/indicators`, {
                        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload)
                    });
                    if (!res.ok) { const d = await res.json(); throw new Error(d.detail || 'Failed'); }
                    intelForm.reset();
                    loadIntel();
                } catch (err) { showCustomAlert(err.message, 'Add Indicator Failed', true); }
            });
        }
        const copilotForm = document.getElementById('copilot-form');
        if (copilotForm) {
            copilotForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                const input = document.getElementById('copilot-input');
                const q = input.value.trim();
                if (!q) return;
                const log = document.getElementById('copilot-log');
                const add = (who, text, cls) => {
                    const div = document.createElement('div');
                    div.className = cls;
                    div.innerHTML = `<span class="text-xs text-gray-500">${who}</span><div class="whitespace-pre-wrap">${escapeHTML(text)}</div>`;
                    log.appendChild(div); log.scrollTop = log.scrollHeight;
                };
                add('You', q, 'text-gray-300');
                input.value = '';
                const thinking = document.createElement('div');
                thinking.className = 'text-gray-500 text-xs'; thinking.textContent = 'Copilot is thinking…';
                log.appendChild(thinking);
                try {
                    const res = await apiFetch(`${API_BASE}/copilot`, {
                        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ question: q })
                    });
                    const data = await res.json();
                    thinking.remove();
                    add('Copilot', data.answer || 'No answer.', 'text-cyber-neon');
                } catch (err) {
                    thinking.remove();
                    add('Copilot', 'Failed to reach the copilot.', 'text-cyber-danger');
                }
            });
        }
        loadSocCenter();
    }

    async function loadSocCenter() {
        loadSocMetrics();
        loadTriage();
        loadAttackCoverage();
        loadIntel();
        loadClusters();
        loadLearning();
        const syncBtn = document.getElementById('sync-behavior-btn');
        if (syncBtn && !syncBtn.dataset.bound) {
            syncBtn.dataset.bound = '1';
            syncBtn.addEventListener('click', async () => {
                syncBtn.disabled = true;
                const orig = syncBtn.innerHTML;
                syncBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-1"></i> Syncing…';
                try {
                    const res = await apiFetch(`${API_BASE}/simulations/sync-behavior`, { method: 'POST' });
                    const data = await res.json();
                    if (!res.ok) throw new Error(data.detail || 'Sync failed');
                    showCustomAlert(`Updated ${data.updated} employee risk profiles (${data.repeat_clickers || 0} repeat clickers).`, 'Behaviour Synced');
                    loadLearning();
                } catch (e) { showCustomAlert(e.message, 'Sync Failed', true); }
                finally { syncBtn.disabled = false; syncBtn.innerHTML = orig; }
            });
        }
    }

    async function loadLearning() {
        try {
            const res = await apiFetch(`${API_BASE}/learning/summary`);
            const d = await res.json();
            const set = (id, v) => { const el = document.getElementById(id); if (el) el.innerText = (v == null) ? '—' : v; };
            set('l-confirmed', d.confirmed_phishing);
            set('l-fp', d.false_positives);
            set('l-bad', d.learned_bad);
            set('l-trusted', d.learned_trusted);

            const clickers = document.getElementById('l-clickers');
            if (clickers) {
                const rows = d.repeat_clickers || [];
                clickers.innerHTML = rows.length ? rows.map(r => `
                    <div class="flex justify-between items-center text-sm py-1 border-b border-cyber-border/40">
                        <span class="text-gray-300 truncate max-w-[200px]">${escapeHTML(r.email)}</span>
                        <span class="text-xs"><span class="text-cyber-danger">${r.failed_simulations_count}× failed</span> · risk ${r.behavioral_risk_score}</span>
                    </div>`).join('') : '<div class="text-sm text-gray-500">No sim failures recorded. Run a simulation, then "Sync sim behaviour".</div>';
            }
            const reput = document.getElementById('l-reputation');
            if (reput) {
                const rows = d.top_reputation || [];
                reput.innerHTML = rows.length ? rows.map(r => {
                    const bad = r.score >= 0;
                    return `<div class="flex justify-between items-center text-sm py-1 border-b border-cyber-border/40">
                        <span class="text-gray-300 truncate max-w-[200px]">${escapeHTML(r.value)} <span class="text-gray-600 text-xs">(${escapeHTML(r.kind.replace('_', ' '))})</span></span>
                        <span class="text-xs font-bold ${bad ? 'text-cyber-danger' : 'text-cyber-neon'}">${r.score > 0 ? '+' : ''}${r.score}</span>
                    </div>`;
                }).join('') : '<div class="text-sm text-gray-500">Nothing learned yet. Mark emails as Phishing/Safe to teach the model.</div>';
            }
        } catch (_) { /* ignore */ }
    }

    async function loadClusters() {
        const el = document.getElementById('clusters-list');
        if (!el) return;
        try {
            const res = await apiFetch(`${API_BASE}/campaigns/clusters?days=14`);
            const clusters = await res.json();
            const multi = (clusters || []).filter(c => c.count > 1);
            const show = multi.length ? multi : (clusters || []);
            if (!show.length) { el.innerHTML = '<div class="text-sm text-gray-500 py-2">No campaigns detected.</div>'; return; }
            el.innerHTML = show.slice(0, 12).map(c => `
                <div class="p-2 rounded bg-cyber-dark border border-cyber-border">
                    <div class="flex justify-between items-center">
                        <span class="text-white text-sm truncate max-w-[180px]">${escapeHTML(c.sample_subject || '(no subject)')}</span>
                        <span class="text-xs px-2 py-0.5 rounded bg-cyber-warning/20 text-cyber-warning">${c.count}×</span>
                    </div>
                    <div class="text-xs text-gray-500 truncate">${escapeHTML(c.sender_domain)} · ${escapeHTML(c.threat_type)} · max ${c.max_risk}%</div>
                </div>`).join('');
        } catch (_) {
            el.innerHTML = '<div class="text-sm text-cyber-danger py-2">Failed to load clusters.</div>';
        }
    }

    async function loadSocMetrics() {
        try {
            const res = await apiFetch(`${API_BASE}/soc/metrics`);
            const m = await res.json();
            const set = (id, v) => { const el = document.getElementById(id); if (el) el.innerText = (v === null || v === undefined) ? '—' : v; };
            set('m-open', m.open_cases);
            set('m-sla', m.sla_breaches);
            set('m-mttd', m.mttd_minutes);
            set('m-mttr', m.mttr_minutes);
        } catch (_) { /* ignore */ }
    }

    async function loadTriage() {
        const tbody = document.getElementById('triage-table-body');
        if (!tbody) return;
        try {
            const res = await apiFetch(`${API_BASE}/triage?limit=50`);
            const items = await res.json();
            if (!items.length) { tbody.innerHTML = '<tr><td colspan="5" class="py-6 text-center text-gray-500">Queue is clear — no items need attention.</td></tr>'; return; }
            const priColor = { P1: 'bg-cyber-danger/20 text-cyber-danger', P2: 'bg-cyber-warning/20 text-cyber-warning', P3: 'bg-cyber-info/20 text-cyber-info' };
            tbody.innerHTML = items.map(it => `
                <tr class="border-b border-cyber-border/40">
                    <td class="py-2"><span class="text-xs px-2 py-0.5 rounded ${priColor[it.priority] || ''}">${escapeHTML(it.priority)}</span></td>
                    <td class="py-2">
                        <div class="text-white truncate max-w-[240px]">${escapeHTML(it.subject || '(no subject)')}</div>
                        <div class="text-xs text-gray-500 truncate max-w-[240px]">${escapeHTML(it.sender || '')}</div>
                    </td>
                    <td class="py-2 font-bold ${it.risk_score > 70 ? 'text-cyber-danger' : 'text-cyber-neon'}">${it.risk_score}%</td>
                    <td class="py-2 text-xs text-gray-400">${escapeHTML(it.threat_type || 'Unknown')}</td>
                    <td class="py-2 text-right space-x-1">
                        <button onclick="remediate(${it.id}, ['notify'])" title="Notify SOC channel" class="text-xs text-gray-400 hover:text-cyber-info"><i class="fa-solid fa-bell"></i></button>
                        <button onclick="remediate(${it.id}, ['block_ioc'])" title="Blocklist IOCs" class="text-xs text-gray-400 hover:text-cyber-warning"><i class="fa-solid fa-ban"></i></button>
                        <button onclick="remediate(${it.id}, ['clawback','ticket'])" title="Clawback + ticket" class="text-xs text-gray-400 hover:text-cyber-danger"><i class="fa-solid fa-hand"></i></button>
                    </td>
                </tr>`).join('');
        } catch (_) {
            tbody.innerHTML = '<tr><td colspan="5" class="py-6 text-center text-cyber-danger">Failed to load triage queue.</td></tr>';
        }
    }

    async function loadAttackCoverage() {
        const container = document.getElementById('attack-coverage');
        if (!container) return;
        try {
            const res = await apiFetch(`${API_BASE}/attack/coverage`);
            const data = await res.json();
            const cov = document.getElementById('m-cov');
            if (cov) cov.innerText = `${data.summary.coverage_pct}%`;
            const statusColor = { defended: 'bg-cyber-neon', observed: 'bg-cyber-warning', gap: 'bg-cyber-border' };
            container.innerHTML = Object.entries(data.tactics).map(([tactic, techs]) => `
                <div>
                    <div class="text-xs text-gray-400 uppercase tracking-wider mb-1">${escapeHTML(tactic)}</div>
                    <div class="flex flex-wrap gap-1">
                        ${techs.map(t => `<span title="${escapeHTML(t.technique)} (${t.status}${t.observed ? ', seen ' + t.observed : ''})" class="text-[10px] px-1.5 py-0.5 rounded ${statusColor[t.status] || 'bg-cyber-border'} ${t.status === 'gap' ? 'text-gray-400' : 'text-black'}">${escapeHTML(t.technique_id)}</span>`).join('')}
                    </div>
                </div>`).join('');
        } catch (_) {
            container.innerHTML = '<div class="text-xs text-cyber-danger">Failed to load coverage.</div>';
        }
    }

    async function loadIntel() {
        const tbody = document.getElementById('intel-table-body');
        if (!tbody) return;
        try {
            const res = await apiFetch(`${API_BASE}/intel/indicators?limit=200`);
            const rows = await res.json();
            if (!rows.length) { tbody.innerHTML = '<tr><td colspan="6" class="py-4 text-center text-gray-500">No indicators yet.</td></tr>'; return; }
            const vColor = { block: 'text-cyber-danger', suspicious: 'text-cyber-warning', allow: 'text-cyber-neon' };
            tbody.innerHTML = rows.map(r => `
                <tr class="border-b border-cyber-border/40">
                    <td class="py-2 text-xs text-gray-400">${escapeHTML(r.type)}</td>
                    <td class="py-2 text-white break-all max-w-[300px]">${escapeHTML(r.value)}</td>
                    <td class="py-2 text-xs font-semibold ${vColor[r.verdict] || ''}">${escapeHTML(r.verdict)}</td>
                    <td class="py-2 text-xs text-gray-500">${r.hits || 0}</td>
                    <td class="py-2 text-xs text-gray-500 truncate max-w-[160px]">${escapeHTML(r.source || '')}</td>
                    <td class="py-2 text-right"><button onclick="deleteIntel(${r.id})" class="text-xs text-gray-400 hover:text-cyber-danger">Remove</button></td>
                </tr>`).join('');
        } catch (_) {
            tbody.innerHTML = '<tr><td colspan="6" class="py-4 text-center text-cyber-danger">Failed to load indicators.</td></tr>';
        }
    }

    window.remediate = async function (emailId, actions) {
        try {
            const res = await apiFetch(`${API_BASE}/emails/${emailId}/remediate`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ actions })
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.detail || 'Remediation failed');
            const summary = (data.results || []).map(r => `${r.action}: ${r.status || (r.results && r.results.map(x => x.target + '=' + x.status).join(', '))}`).join(' · ');
            showCustomAlert(summary || 'Actions dispatched.', 'Remediation', false);
            loadTriage();
        } catch (err) { showCustomAlert(err.message, 'Remediation Failed', true); }
    };

    window.deleteIntel = async function (id) {
        const ok = await showCustomConfirm('Remove this indicator?', 'Remove Indicator');
        if (!ok) return;
        try {
            const res = await apiFetch(`${API_BASE}/intel/indicators/${id}`, { method: 'DELETE' });
            if (!res.ok) { const d = await res.json(); throw new Error(d.detail || 'Delete failed'); }
            loadIntel();
        } catch (err) { showCustomAlert(err.message, 'Remove Failed', true); }
    };

    window.investigateEmail = async function (emailId) {
        const box = document.getElementById(`ai-invest-${emailId}`);
        if (!box) return;
        box.innerHTML = '<div class="text-xs text-gray-500 mt-2"><i class="fa-solid fa-spinner fa-spin mr-1"></i> AI is investigating…</div>';
        try {
            const res = await apiFetch(`${API_BASE}/emails/${emailId}/investigate`);
            const data = await res.json();
            if (!res.ok) throw new Error(data.detail || 'Investigation failed');
            box.innerHTML = `
                <label class="text-xs text-gray-500 uppercase tracking-wider block mb-1 mt-2">AI Investigation</label>
                <div class="bg-cyber-dark border border-cyber-neon/30 rounded p-3 text-xs text-gray-300 whitespace-pre-wrap">${escapeHTML(data.narrative || '')}</div>`;
        } catch (err) {
            box.innerHTML = `<div class="text-xs text-cyber-danger mt-2">${escapeHTML(err.message)}</div>`;
        }
    };

    // ---------------- Team & Access (users + API keys) ----------------
    const ROLE_OPTIONS = ['viewer', 'analyst', 'admin', 'owner'];

    async function setupTeamView() {
        const userForm = document.getElementById('create-user-form');
        if (userForm) {
            userForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                const payload = {
                    username: document.getElementById('new-user-username').value.trim(),
                    password: document.getElementById('new-user-password').value,
                    full_name: document.getElementById('new-user-fullname').value.trim(),
                    role: document.getElementById('new-user-role').value
                };
                try {
                    const res = await apiFetch(`${API_BASE}/users`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload)
                    });
                    const data = await res.json();
                    if (!res.ok) throw new Error(data.detail || 'Failed to create user');
                    userForm.reset();
                    loadUsers();
                } catch (err) {
                    showCustomAlert(err.message, 'Create User Failed', true);
                }
            });
        }
        const keyForm = document.getElementById('create-key-form');
        if (keyForm) {
            keyForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                const name = document.getElementById('new-key-name').value.trim();
                try {
                    const res = await apiFetch(`${API_BASE}/keys`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ name })
                    });
                    const data = await res.json();
                    if (!res.ok) throw new Error(data.detail || 'Failed to create key');
                    document.getElementById('new-key-value').innerText = data.api_key;
                    document.getElementById('new-key-reveal').classList.remove('hidden');
                    keyForm.reset();
                    loadApiKeys();
                } catch (err) {
                    showCustomAlert(err.message, 'Create Key Failed', true);
                }
            });
        }
        loadUsers();
        loadApiKeys();
    }

    async function loadUsers() {
        const tbody = document.getElementById('users-table-body');
        if (!tbody) return;
        try {
            const res = await apiFetch(`${API_BASE}/users`);
            if (!res.ok) {
                tbody.innerHTML = '<tr><td colspan="4" class="py-4 text-center text-gray-500">Requires admin role to manage users.</td></tr>';
                return;
            }
            const users = await res.json();
            if (!users.length) {
                tbody.innerHTML = '<tr><td colspan="4" class="py-4 text-center text-gray-500">No users.</td></tr>';
                return;
            }
            tbody.innerHTML = users.map(u => {
                const roleSelect = ROLE_OPTIONS.map(r => `<option value="${r}" ${u.role === r ? 'selected' : ''}>${r}</option>`).join('');
                return `
                <tr class="border-b border-cyber-border/40">
                    <td class="py-2">
                        <div class="text-white">${escapeHTML(u.username)}</div>
                        <div class="text-xs text-gray-500">${escapeHTML(u.full_name || '')}</div>
                    </td>
                    <td class="py-2">
                        <select onchange="updateUserRole(${u.id}, this.value)" class="cyber-input p-1 rounded text-xs">${roleSelect}</select>
                    </td>
                    <td class="py-2"><span class="${u.active ? 'text-cyber-neon' : 'text-gray-500'} text-xs">${u.active ? 'Active' : 'Disabled'}</span></td>
                    <td class="py-2 text-right space-x-2">
                        <button onclick="toggleUser(${u.id}, ${u.active ? 'false' : 'true'})" class="text-xs text-gray-400 hover:text-cyber-warning">${u.active ? 'Disable' : 'Enable'}</button>
                        <button onclick="deleteUser(${u.id})" class="text-xs text-gray-400 hover:text-cyber-danger">Delete</button>
                    </td>
                </tr>`;
            }).join('');
        } catch (err) {
            tbody.innerHTML = '<tr><td colspan="4" class="py-4 text-center text-cyber-danger">Failed to load users.</td></tr>';
        }
    }

    async function loadApiKeys() {
        const tbody = document.getElementById('keys-table-body');
        if (!tbody) return;
        try {
            const res = await apiFetch(`${API_BASE}/keys`);
            if (!res.ok) {
                tbody.innerHTML = '<tr><td colspan="4" class="py-4 text-center text-gray-500">Requires admin role.</td></tr>';
                return;
            }
            const keys = await res.json();
            if (!keys.length) {
                tbody.innerHTML = '<tr><td colspan="4" class="py-4 text-center text-gray-500">No API keys yet.</td></tr>';
                return;
            }
            tbody.innerHTML = keys.map(k => `
                <tr class="border-b border-cyber-border/40">
                    <td class="py-2 text-white">${escapeHTML(k.name)}</td>
                    <td class="py-2"><span class="${k.active ? 'text-cyber-neon' : 'text-gray-500'} text-xs">${k.active ? 'Active' : 'Revoked'}</span></td>
                    <td class="py-2 text-xs text-gray-500">${k.last_used_at ? escapeHTML(String(k.last_used_at)) : 'never'}</td>
                    <td class="py-2 text-right">
                        ${k.active ? `<button onclick="revokeKey(${k.id})" class="text-xs text-gray-400 hover:text-cyber-danger">Revoke</button>` : '<span class="text-xs text-gray-600">&mdash;</span>'}
                    </td>
                </tr>`).join('');
        } catch (err) {
            tbody.innerHTML = '<tr><td colspan="4" class="py-4 text-center text-cyber-danger">Failed to load keys.</td></tr>';
        }
    }

    window.updateUserRole = async function (userId, role) {
        try {
            const res = await apiFetch(`${API_BASE}/users/${userId}`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ role })
            });
            if (!res.ok) { const d = await res.json(); throw new Error(d.detail || 'Update failed'); }
        } catch (err) { showCustomAlert(err.message, 'Update Failed', true); loadUsers(); }
    };

    window.toggleUser = async function (userId, active) {
        try {
            const res = await apiFetch(`${API_BASE}/users/${userId}`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ active })
            });
            if (!res.ok) { const d = await res.json(); throw new Error(d.detail || 'Update failed'); }
            loadUsers();
        } catch (err) { showCustomAlert(err.message, 'Update Failed', true); }
    };

    window.deleteUser = async function (userId) {
        const ok = await showCustomConfirm('Delete this user? This cannot be undone.', 'Delete User');
        if (!ok) return;
        try {
            const res = await apiFetch(`${API_BASE}/users/${userId}`, { method: 'DELETE' });
            if (!res.ok) { const d = await res.json(); throw new Error(d.detail || 'Delete failed'); }
            loadUsers();
        } catch (err) { showCustomAlert(err.message, 'Delete Failed', true); }
    };

    window.revokeKey = async function (keyId) {
        const ok = await showCustomConfirm('Revoke this API key? Clients using it will stop working.', 'Revoke Key');
        if (!ok) return;
        try {
            const res = await apiFetch(`${API_BASE}/keys/${keyId}`, { method: 'DELETE' });
            if (!res.ok) { const d = await res.json(); throw new Error(d.detail || 'Revoke failed'); }
            loadApiKeys();
        } catch (err) { showCustomAlert(err.message, 'Revoke Failed', true); }
    };

    async function loadTimeline(emailId, containerId) {
        const container = document.getElementById(containerId);
        if (!container) return;
        try {
            const res = await apiFetch(`${API_BASE}/emails/${emailId}/timeline`);
            const events = await res.json();
            if (!events.length) {
                container.innerHTML = '<div class="text-xs text-gray-500">No timeline events yet.</div>';
                return;
            }
            container.innerHTML = events.map(ev => `
                <div class="flex gap-2 text-xs">
                    <div class="mt-1 w-2 h-2 rounded-full bg-cyber-info"></div>
                    <div>
                        <div class="text-white">${escapeHTML(ev.event_type)}</div>
                        <div class="text-gray-500">${escapeHTML(ev.details || '')}</div>
                    </div>
                </div>
            `).join('');
        } catch (_) {
            container.innerHTML = '<div class="text-xs text-cyber-danger">Failed to load timeline.</div>';
        }
    }

    // Global Modal Control Functions
    window.showCustomAlert = function (message, title = "Notification", isError = false) {
        return new Promise((resolve) => {
            const modal = document.getElementById('custom-modal');
            const icon = document.getElementById('modal-icon');

            document.getElementById('modal-title-text').innerText = title;
            document.getElementById('modal-message').innerText = message;

            document.getElementById('modal-cancel-btn').classList.add('hidden'); // Hide cancel for simple alert

            if (isError) {
                icon.className = "fa-solid fa-triangle-exclamation text-cyber-danger mr-2";
            } else {
                icon.className = "fa-solid fa-circle-exclamation text-cyber-neon mr-2";
            }

            modal.classList.remove('hidden');
            setTimeout(() => modal.classList.remove('opacity-0'), 10);

            const closeBtn = document.getElementById('modal-close-icon');
            const okBtn = document.getElementById('modal-confirm-btn');

            const closeHandler = () => {
                modal.classList.add('opacity-0');
                setTimeout(() => modal.classList.add('hidden'), 300);
                okBtn.removeEventListener('click', closeHandler);
                closeBtn.removeEventListener('click', closeHandler);
                resolve(true);
            };

            okBtn.addEventListener('click', closeHandler);
            closeBtn.addEventListener('click', closeHandler);
        });
    };

    window.showCustomConfirm = function (message, title = "Confirm Action") {
        return new Promise((resolve) => {
            const modal = document.getElementById('custom-modal');
            const icon = document.getElementById('modal-icon');

            document.getElementById('modal-title-text').innerText = title;
            document.getElementById('modal-message').innerText = message;

            icon.className = "fa-solid fa-circle-question text-cyber-warning mr-2";

            const cancelBtn = document.getElementById('modal-cancel-btn');
            cancelBtn.classList.remove('hidden');

            modal.classList.remove('hidden');
            setTimeout(() => modal.classList.remove('opacity-0'), 10);

            const closeBtn = document.getElementById('modal-close-icon');
            const okBtn = document.getElementById('modal-confirm-btn');

            const closeHandler = (result) => {
                modal.classList.add('opacity-0');
                setTimeout(() => modal.classList.add('hidden'), 300);

                // Cleanup listeners
                okBtn.replaceWith(okBtn.cloneNode(true));
                cancelBtn.replaceWith(cancelBtn.cloneNode(true));
                closeBtn.replaceWith(closeBtn.cloneNode(true));

                resolve(result);
            };

            document.getElementById('modal-confirm-btn').addEventListener('click', () => closeHandler(true));
            document.getElementById('modal-cancel-btn').addEventListener('click', () => closeHandler(false));
            document.getElementById('modal-close-icon').addEventListener('click', () => closeHandler(false));
        });
    };

    window.emptyQuarantine = async function () {
        const confirmed = await showCustomConfirm("Are you sure you want to permanently delete ALL quarantined emails?", "Empty Quarantine");
        if (confirmed) {
            try {
                const res = await apiFetch(`${API_BASE}/quarantine/empty/all`, { method: 'DELETE' });
                if (res.ok) {
                    await showCustomAlert("Quarantine emptied successfully", "Success", false);
                    loadQuarantineEmails();
                    loadDashboardStats();
                } else {
                    await showCustomAlert("Failed to empty quarantine", "Error", true);
                }
            } catch (e) {
                await showCustomAlert("Network error", "Error", true);
            }
        }
    };

    window.testImapConnection = async function () {
        // Blank fields fall back to the saved config on the backend, so the button
        // works on an already-saved server without re-typing the password.
        const server = document.getElementById('setting-imap-server').value.trim();
        const user = document.getElementById('setting-imap-user').value.trim();
        const pass = document.getElementById('setting-imap-pass').value;
        try {
            const res = await apiFetch(`${API_BASE}/settings/test-imap`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ server, user, password: pass })
            });
            const data = await res.json();
            if (res.ok) {
                await showCustomAlert(data.message || "Connection successful.", "Connection Successful", false);
            } else {
                await showCustomAlert(data.detail || "Connection failed.", "Connection Failed", true);
            }
        } catch (e) {
            await showCustomAlert("Network error occurred while testing connection.", "Error", true);
        }
    };

    window.testAiConnection = async function () {
        const provider = document.getElementById('setting-ai-provider')?.value || '';
        const model = document.getElementById('setting-ai-model')?.value.trim() || '';
        const api_key = document.getElementById('setting-ai-key')?.value || '';
        const base_url = document.getElementById('setting-ai-base')?.value.trim() || '';
        await showCustomAlert("Testing AI connection… this may take a few seconds.", "Testing", false);
        try {
            const res = await apiFetch(`${API_BASE}/settings/test-ai`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ provider, model, api_key, base_url })
            });
            const data = await res.json();
            if (res.ok) {
                await showCustomAlert(`✓ ${data.provider} · ${data.model}\nLatency: ${data.latency_ms} ms\nReply: ${data.reply}`, "AI Connection OK", false);
            } else {
                await showCustomAlert(data.detail || "AI connection failed.", "AI Connection Failed", true);
            }
        } catch (e) {
            await showCustomAlert("Network error while testing AI connection.", "Error", true);
        }
    };

    window.testSiemConnection = async function () {
        // Tests the SAVED SIEM config — save settings first, then send a test alert.
        await showCustomAlert("Sending a test alert to your SIEM…", "Testing SIEM", false);
        try {
            const res = await apiFetch(`${API_BASE}/settings/test-siem`, { method: 'POST' });
            const data = await res.json();
            if (res.ok) {
                await showCustomAlert(`✓ Delivered to ${data.destination}\nHTTP ${data.response_code} · format: ${data.format}`, "SIEM Alert Sent", false);
            } else {
                await showCustomAlert(data.detail || "SIEM test failed.", "SIEM Test Failed", true);
            }
        } catch (e) {
            await showCustomAlert("Network error while testing SIEM.", "Error", true);
        }
    };

    window.handleQuarantineAction = async function (action, emailId) {
        if (action === 'delete') {
            const confirmed = await showCustomConfirm("Are you sure you want to permanently delete this email?");
            if (confirmed) {
                await apiFetch(`${API_BASE}/emails/${emailId}`, { method: 'DELETE' });
                loadQuarantineEmails();
                loadDashboardStats();
                // Also remove it from Monitor array locally so it disappears until SSE refreshes
                if (window.monitorEmailsRef) {
                    window.monitorEmailsRef = window.monitorEmailsRef.filter(e => e.id != emailId);
                }
                const detailCardQ = document.querySelector('#quarantine-view .glass-card:last-child');
                if (detailCardQ) detailCardQ.innerHTML = '<h3 class="font-medium text-white mb-4 border-b border-cyber-border/50 pb-2">Threat Detail</h3><p class="text-gray-500 text-sm">Select an item to view details</p>';
                const detailCardM = document.querySelector('#monitoring-view .glass-card:last-child');
                if (detailCardM) detailCardM.innerHTML = '<h3 class="font-medium text-white mb-4 border-b border-cyber-border/50 pb-2">Threat Detail</h3><p class="text-gray-500 text-sm">Select an item to view details</p>';

                // Switch back focus
                if (window.currentView === 'monitoring') loadMonitoringEmails();
            }
        } else if (action === 'release') {
            try {
                const res = await apiFetch(`${API_BASE}/emails/${emailId}/release`, { method: 'POST' });
                if (res.ok) {
                    await showCustomAlert("Email released to user inbox.", "Success");
                    loadQuarantineEmails();
                    loadDashboardStats();
                    if (window.currentView === 'monitoring') loadMonitoringEmails();

                    const detailCardQ = document.querySelector('#quarantine-view .glass-card:last-child');
                    if (detailCardQ) detailCardQ.innerHTML = '<h3 class="font-medium text-white mb-4 border-b border-cyber-border/50 pb-2">Threat Detail</h3><p class="text-gray-500 text-sm">Select an item to view details</p>';
                    const detailCardM = document.querySelector('#monitoring-view .glass-card:last-child');
                    if (detailCardM) detailCardM.innerHTML = '<h3 class="font-medium text-white mb-4 border-b border-cyber-border/50 pb-2">Threat Detail</h3><p class="text-gray-500 text-sm">Select an item to view details</p>';
                } else {
                    await showCustomAlert("Failed to release email.", "Error", true);
                }
            } catch (e) {
                await showCustomAlert("Network error.", "Error", true);
            }
        }
    };

    window.reviewEmail = async function (emailId, verdict) {
        try {
            const res = await apiFetch(`${API_BASE}/emails/${emailId}/review`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ verdict, notes: 'Reviewed from ThreatEye dashboard' })
            });
            const data = await res.json();
            if (res.ok) {
                await showCustomAlert(`Review status: ${data.review_status}`, "Review Saved", false);
                loadMonitoringEmails();
                loadQuarantineEmails();
                loadDashboardStats();
            } else {
                await showCustomAlert(data.detail || "Failed to save review.", "Review Error", true);
            }
        } catch (e) {
            await showCustomAlert("Network error while saving review.", "Review Error", true);
        }
    };

    // Notifications Logic
    async function initNotifications() {
        const notifBtn = document.getElementById('notification-btn');
        const notifDropdown = document.getElementById('notification-dropdown');
        const notifBadge = document.getElementById('notification-badge');
        const notifList = document.getElementById('notification-list');

        if (!notifBtn || !notifDropdown) return;

        // Toggle Dropdown
        notifBtn.addEventListener('click', () => {
            notifDropdown.classList.toggle('hidden');
        });

        // Close when clicking outside
        document.addEventListener('click', (e) => {
            if (!notifBtn.contains(e.target) && !notifDropdown.contains(e.target)) {
                notifDropdown.classList.add('hidden');
            }
        });

        // Backend SSE Connection — the httpOnly access cookie authenticates the stream.
        const sse = new EventSource(`${API_BASE}/stream`, { withCredentials: true });

        sse.addEventListener('new_email', (e) => {
            try {
                const newEmails = JSON.parse(e.data);
                if (newEmails && newEmails.length > 0) {
                    // Update monitor table dynamically without reloading entire view
                    const tbody = document.getElementById('monitor-table-body');
                    if (tbody) {
                        // Remove empty state message if present
                        if (tbody.innerHTML.includes('No incoming emails')) {
                            tbody.innerHTML = '';
                        }

                        // Prevent UI clutter by keeping only newest 50
                        if (tbody.children.length >= 50) {
                            for (let i = 0; i < newEmails.length; i++) {
                                tbody.removeChild(tbody.lastChild);
                            }
                        }

                        const rowsHTML = newEmails.map(r => {
                            const dateObj = new Date(r.timestamp + 'Z');
                            const timeStr = dateObj.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                            const sender = escapeHTML(r.sender);
                            const subject = escapeHTML(r.subject);
                            const senderLower = escapeHTML(String(r.sender || '').toLowerCase());
                            const subjectLower = escapeHTML(String(r.subject || '').toLowerCase());
                            const status = escapeHTML(r.status);
                            const isInternal = String(r.sender || '').includes('company') || String(r.sender || '').includes('internal');
                            const isDanger = r.risk_score > 70 || r.url_threat_score > 70;
                            const statusColor = r.status === 'Quarantined' ? 'bg-cyber-danger/20 text-cyber-danger border border-cyber-danger/30' : 'bg-cyber-neon/10 text-cyber-neon border border-cyber-neon/20';

                            return `
                        <tr class="cyber-table-row group cursor-pointer monitor-row border-l-2 border-transparent hover:border-cyber-neon transition-colors animate-pulse" data-id="${r.id}" data-sender="${senderLower}" data-subject="${subjectLower}" data-risk="${r.risk_score}">
                            <td class="py-4 px-6 text-cyber-neon font-medium">${timeStr}</td>
                            <td class="py-4 px-6">
                                <div class="font-medium text-white truncate max-w-[250px]">${sender}</div>
                                <div class="text-xs ${isInternal ? 'text-cyber-info' : 'text-gray-500'}">${isInternal ? 'Internal' : 'External'}</div>
                            </td>
                            <td class="py-4 px-6 text-gray-300 truncate max-w-[300px]">${subject}</td>
                            <td class="py-4 px-6">
                                <div class="flex items-center">
                                    <span class="w-2 h-2 rounded-full ${r.url_threat_score > 50 ? 'bg-cyber-danger' : 'bg-cyber-neon'} mr-2"></span>
                                    ${r.url_threat_score}%
                                </div>
                            </td>
                            <td class="py-4 px-6">
                                <div class="w-full bg-cyber-dark rounded-full h-1.5 mt-2">
                                    <div class="${isDanger ? 'bg-cyber-danger' : 'bg-cyber-neon'} h-1.5 rounded-full" style="width: ${r.risk_score}%"></div>
                                </div>
                                <span class="text-xs ${isDanger ? 'text-cyber-danger' : 'text-cyber-neon'} font-medium">${r.risk_score}%</span>
                            </td>
                            <td class="py-4 px-6">
                                <span class="${statusColor} px-2.5 py-1 rounded text-xs">${status}</span>
                            </td>
                            <td class="py-4 px-6 text-right">
                                <button class="text-gray-500 hover:text-cyber-neon transition-colors"><i class="fa-solid fa-expand"></i></button>
                            </td>
                        </tr>
                        `;
                        }).join('');

                        // Use insertAdjacentHTML to prepend instead of overwriting
                        tbody.insertAdjacentHTML('afterbegin', rowsHTML);

                        // Add click listeners to new rows directly
                        bindMonitorRowClicks();

                        // Apply filters to ensure newly added row adheres to current UI search/select state
                        applyMonitorFilters();

                        // Remove pulse animation after a few seconds
                        setTimeout(() => {
                            const pulsed = tbody.querySelectorAll('.animate-pulse');
                            pulsed.forEach(el => el.classList.remove('animate-pulse'));
                        }, 3000);
                    }

                    // Show a toast
                    const latest = newEmails[newEmails.length - 1];
                    if (latest.risk_score > 60) {
                        showCustomAlert(`High Risk Email Detected from ${latest.sender || 'unknown sender'}`, "Threat Alert", true);
                        if (notifBadge) notifBadge.classList.remove('hidden');
                    }
                }
            } catch (e) {
                console.error("Error parsing SSE new_email", e);
            }
        });

        sse.addEventListener('refresh_stats', () => {
            // When an event happens, softly update the dashboard stats and quarantine logic
            loadDashboardStats();

            // If we are looking at Quarantine View, refresh it
            const currentView = document.querySelector('.view-section:not(.hidden)');
            if (currentView && currentView.id === 'quarantine-view') {
                loadQuarantineEmails();
            }
        });

        // Fetch Initial Notifications To Populate List
        try {
            const res = await apiFetch(`${API_BASE}/notifications`);
            if (res.ok) {
                const alerts = await res.json();
                if (alerts.length > 0) {
                    notifBadge.classList.remove('hidden');
                    notifList.innerHTML = alerts.map(a => `
                        <li class="p-3 border-b border-cyber-border/50 hover:bg-cyber-panel/50 cursor-pointer transition-colors" onclick="openNotification(${a.email_id || 'null'})">
                            <div class="flex items-start">
                                <i class="fa-solid fa-triangle-exclamation text-cyber-danger mt-1 mr-3"></i>
                                <div>
                                    <p class="text-xs font-semibold text-white">${escapeHTML(a.subject)}</p>
                                    <p class="text-[10px] text-gray-400 mt-1">${escapeHTML(a.details)}</p>
                                    <p class="text-[9px] text-cyber-neon mt-1">${new Date(a.time + 'Z').toLocaleString()}</p>
                                </div>
                            </div>
                        </li>
                    `).join('');
                } else {
                    notifBadge.classList.add('hidden');
                    notifList.innerHTML = '<li class="p-3 text-xs text-center text-gray-500">No new alerts</li>';
                }
            }
        } catch (error) {
            console.error("Failed to load notifications:", error);
        }
    }

    // Clicking a notification navigates to Quarantine and opens the exact email.
    window.openNotification = function (emailId) {
        const dd = document.getElementById('notification-dropdown');
        if (dd) dd.classList.add('hidden');
        const badge = document.getElementById('notification-badge');
        if (badge) badge.classList.add('hidden');
        switchView('quarantine');
        if (!emailId) return;
        let tries = 0;
        const iv = setInterval(() => {
            tries += 1;
            const row = document.querySelector(`#quarantine-view .cyber-table-row[data-id="${emailId}"]`);
            if (row) {
                clearInterval(iv);
                row.click();
                row.scrollIntoView({ behavior: 'smooth', block: 'center' });
                row.classList.add('border-cyber-neon', 'bg-cyber-panel/60');
                setTimeout(() => row.classList.remove('bg-cyber-panel/60'), 2500);
            } else if (tries > 25) {
                clearInterval(iv);
            }
        }, 150);
    };

    function initializeApp() {
        if (appInitialized) return;
        appInitialized = true;
        applyIdentity();
        initNotifications();
        switchView('dashboard');
    }

    // Fetch the current identity and gate admin-only UI by role.
    async function applyIdentity() {
        try {
            const res = await apiFetch(`${API_BASE}/auth/me`);
            if (!res.ok) return;
            const me = await res.json();
            window.currentUser = me;
            const isAdmin = ['admin', 'owner'].includes(me.role);
            document.querySelectorAll('.admin-only').forEach(el => {
                el.style.display = isAdmin ? '' : 'none';
            });
            // Reflect the logged-in user in the sidebar profile block.
            const nameEl = document.querySelector('aside .text-xs.text-white.font-medium');
            const roleEl = document.querySelector('aside .text-\\[10px\\].text-gray-500');
            if (nameEl && me.username) nameEl.innerText = me.username;
            if (roleEl && me.role) roleEl.innerText = me.role.charAt(0).toUpperCase() + me.role.slice(1);
        } catch (_) { /* non-fatal */ }
    }

    // Default load — determine the session from the cookie (via /auth/me, with refresh).
    bootstrapAuth();

    async function loadDashboardStats(days = 7) {
        try {
            const res = await apiFetch(`${API_BASE}/stats?days=${encodeURIComponent(days)}`);
            const data = await res.json();

            // Update Number Cards
            document.querySelector('#dashboard-view h3:nth-of-type(1)').innerText = data.total_emails_scanned.toLocaleString();
            document.querySelectorAll('#dashboard-view h3')[1].innerText = data.suspicious_emails.toLocaleString();
            document.querySelectorAll('#dashboard-view h3')[2].innerText = data.quarantined_emails.toLocaleString();
            document.querySelectorAll('#dashboard-view h3')[3].innerText = data.active_simulations.toLocaleString();

            const currentRisk = data.current_risk_level || 0;
            const gaugeValueEl = document.querySelector('#dashboard-view .text-4xl.font-bold');
            if (gaugeValueEl) {
                gaugeValueEl.innerText = currentRisk;
                if (currentRisk < 30) {
                    gaugeValueEl.className = 'text-4xl font-bold text-cyber-neon';
                } else if (currentRisk < 70) {
                    gaugeValueEl.className = 'text-4xl font-bold text-cyber-warning';
                } else {
                    gaugeValueEl.className = 'text-4xl font-bold text-cyber-danger';
                }
            }

            // Update Sidebar Quarantine Count Badge
            const qBadge = document.getElementById('sidebar-quarantine-count');
            if (qBadge) {
                const qCount = parseInt(data.quarantined_emails) || 0;
                if (qCount > 0) {
                    qBadge.innerText = qCount;
                    qBadge.classList.remove('hidden');
                } else {
                    qBadge.classList.add('hidden');
                }
            }

            initDashboardCharts(currentRisk, data.trend_labels, data.trend_values);

        } catch (error) {
            console.error("Failed to load dashboard stats:", error);
            initDashboardCharts(50, ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'], [0, 0, 0, 0, 0, 0, 0]); // Fallback
        }
    }

    async function loadRecentThreats() {
        try {
            const res = await apiFetch(`${API_BASE}/emails?limit=5`);
            const emails = await res.json();
            const tbody = document.getElementById('dashboard-recent-table');
            if (!tbody) return;

            if (emails.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="py-4 text-center text-gray-500">No emails monitored yet</td></tr>';
                return;
            }

            tbody.innerHTML = emails.map(r => {
                const dateObj = new Date(r.timestamp + 'Z'); // Assume UTC from DB for now
                const timeStr = dateObj.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                const isDanger = r.risk_score > 70 || r.url_threat_score > 70;
                const subject = escapeHTML(r.subject);
                const sender = escapeHTML(r.sender);
                const status = escapeHTML(r.status);

                return `
                <tr class="nav-btn cursor-pointer border-b border-cyber-border/50 hover:bg-cyber-panel/50 transition-colors" data-target="${isDanger ? 'quarantine' : 'monitoring'}">
                    <td class="py-3 px-4">${timeStr}</td>
                    <td class="py-3 px-4 text-gray-300 font-medium truncate max-w-[200px]">${subject}</td>
                    <td class="py-3 px-4 truncate max-w-[200px]">${sender}</td>
                    <td class="py-3 px-4">
                        <span class="${isDanger ? 'text-cyber-danger' : 'text-cyber-neon'} font-bold">${r.risk_score}%</span>
                    </td>
                    <td class="py-3 px-4">
                        <span class="${r.status === 'Quarantined' ? 'bg-cyber-danger/20 text-cyber-danger border-cyber-danger/30' : 'bg-cyber-neon/10 text-cyber-neon border-cyber-neon/20'} border px-2 py-0.5 rounded text-xs">
                            ${status}
                        </span>
                    </td>
                </tr>
                `;
            }).join('');
        } catch (error) {
            console.error("Failed to load recent threats:", error);
        }
    }

    async function loadMonitoringEmails() {
        try {
            const res = await apiFetch(`${API_BASE}/emails?limit=50`);
            const emails = await res.json();
            window.monitorEmailsRef = emails; // store for easy access

            const tbody = document.getElementById('monitor-table-body');
            if (!tbody) return;

            if (emails.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" class="py-12 text-center text-gray-500">No incoming emails monitored yet.</td></tr>';
                return;
            }

            tbody.innerHTML = emails.map(r => {
                const dateObj = new Date(r.timestamp + 'Z');
                const timeStr = dateObj.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                const sender = escapeHTML(r.sender);
                const subject = escapeHTML(r.subject);
                const senderLower = escapeHTML(String(r.sender || '').toLowerCase());
                const subjectLower = escapeHTML(String(r.subject || '').toLowerCase());
                const status = escapeHTML(r.status);
                const isInternal = String(r.sender || '').includes('internal.com') || String(r.sender || '').includes('corp.com');
                const isDanger = r.risk_score > 70 || r.url_threat_score > 70;
                const statusColor = r.status === 'Quarantined' ? 'bg-cyber-danger/20 text-cyber-danger border border-cyber-danger/30' : 'bg-cyber-neon/10 text-cyber-neon border border-cyber-neon/20';

                return `
                <tr class="cyber-table-row group cursor-pointer monitor-row border-l-2 border-transparent hover:border-cyber-neon transition-colors" data-id="${r.id}" data-sender="${senderLower}" data-subject="${subjectLower}" data-risk="${r.risk_score}">
                    <td class="py-4 px-6 text-gray-400">${timeStr}</td>
                    <td class="py-4 px-6">
                        <div class="font-medium text-white truncate max-w-[250px]">${sender}</div>
                        <div class="text-xs ${isInternal ? 'text-cyber-info' : 'text-gray-500'}">${isInternal ? 'Internal' : 'External'}</div>
                    </td>
                    <td class="py-4 px-6 text-gray-300 truncate max-w-[300px]">${subject}</td>
                    <td class="py-4 px-6">
                        <div class="flex items-center">
                            <span class="w-2 h-2 rounded-full ${r.url_threat_score > 50 ? 'bg-cyber-danger' : 'bg-cyber-neon'} mr-2"></span>
                            ${r.url_threat_score}%
                        </div>
                    </td>
                    <td class="py-4 px-6">
                        <div class="w-full bg-cyber-dark rounded-full h-1.5 mt-2">
                            <div class="${isDanger ? 'bg-cyber-danger' : 'bg-cyber-neon'} h-1.5 rounded-full" style="width: ${r.risk_score}%"></div>
                        </div>
                        <span class="text-xs ${isDanger ? 'text-cyber-danger' : 'text-cyber-neon'} font-medium">${r.risk_score}%</span>
                    </td>
                    <td class="py-4 px-6">
                        <span class="${statusColor} px-2.5 py-1 rounded text-xs">${status}</span>
                    </td>
                    <td class="py-4 px-6 text-right">
                        <button class="text-gray-500 hover:text-cyber-neon transition-colors"><i class="fa-solid fa-expand"></i></button>
                    </td>
                </tr>
                `;
            }).join('');

            // Apply current filters if any
            applyMonitorFilters();
            bindMonitorRowClicks();

        } catch (error) {
            console.error("Failed to load monitoring emails:", error);
        }
    }

    function bindMonitorRowClicks() {
        document.querySelectorAll('#monitor-table-body .cyber-table-row').forEach(row => {
            // Remove old listener if exists to prevent duplicates (though typically we redraw)
            const newRow = row.cloneNode(true);
            row.parentNode.replaceChild(newRow, row);

            newRow.addEventListener('click', () => {
                const rowId = newRow.getAttribute('data-id');
                const emails = window.monitorEmailsRef || [];
                const item = emails.find(e => e.id == rowId);

                if (item) {
                    const detailContent = document.getElementById('monitor-detail-content');
                    const detailActions = document.getElementById('monitor-detail-actions');

                    if (detailContent && detailActions) {
                        const isMalicious = item.risk_score > 70;
                        const iconColor = isMalicious ? 'text-cyber-danger' : 'text-cyber-neon';
                        const bgColor = isMalicious ? 'bg-cyber-danger/10 border-cyber-danger/30' : 'bg-cyber-neon/10 border-cyber-neon/30';
                        const subject = escapeHTML(item.subject || 'No Subject');
                        const sender = escapeHTML(item.sender);
                        const status = escapeHTML(item.status);
                        const analysisLog = escapeHTML(item.ai_analysis_log || 'Heuristic checks passed. No significant AI behavioral threats detected.');

                        detailContent.innerHTML = `
                            <div>
                                <label class="text-xs text-gray-500 uppercase tracking-wider block mb-1">Subject</label>
                                <div class="text-white font-medium bg-cyber-dark p-2 rounded border border-cyber-border">${subject}</div>
                            </div>
                            <div>
                                <label class="text-xs text-gray-500 uppercase tracking-wider block mb-1">Sender</label>
                                <div class="text-xs text-gray-400 font-mono bg-cyber-dark p-2 rounded border border-cyber-border break-all">
                                    Return-Path: &lt;${sender}&gt;
                                </div>
                            </div>
                            <div>
                                <label class="text-xs text-gray-500 uppercase tracking-wider block mb-1">Risk Assessment</label>
                                <div class="text-sm text-gray-300 ${bgColor} border p-3 rounded">
                                    <div class="flex items-center justify-between mb-2">
                                        <span class="font-bold flex items-center"><i class="fa-solid fa-robot ${iconColor} mr-2"></i> Overall Score: ${item.risk_score}%</span>
                                        <span class="text-xs px-2 rounded ${item.status === 'Quarantined' ? 'bg-cyber-danger text-white' : 'bg-cyber-neon text-black'}">${status}</span>
                                    </div>
                                    <div class="text-xs mt-2 border-t border-gray-600/50 pt-2 break-words">
                                        ${analysisLog}
                                    </div>
                                </div>
                            </div>
                            ${renderEvidence(item)}
                            ${renderAgentVerdicts(item)}
                            <div>
                                <label class="text-xs text-gray-500 uppercase tracking-wider block mb-1">SOC Timeline</label>
                                <div id="monitor-timeline-${item.id}" class="bg-cyber-dark border border-cyber-border rounded p-3 space-y-2">
                                    <div class="text-xs text-gray-500">Loading timeline...</div>
                                </div>
                            </div>
                            <div id="ai-invest-${item.id}"></div>
                        `;
                        loadTimeline(item.id, `monitor-timeline-${item.id}`);

                        // Show/hide actions based on status
                        detailActions.classList.remove('hidden');
                        detailActions.innerHTML = `
                            <button onclick="investigateEmail(${item.id})" class="w-full py-2 mb-2 bg-cyber-neon/10 border border-cyber-neon/40 text-cyber-neon rounded text-xs font-medium hover:bg-cyber-neon/20 transition-colors"><i class="fa-solid fa-robot mr-1"></i> AI Investigate</button>
                            <div class="grid grid-cols-3 gap-2">
                                <button onclick="reviewEmail(${item.id}, 'safe')" class="py-2 bg-cyber-neon/10 border border-cyber-neon/30 text-cyber-neon rounded text-xs">Mark Safe</button>
                                <button onclick="reviewEmail(${item.id}, 'phishing')" class="py-2 bg-cyber-danger/10 border border-cyber-danger/30 text-cyber-danger rounded text-xs">Confirm Phishing</button>
                                <button onclick="reviewEmail(${item.id}, 'review')" class="py-2 bg-cyber-info/10 border border-cyber-info/30 text-cyber-info rounded text-xs">Needs Review</button>
                            </div>
                            ${item.status === 'Quarantined' ? `
                                <button onclick="handleQuarantineAction('delete', ${item.id})" class="w-full py-2 bg-cyber-danger/80 hover:bg-cyber-danger text-white rounded font-medium transition-colors shadow-lg shadow-cyber-danger/20">Delete Permanently</button>
                                <button onclick="handleQuarantineAction('release', ${item.id})" class="w-full py-2 bg-transparent border border-cyber-border text-gray-400 hover:text-white hover:border-gray-500 rounded font-medium transition-colors">Release to Inbox (Admin)</button>
                            ` : ''}
                        `;
                    }
                }
            });
        });
    }

    // Front-end filter logic for Monitor Table
    function applyMonitorFilters() {
        const searchInput = document.getElementById('monitor-search');
        const filterSelect = document.getElementById('monitor-risk-filter');
        if (!searchInput || !filterSelect) return;

        const term = searchInput.value.toLowerCase();
        const riskMode = filterSelect.value;
        const rows = document.querySelectorAll('.monitor-row');

        rows.forEach(row => {
            const sender = row.getAttribute('data-sender') || '';
            const subject = row.getAttribute('data-subject') || '';
            const risk = parseInt(row.getAttribute('data-risk') || '0');

            let matchesSearch = sender.includes(term) || subject.includes(term);
            let matchesRisk = true;

            if (riskMode === 'high') {
                matchesRisk = risk > 70;
            } else if (riskMode === 'medium') {
                matchesRisk = risk >= 30 && risk <= 70;
            } else if (riskMode === 'low') {
                matchesRisk = risk < 30;
            }

            if (matchesSearch && matchesRisk) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    }

    // Attach listeners for monitor filters natively (Event Delegation for dynamically injected views)
    document.addEventListener('input', (e) => {
        if (e.target.id === 'monitor-search') {
            applyMonitorFilters();
        }
    });
    document.addEventListener('change', (e) => {
        if (e.target.id === 'monitor-risk-filter') {
            applyMonitorFilters();
        } else if (e.target.id === 'dashboard-trend-range') {
            const days = parseInt(e.target.value) || 7;
            const titleMap = {
                7: '7-Day Threat Trend',
                30: '1-Month Threat Trend',
                90: '3-Month Threat Trend',
                365: '1-Year Threat Trend'
            };
            const titleEl = document.getElementById('dashboard-trend-title');
            if (titleEl) titleEl.innerText = titleMap[days];
            loadDashboardStats(days);
        }
    });

    async function loadQuarantineEmails() {
        try {
            const res = await apiFetch(`${API_BASE}/quarantine`);
            const qItems = await res.json();
            const tbody = document.querySelector('#quarantine-view tbody');
            const titleCount = document.querySelector('#quarantine-view h3.text-white');
            if (!tbody) return;

            if (titleCount) titleCount.innerText = `Isolated Items (${qItems.length})`;

            if (qItems.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" class="p-8 text-center text-gray-500">No threats currently isolated.</td></tr>';
                return;
            }

            // Using event delegation since we dynamically create buttons
            tbody.innerHTML = qItems.map((item, index) => {
                const dateObj = new Date(item.quarantined_at + 'Z');
                const timeStr = dateObj.toLocaleDateString() + ' ' + dateObj.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                const recipient = escapeHTML(item.recipient);
                const subject = escapeHTML(item.subject || 'No Subject');
                const reason = escapeHTML(item.ai_reason || 'High Threat Score');

                return `
                    <tr class="cyber-table-row hover:bg-cyber-panel cursor-pointer border-l-2 border-transparent" data-id="${item.id}">
                        <td class="p-4">
                            <div class="text-white">${recipient}</div>
                            <div class="text-xs text-gray-500">${timeStr}</div>
                        </td>
                        <td class="p-4 text-gray-300">${subject}</td>
                        <td class="p-4">
                            <span class="text-xs text-cyber-danger flex items-center">
                                <i class="fa-solid fa-robot mr-1"></i> ${reason}
                            </span>
                        </td>
                        <td class="p-4">
                            <div class="flex space-x-2">
                                <button data-action="release" data-id="${item.id}" class="text-xs border border-cyber-border hover:border-cyber-neon text-gray-400 hover:text-cyber-neon px-3 py-1 rounded transition-colors quarantine-action-btn">Release</button>
                                <button data-action="delete" data-id="${item.id}" class="text-xs bg-cyber-danger/10 text-cyber-danger hover:bg-cyber-danger/20 px-3 py-1 rounded transition-colors quarantine-action-btn">Delete</button>
                            </div>
                        </td>
                    </tr>
                `;
            }).join('');

            // Add Event Listeners to rendered buttons
            document.querySelectorAll('.quarantine-action-btn').forEach(btn => {
                btn.addEventListener('click', async (e) => {
                    e.stopPropagation(); // Prevents row click action
                    const action = e.target.getAttribute('data-action');
                    const qId = e.target.getAttribute('data-id');
                    handleQuarantineAction(action, qId);
                });
            });

            document.querySelectorAll('#quarantine-view .cyber-table-row').forEach(row => {
                row.addEventListener('click', () => {
                    const emailId = row.getAttribute('data-id');
                    const item = qItems.find(i => i.id == emailId);
                    if (item) {
                        const detailView = document.querySelector('#quarantine-view .glass-card:last-child');
                        if (detailView) {
                            const subject = escapeHTML(item.subject || 'No Subject');
                            const sender = escapeHTML(item.sender);
                            const reason = escapeHTML(item.ai_reason || 'High Threat Score');
                            detailView.innerHTML = `
                                <h3 class="font-medium text-white mb-4 border-b border-cyber-border/50 pb-2">Threat Detail</h3>
                                <div class="flex-1 overflow-y-auto pr-2 custom-scrollbar space-y-4">
                                    <div>
                                        <label class="text-xs text-gray-500 uppercase tracking-wider block mb-1">Subject</label>
                                        <div class="text-white font-medium bg-cyber-dark p-2 rounded border border-cyber-border">${subject}</div>
                                    </div>
                                    <div>
                                        <label class="text-xs text-gray-500 uppercase tracking-wider block mb-1">Sender</label>
                                        <div class="text-xs text-gray-400 font-mono bg-cyber-dark p-2 rounded border border-cyber-border break-all">
                                            Return-Path: &lt;${sender}&gt;
                                        </div>
                                    </div>
                                    <div>
                                        <label class="text-xs text-gray-500 uppercase tracking-wider block mb-1">AI Analysis Log</label>
                                        <div class="text-sm text-gray-300 bg-cyber-danger/10 border border-cyber-danger/30 p-3 rounded">
                                            <i class="fa-solid fa-robot text-cyber-danger mr-2"></i> 
                                            ${reason}
                                        </div>
                                    </div>
                                    ${renderEvidence(item)}
                                    ${renderAgentVerdicts(item)}
                                    <div>
                                        <label class="text-xs text-gray-500 uppercase tracking-wider block mb-1">SOC Timeline</label>
                                        <div id="quarantine-timeline-${item.id}" class="bg-cyber-dark border border-cyber-border rounded p-3 space-y-2">
                                            <div class="text-xs text-gray-500">Loading timeline...</div>
                                        </div>
                                    </div>
                                </div>
                                    <div class="grid grid-cols-3 gap-2">
                                        <button onclick="reviewEmail(${item.id}, 'safe')" class="py-2 bg-cyber-neon/10 border border-cyber-neon/30 text-cyber-neon rounded text-xs">Mark Safe</button>
                                        <button onclick="reviewEmail(${item.id}, 'phishing')" class="py-2 bg-cyber-danger/10 border border-cyber-danger/30 text-cyber-danger rounded text-xs">Confirm Phishing</button>
                                        <button onclick="reviewEmail(${item.id}, 'review')" class="py-2 bg-cyber-info/10 border border-cyber-info/30 text-cyber-info rounded text-xs">Needs Review</button>
                                    </div>
                                    <button onclick="handleQuarantineAction('delete', ${item.id})" class="w-full py-2 bg-cyber-danger/80 hover:bg-cyber-danger text-white rounded font-medium transition-colors shadow-lg shadow-cyber-danger/20">Delete Permanently</button>
                                    <button onclick="handleQuarantineAction('release', ${item.id})" class="w-full py-2 bg-transparent border border-cyber-border text-gray-400 hover:text-white hover:border-gray-500 rounded font-medium transition-colors">Release to Inbox (Admin)</button>
                                </div>
                            `;
                            loadTimeline(item.id, `quarantine-timeline-${item.id}`);
                        }
                    }
                });
            });

        } catch (error) {
            console.error("Failed to load quarantined emails:", error);
        }
    }

    async function loadActiveSimulations() {
        const tbody = document.getElementById('sim-history-table');
        if (!tbody) return;
        try {
            const res = await apiFetch(`${API_BASE}/simulations/history`);
            const data = await res.json();
            if (!data.length) {
                tbody.innerHTML = '<tr><td colspan="4" class="py-6 text-center text-gray-500">No campaigns launched yet.</td></tr>';
                return;
            }
            tbody.innerHTML = data.map(camp => {
                const statusColor = camp.status === 'Completed' ? 'bg-gray-800 text-gray-400' : 'bg-cyber-neon/10 text-cyber-neon border border-cyber-neon/30';
                const rate = (camp.click_rate != null) ? camp.click_rate : (camp.total ? Math.round((camp.clicked / camp.total) * 100) : 0);
                return `
                    <tr class="hover:bg-cyber-dark/50 transition-colors border-b border-cyber-border/40">
                        <td class="py-3">
                            <div class="font-medium text-white text-sm">${escapeHTML(camp.name)}</div>
                            <div class="text-xs text-gray-500">Launched: ${escapeHTML(String(camp.launch_date || 'Unknown'))}</div>
                        </td>
                        <td class="py-3"><span class="text-xs ${statusColor} px-2 py-0.5 rounded">${escapeHTML(String(camp.status))}</span></td>
                        <td class="py-3 text-gray-300">${camp.total || 0}</td>
                        <td class="py-3 font-bold ${rate > 30 ? 'text-cyber-danger' : 'text-cyber-neon'}">${rate}%</td>
                    </tr>
                `;
            }).join('');
        } catch (error) {
            tbody.innerHTML = '<tr><td colspan="4" class="py-6 text-center text-cyber-danger">Failed to load campaigns from API</td></tr>';
        }
    }

    window.switchUrlMode = function (mode) {
        window.currentUrlMode = mode;
        const btnAI = document.getElementById('url-mode-ai');
        const btnOS = document.getElementById('url-mode-os');

        if (!btnAI || !btnOS) return;

        [btnAI, btnOS].forEach(btn => {
            btn.classList.remove('bg-cyber-neon/20', 'text-cyber-neon');
            btn.classList.add('text-gray-400');
        });

        if (mode === 'AI') {
            btnAI.classList.add('bg-cyber-neon/20', 'text-cyber-neon');
            btnAI.classList.remove('text-gray-400', 'hover:text-white');
            btnOS.classList.add('hover:text-white');
        } else {
            btnOS.classList.add('bg-cyber-neon/20', 'text-cyber-neon');
            btnOS.classList.remove('text-gray-400', 'hover:text-white');
            btnAI.classList.add('hover:text-white');
        }
    };

    // URL Analyzer Logic (Event Delegation)
    document.addEventListener('click', async (e) => {
        const analyzeBtn = e.target.closest('#url-scan-btn');
        if (!analyzeBtn) return;

        const inputField = document.querySelector('#urlanalyzer-view input');
        const resultSection = document.querySelector('#urlanalyzer-view .glass-card');

        if (!inputField) return;

        const url = inputField.value.trim();
        if (!url) return;

        const originalText = analyzeBtn.innerHTML;
        analyzeBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Scanning...';
        analyzeBtn.disabled = true;

        try {
            const mode = window.currentUrlMode || 'AI';
            const res = await apiFetch(`${API_BASE}/analyze-url`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url, mode: mode })
            });
            const data = await res.json();

            if (resultSection) {
                // Update UI with response data
                const score = data.phishing_score || data.url_threat_score || 0;

                let riskLabel, riskColorClass, riskBorderClass, resolutionText, actionBtnHTML;
                const actionTmpl = (msg, cls, title) => `<button onclick="showCustomAlert('${msg}', '${title}')" class="text-xs border border-${cls} text-${cls} px-3 py-1 rounded hover:bg-${cls}/10 transition-colors">`;

                if (score <= 19) {
                    riskLabel = "SAFE";
                    riskColorClass = "text-cyber-neon bg-cyber-neon/20";
                    riskBorderClass = "border-t-cyber-neon";
                    resolutionText = "No significant threats detected. Traffic seems benign. Continue standard monitoring.";
                    actionBtnHTML = actionTmpl('Domain marked as Trusted.', 'cyber-neon', 'Safe Domain') + 'Mark as Trusted</button>';
                } else if (score <= 39) {
                    riskLabel = "LOW RISK";
                    riskColorClass = "text-cyber-info bg-cyber-info/20";
                    riskBorderClass = "border-t-cyber-info";
                    resolutionText = "Minor risk factors present. May be a newly registered domain or have generic keywords. Safe for general use but warrants observation.";
                    actionBtnHTML = actionTmpl('Domain added to observation list.', 'cyber-info', 'Observation Mode') + 'Monitor Activity</button>';
                } else if (score <= 59) {
                    riskLabel = "SUSPICIOUS";
                    riskColorClass = "text-cyber-warning bg-cyber-warning/20";
                    riskBorderClass = "border-t-cyber-warning";
                    resolutionText = "Domain contains suspicious combinations. Exercise caution before proceeding. Recommend visual inspection by SOC.";
                    actionBtnHTML = actionTmpl('Flagged for Manual Review by incident response team.', 'cyber-warning', 'SOC Notification') + 'Send for Manual Review</button>';
                } else if (score <= 79) {
                    riskLabel = "HIGH RISK";
                    riskColorClass = "text-orange-500 bg-orange-500/20";
                    riskBorderClass = "border-t-orange-500";
                    resolutionText = "Domain exhibits significant phishing tactics such as typosquatting or malicious keywords. Strongly recommend blocking access.";
                    actionBtnHTML = actionTmpl('Domain added to Global Blocklist successfully.', 'orange-500', 'Blocked') + 'Block Domain</button>';
                } else {
                    riskLabel = "MALICIOUS";
                    riskColorClass = "text-cyber-danger bg-cyber-danger/20";
                    riskBorderClass = "border-t-cyber-danger";
                    resolutionText = "High risk indicators present. The domain exhibits tactics definitively matched to credential harvesting or malware distribution. Block immediately.";
                    actionBtnHTML = actionTmpl('Domain added to Global Blocklist successfully. Firewall rule deployed.', 'cyber-danger', 'Blocked') + 'Add to Global Blocklist</button>';
                }

                document.getElementById('url-scan-result-text').innerText = url;
                const badgeEl = document.getElementById('url-scan-badge');
                badgeEl.className = `${riskColorClass} px-3 py-1 rounded-full font-bold`;
                badgeEl.innerText = `${score}% ${riskLabel}`;

                resultSection.className = `glass-card rounded-xl text-left border-t-4 overflow-hidden text-sm ${riskBorderClass}`;

                const findingsList = document.getElementById('url-scan-findings-list');
                const isOSMode = mode === 'OpenSource';

                if (isOSMode) {
                    const domName = escapeHTML(data.features?.domain_name || 'N/A');
                    const reg = escapeHTML(data.features?.registrar || 'Hidden / Privacy Protected');
                    const created = escapeHTML(data.features?.creation_date || 'Unknown');
                    const expires = escapeHTML(data.features?.expiration_date || 'Unknown');
                    const age = data.features?.domain_age_days !== undefined && data.features?.domain_age_days >= 0 ? `${data.features.domain_age_days} Days` : 'Unknown';

                    let extraIntel = '';
                    if (data.features?.typosquatting_target) {
                        extraIntel += `<li><i class="fa-solid fa-masks-theater text-cyber-danger mr-2"></i> <strong>Typosquatting:</strong> Spoofing <span class="text-cyber-danger">${escapeHTML(data.features.typosquatting_target)}</span></li>`;
                    }
                    if (data.features?.suspicious_keywords && data.features.suspicious_keywords.length > 0) {
                        extraIntel += `<li><i class="fa-solid fa-magnifying-glass text-cyber-warning mr-2"></i> <strong>Risk Keywords:</strong> <span class="text-cyber-warning">${escapeHTML(data.features.suspicious_keywords.join(', '))}</span></li>`;
                    }
                    if (data.features?.is_ip_based) {
                        extraIntel += `<li><i class="fa-solid fa-network-wired text-cyber-danger mr-2"></i> <strong>IP-Based Host:</strong> Direct IP navigation is highly suspicious.</li>`;
                    }

                    findingsList.innerHTML = `
                        <li><i class="fa-solid fa-server text-cyber-neon mr-2"></i> <strong>Target Domain:</strong> ${domName}</li>
                        <li><i class="fa-solid fa-building text-cyber-neon mr-2"></i> <strong>Registrar:</strong> ${reg}</li>
                        <li><i class="fa-solid fa-calendar-plus text-cyber-neon mr-2"></i> <strong>Creation Date:</strong> ${created} (Age: ${age})</li>
                        <li><i class="fa-solid fa-calendar-minus text-cyber-neon mr-2"></i> <strong>Expiration Date:</strong> ${expires}</li>
                        ${extraIntel}
                        <li class="pt-2 mt-2 border-t border-cyber-border/50"><i class="fa-solid fa-shield-halved ${score >= 60 ? 'text-cyber-danger' : 'text-cyber-neon'} mr-2"></i> <strong>Heuristics Score:</strong> ${score}%</li>
                    `;
                    document.getElementById('url-scan-findings-title').innerText = "WHOIS Intelligence";
                } else {
                    findingsList.innerHTML = `
                        <li><i class="fa-solid fa-robot ${score >= 60 ? 'text-cyber-danger' : 'text-cyber-neon'} mr-2"></i> <strong>AI Insight:</strong> ${escapeHTML(data.explanation)}</li>
                        <li><i class="fa-solid fa-link text-gray-400 mr-2"></i> <strong>Base Phishing Score:</strong> ${score}%</li>
                    `;
                    document.getElementById('url-scan-findings-title').innerText = "AI Findings";
                }

                document.getElementById('url-scan-resolution-desc').innerText = resolutionText;
                document.getElementById('url-scan-resolution-action').innerHTML = actionBtnHTML;

                resultSection.style.display = 'block';
            }
        } catch (e) {
            showCustomAlert("Analysis Failed. Ensure backend API is running.", "Error", true);
        } finally {
            analyzeBtn.innerHTML = originalText;
            analyzeBtn.disabled = false;
        }
    });

    document.addEventListener('click', async (e) => {
        const btn = e.target.closest('#download-report-btn');
        if (!btn) return;

        const originalText = btn.innerHTML;
        btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-2"></i> Generating Report...';
        btn.disabled = true;

        try {
            const res = await apiFetch(`${API_BASE}/analytics/report/pdf`);
            if (!res.ok) throw new Error("Failed to generate PDF");
            
            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `ThreatEye_Report_${new Date().toISOString().split('T')[0]}.pdf`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        } catch (error) {
            console.error(error);
            showCustomAlert("Could not generate PDF report. Check backend.", "Export Error", true);
        } finally {
            btn.innerHTML = originalText;
            btn.disabled = false;
        }
    });

    window.switchSimMode = function (mode) {
        window.currentSimMode = mode;
        const aiSettings = document.getElementById('sim-ai-settings');
        const manualSettings = document.getElementById('sim-manual-settings');
        const btnManual = document.getElementById('sim-mode-manual');
        const btnAi = document.getElementById('sim-mode-ai');
        if (!aiSettings || !manualSettings) return;
        const active = "flex-1 py-1.5 text-sm font-medium rounded-md bg-cyber-neon/20 text-cyber-neon transition-colors";
        const idle = "flex-1 py-1.5 text-sm font-medium rounded-md text-gray-400 hover:text-white transition-colors";
        if (mode === 'Manual') {
            aiSettings.classList.add('hidden');
            manualSettings.classList.remove('hidden');
            btnManual.className = active; btnAi.className = idle;
        } else {
            manualSettings.classList.add('hidden');
            aiSettings.classList.remove('hidden');
            btnAi.className = active; btnManual.className = idle;
        }
    };

    window.triggerSimulation = async function () {
        const btn = document.getElementById('sim-launch-btn');
        if (!btn) return;
        const mode = window.currentSimMode || 'AI';
        const original = btn.innerHTML;
        btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-1"></i> Launching…';
        btn.disabled = true;
        try {
            const fd = new FormData();
            fd.append('mode', mode);
            const dept = document.getElementById('sim-department');
            if (dept && dept.value) fd.append('department', dept.value);
            if (mode === 'AI') {
                const aiFile = document.getElementById('sim-ai-file');
                if (aiFile && aiFile.files.length > 0) fd.append('file', aiFile.files[0]);
                const sample = document.getElementById('sim-sample');
                if (sample && sample.value) fd.append('sample', sample.value);
                const theme = document.getElementById('sim-theme');
                if (theme && theme.value) fd.append('theme', theme.value);
            } else {
                const file = document.getElementById('sim-file');
                if (file && file.files.length > 0) fd.append('file', file.files[0]);
            }
            const res = await apiFetch(`${API_BASE}/simulations/trigger`, { method: 'POST', body: fd });
            const data = await res.json();
            if (!res.ok) throw new Error(data.detail || 'Failed to launch campaign');
            showCustomAlert(data.message || 'Campaign launched.', 'Simulation Launched');
            setTimeout(() => { loadSimResults(); loadActiveSimulations(); loadRoster(); }, 1500);
        } catch (e) {
            showCustomAlert(e.message, 'Launch Failed', true);
        } finally {
            btn.innerHTML = original;
            btn.disabled = false;
        }
    };

    async function uploadRoster(fileInput) {
        if (!fileInput || !fileInput.files.length) return;
        const fd = new FormData();
        fd.append('file', fileInput.files[0]);
        try {
            const res = await apiFetch(`${API_BASE}/simulations/targets/upload`, { method: 'POST', body: fd });
            const data = await res.json();
            if (!res.ok) throw new Error(data.detail || 'Upload failed');
            showCustomAlert(`Imported ${data.imported} employees.`, 'Roster Updated');
            loadRoster();
        } catch (e) {
            showCustomAlert(e.message, 'Import Failed', true);
        }
    }

    async function loadRoster() {
        const el = document.getElementById('roster-summary');
        const deptSelect = document.getElementById('sim-department');
        try {
            const res = await apiFetch(`${API_BASE}/simulations/targets`);
            const data = await res.json();
            const summary = data.summary || { total: 0, by_department: {} };
            if (el) {
                if (!summary.total) {
                    el.innerHTML = '<span class="text-gray-500">No employees yet — import a CSV to begin.</span>';
                } else {
                    el.innerHTML = `<div class="mb-2 text-white font-medium">${summary.total} employees</div>` +
                        '<div class="flex flex-wrap gap-2">' +
                        Object.entries(summary.by_department).map(([d, n]) => `<span class="text-xs px-2 py-1 rounded bg-cyber-dark border border-cyber-border">${escapeHTML(d)}: <span class="text-cyber-neon">${n}</span></span>`).join('') +
                        '</div>';
                }
            }
            if (deptSelect) {
                const current = deptSelect.value;
                deptSelect.innerHTML = '<option value="">All departments (whole roster)</option>' +
                    Object.keys(summary.by_department || {}).map(d => `<option value="${escapeHTML(d)}">${escapeHTML(d)}</option>`).join('');
                deptSelect.value = current;
            }
        } catch (e) {
            if (el) el.innerHTML = '<span class="text-cyber-danger">Failed to load roster.</span>';
        }
    }

    async function loadSimResults() {
        try {
            const res = await apiFetch(`${API_BASE}/simulations/results`);
            const data = await res.json();
            const camps = data.campaigns || [];
            const totals = camps.reduce((a, c) => ({
                sent: a.sent + (c.total || 0), opened: a.opened + (c.opened || 0),
                clicked: a.clicked + (c.clicked || 0), submitted: a.submitted + (c.submitted || 0)
            }), { sent: 0, opened: 0, clicked: 0, submitted: 0 });
            const set = (id, v) => { const el = document.getElementById(id); if (el) el.innerText = v; };
            set('sr-sent', totals.sent); set('sr-opened', totals.opened);
            set('sr-clicked', totals.clicked); set('sr-submitted', totals.submitted);

            const deptBody = document.getElementById('sim-dept-table');
            if (deptBody) {
                const depts = data.departments || [];
                deptBody.innerHTML = depts.length ? depts.map(d => {
                    const rate = d.total ? Math.round((d.clicked / d.total) * 100) : 0;
                    return `<tr class="border-b border-cyber-border/40">
                        <td class="py-2 text-white">${escapeHTML(d.department)}</td>
                        <td class="py-2 text-gray-400">${d.total}</td>
                        <td class="py-2 text-cyber-info">${d.opened}</td>
                        <td class="py-2 text-cyber-warning">${d.clicked}</td>
                        <td class="py-2 text-cyber-danger">${d.submitted}</td>
                        <td class="py-2 font-bold ${rate > 30 ? 'text-cyber-danger' : 'text-cyber-neon'}">${rate}%</td>
                    </tr>`;
                }).join('') : '<tr><td colspan="6" class="py-4 text-center text-gray-500">No results yet.</td></tr>';
            }

            const caught = document.getElementById('sim-caught-list');
            if (caught) {
                const emps = data.employees || [];
                caught.innerHTML = emps.length ? emps.map(e => `
                    <div class="flex justify-between items-center py-2 border-b border-cyber-border/40">
                        <div>
                            <div class="text-white text-sm">${escapeHTML(e.name || e.email)}</div>
                            <div class="text-xs text-gray-500">${escapeHTML(e.email)} · ${escapeHTML(e.department)}</div>
                        </div>
                        <span class="text-xs px-2 py-0.5 rounded ${e.status === 'Submitted Data' ? 'bg-cyber-danger/20 text-cyber-danger' : 'bg-cyber-warning/20 text-cyber-warning'}">${escapeHTML(e.status)}</span>
                    </div>`).join('') : '<div class="text-sm text-gray-500 py-4 text-center">No employees have clicked yet.</div>';
            }
        } catch (e) { /* ignore */ }
    }

    async function setupSimulationTriggers() {
        switchSimMode('AI');

        const rosterForm = document.getElementById('roster-upload-form');
        if (rosterForm) {
            rosterForm.addEventListener('submit', (e) => {
                e.preventDefault();
                uploadRoster(document.getElementById('roster-file'));
            });
        }

        // GoPhish connectivity + automation toggle state.
        const statusEl = document.getElementById('sim-gophish-status');
        const autoToggle = document.getElementById('sim-auto-toggle');
        try {
            const res = await apiFetch(`${API_BASE}/simulations/config`);
            const cfg = await res.json();
            const configured = Boolean(cfg.gophish_api_key || cfg.gophish_key);
            if (statusEl) {
                statusEl.textContent = configured ? 'GoPhish: configured' : 'GoPhish: not configured';
                statusEl.className = 'text-xs px-3 py-1.5 rounded-full border ' + (configured ? 'border-cyber-neon/40 text-cyber-neon' : 'border-cyber-danger/40 text-cyber-danger');
            }
            if (autoToggle) autoToggle.checked = String(cfg.auto_enabled).toLowerCase() === 'true';
        } catch (_) { /* ignore */ }

        if (autoToggle) {
            autoToggle.addEventListener('change', async (e) => {
                try {
                    const res = await apiFetch(`${API_BASE}/settings`, {
                        method: 'POST', headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ sim_auto_enabled: e.target.checked ? 'true' : 'false' })
                    });
                    if (!res.ok) throw new Error('Requires admin role');
                } catch (err) {
                    e.target.checked = !e.target.checked;
                    showCustomAlert('Could not change automation (admin role required).', 'Not Allowed', true);
                }
            });
        }

        loadRoster();
        loadSimResults();
    }

    async function loadPlugins() {
        const el = document.getElementById('plugins-list');
        if (!el) return;
        try {
            const res = await apiFetch(`${API_BASE}/plugins`);
            const plugins = await res.json();
            if (!Array.isArray(plugins) || !plugins.length) {
                el.innerHTML = '<div class="text-sm text-gray-500 py-2">No plugins installed.</div>';
                return;
            }
            el.innerHTML = plugins.map(p => {
                const c = p.counts || {};
                const badge = p.signed
                    ? '<span class="text-[10px] px-2 py-0.5 rounded bg-cyber-neon/20 text-cyber-neon">signed</span>'
                    : '<span class="text-[10px] px-2 py-0.5 rounded bg-cyber-warning/20 text-cyber-warning">unverified</span>';
                return `
                <div class="flex justify-between items-center p-3 rounded bg-cyber-dark border border-cyber-border">
                    <div>
                        <div class="text-white text-sm font-medium">${escapeHTML(p.name)} <span class="text-gray-600 text-xs">v${escapeHTML(String(p.version || ''))}</span> ${badge}</div>
                        <div class="text-xs text-gray-500">${escapeHTML(p.description || '')}</div>
                        <div class="text-[11px] text-gray-600 mt-1">by ${escapeHTML(p.author || 'unknown')} · rules ${c.rules || 0} · intel ${c.intel || 0} · playbooks ${c.playbooks || 0}</div>
                    </div>
                    <div class="flex items-center gap-2">
                        <button onclick="togglePlugin('${escapeHTML(p.plugin_id)}', ${p.enabled ? 'false' : 'true'})" class="text-xs px-2 py-1 rounded border ${p.enabled ? 'border-cyber-neon/40 text-cyber-neon' : 'border-cyber-border text-gray-500'}">${p.enabled ? 'Enabled' : 'Disabled'}</button>
                        <button onclick="removePlugin('${escapeHTML(p.plugin_id)}')" class="text-xs px-2 py-1 rounded text-gray-400 hover:text-cyber-danger">Remove</button>
                    </div>
                </div>`;
            }).join('');
        } catch (e) {
            el.innerHTML = '<div class="text-sm text-cyber-danger py-2">Failed to load plugins.</div>';
        }
    }

    window.togglePlugin = async function (id, enabled) {
        try {
            const res = await apiFetch(`${API_BASE}/plugins/${encodeURIComponent(id)}/toggle`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled })
            });
            if (!res.ok) { const d = await res.json(); throw new Error(d.detail || 'Toggle failed'); }
            loadPlugins();
        } catch (e) { showCustomAlert(e.message, 'Plugin', true); }
    };

    window.removePlugin = async function (id) {
        const ok = await showCustomConfirm(`Remove plugin "${id}" and all content it added?`, 'Remove Plugin');
        if (!ok) return;
        try {
            const res = await apiFetch(`${API_BASE}/plugins/${encodeURIComponent(id)}`, { method: 'DELETE' });
            if (!res.ok) { const d = await res.json(); throw new Error(d.detail || 'Remove failed'); }
            loadPlugins();
        } catch (e) { showCustomAlert(e.message, 'Plugin', true); }
    };

    window.switchSettingsTab = function (name) {
        document.querySelectorAll('#settings-view [data-settings-panel]').forEach(p => {
            p.classList.toggle('hidden', p.dataset.settingsPanel !== name);
        });
        document.querySelectorAll('#settings-view [data-settings-tab]').forEach(t => {
            const active = t.dataset.settingsTab === name;
            t.classList.toggle('bg-cyber-neon/10', active);
            t.classList.toggle('text-cyber-neon', active);
            t.classList.toggle('text-gray-400', !active);
            t.classList.toggle('hover:text-white', !active);
            t.classList.toggle('hover:bg-cyber-panel/50', !active);
        });
    };

    async function setupSettings() {
        const saveBtn = document.getElementById('save-settings-btn');
        const rangeSlider = document.getElementById('setting-ai-threshold');
        const rangeVal = document.getElementById('setting-ai-threshold-val');
        switchSettingsTab('ai');  // initialise the active section

        const pluginForm = document.getElementById('plugin-upload-form');
        if (pluginForm) {
            pluginForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                const fileInput = document.getElementById('plugin-file');
                if (!fileInput || !fileInput.files.length) return;
                const fd = new FormData();
                fd.append('file', fileInput.files[0]);
                try {
                    const res = await apiFetch(`${API_BASE}/plugins/upload`, { method: 'POST', body: fd });
                    const data = await res.json();
                    if (!res.ok) throw new Error(data.detail || 'Install failed');
                    const c = data.installed || {};
                    showCustomAlert(`Installed "${data.name}" — rules ${c.rules || 0}, intel ${c.intel || 0}, playbooks ${c.playbooks || 0}.`, 'Plugin Installed');
                    pluginForm.reset();
                    loadPlugins();
                } catch (err) { showCustomAlert(err.message, 'Install Failed', true); }
            });
        }
        loadPlugins();

        // Dynamic slider value display
        if (rangeSlider && rangeVal) {
            rangeSlider.addEventListener('input', (e) => {
                rangeVal.innerText = `${e.target.value}%`;
            });
        }

        const MASK = '********';
        const setVal = (id, v) => { const el = document.getElementById(id); if (el && v != null) el.value = v; };
        // Secret fields are returned masked by the API — leave them blank with a hint
        // so the user only types when changing them (blank = keep existing on save).
        const setSecretPlaceholder = (id, v) => {
            const el = document.getElementById(id);
            if (el) { el.value = ''; el.placeholder = (v === MASK) ? '•••••••• (saved — leave blank to keep)' : el.placeholder; }
        };

        // Fetch settings on load
        try {
            const res = await apiFetch(`${API_BASE}/settings`);
            if (res.ok) {
                const data = await res.json();
                setVal('setting-imap-server', data.imap_server);
                setVal('setting-imap-user', data.imap_user);
                setSecretPlaceholder('setting-imap-pass', data.imap_pass);
                setVal('setting-ai-provider', data.ai_provider || 'ollama');
                setVal('setting-ai-model', data.ai_model);
                setVal('setting-ai-base', data.ai_base_url);
                setSecretPlaceholder('setting-ai-key', data.ai_api_key);
                if (data.ai_threshold) {
                    document.getElementById('setting-ai-threshold').value = data.ai_threshold;
                    if (rangeVal) rangeVal.innerText = `${data.ai_threshold}%`;
                }
                setVal('setting-gophish-url', data.gophish_url);
                setSecretPlaceholder('setting-gophish-key', data.gophish_key);
                setVal('setting-siem-url', data.siem_webhook_url);
                setSecretPlaceholder('setting-siem-key', data.siem_api_key);
                setVal('setting-siem-auth-header', data.siem_auth_header);
                setVal('setting-siem-auth-prefix', data.siem_auth_prefix);
                setVal('setting-siem-format', data.siem_format || 'raw');
            }
        } catch (e) {
            console.error("Failed to load settings:", e);
        }

        if (saveBtn) {
            saveBtn.addEventListener('click', async () => {
                const originalText = saveBtn.innerText;
                saveBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-1"></i> Saving...';
                saveBtn.disabled = true;

                const val = (id) => (document.getElementById(id)?.value ?? '').trim();
                const payload = {
                    imap_server: val('setting-imap-server'),
                    imap_user: val('setting-imap-user'),
                    ai_provider: val('setting-ai-provider'),
                    ai_model: val('setting-ai-model'),
                    ai_base_url: val('setting-ai-base'),
                    ai_threshold: document.getElementById('setting-ai-threshold').value,
                    gophish_url: val('setting-gophish-url'),
                    siem_webhook_url: val('setting-siem-url'),
                    siem_auth_header: val('setting-siem-auth-header'),
                    siem_auth_prefix: val('setting-siem-auth-prefix'),
                    siem_format: val('setting-siem-format')
                };
                // Only send secrets when the user actually typed one (blank = keep existing).
                const imapPass = val('setting-imap-pass'); if (imapPass) payload.imap_pass = imapPass;
                const aiKey = val('setting-ai-key'); if (aiKey) payload.ai_api_key = aiKey;
                const gophishKey = val('setting-gophish-key'); if (gophishKey) payload.gophish_key = gophishKey;
                const siemKey = val('setting-siem-key'); if (siemKey) payload.siem_api_key = siemKey;

                try {
                    const res = await apiFetch(`${API_BASE}/settings`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload)
                    });
                    if (res.ok) {
                        saveBtn.innerHTML = '<i class="fa-solid fa-check mr-1"></i> Saved Successfully';
                        saveBtn.classList.replace('bg-cyber-neon', 'bg-cyber-info');
                        showCustomAlert("Settings have been successfully saved.", "Configuration Saved", false);
                        setTimeout(() => {
                            saveBtn.innerText = originalText;
                            saveBtn.classList.replace('bg-cyber-info', 'bg-cyber-neon');
                            saveBtn.disabled = false;
                        }, 2000);
                    }
                } catch (err) {
                    showCustomAlert('Error saving settings. Is the backend running?', 'Failure', true);
                    saveBtn.innerText = originalText;
                    saveBtn.disabled = false;
                }
            });
        }
    }


    function initDashboardCharts(currentRisk, labels, dataSet) {
        Chart.defaults.color = '#9ca3af';
        Chart.defaults.font.family = 'Inter';

        // Destroy existing to prevent overlap on reload
        if (chartInstances.gauge) chartInstances.gauge.destroy();
        if (chartInstances.trend) chartInstances.trend.destroy();

        // Very simple implementation of a half-doughnut gauge
        const ctxGauge = document.getElementById('riskGauge');
        if (ctxGauge) {
            chartInstances.gauge = new Chart(ctxGauge, {
                type: 'doughnut',
                data: {
                    datasets: [{
                        data: [currentRisk, 100 - currentRisk],
                        backgroundColor: [currentRisk > 60 ? '#ff3366' : (currentRisk > 30 ? '#ffb84d' : '#00ff9d'), '#1f1f2e'],
                        borderWidth: 0,
                        circumference: 180,
                        rotation: -90
                    }]
                },
                options: {
                    cutout: '80%',
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { tooltip: { enabled: false }, legend: { display: false } },
                    animation: { animateRotate: true }
                }
            });
        }

        const ctxTrend = document.getElementById('trendChart');
        if (ctxTrend && labels && dataSet) {
            chartInstances.trend = new Chart(ctxTrend, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Detected Phishing Attempts',
                        data: dataSet,
                        borderColor: '#00ff9d',
                        backgroundColor: 'rgba(0, 255, 157, 0.1)',
                        borderWidth: 2,
                        tension: 0.4,
                        fill: true,
                        pointBackgroundColor: '#13131a',
                        pointBorderColor: '#00ff9d'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: { grid: { color: '#1f1f2e' }, beginAtZero: true },
                        x: { grid: { display: false } }
                    },
                    plugins: { legend: { display: false } }
                }
            });
        }
    }

    async function setupFrameworkCenter() {
        const refreshBtn = document.getElementById('refresh-framework-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', loadFrameworkCenter);
        }
        await loadFrameworkCenter();
    }

    async function loadFrameworkCenter() {
        try {
            const [statusRes, policiesRes, casesRes, auditRes, iocsRes, rulesRes, playbooksRes] = await Promise.all([
                apiFetch(`${API_BASE}/framework/status`),
                apiFetch(`${API_BASE}/policies`),
                apiFetch(`${API_BASE}/cases`),
                apiFetch(`${API_BASE}/audit-log?limit=50`),
                apiFetch(`${API_BASE}/iocs?limit=50`),
                apiFetch(`${API_BASE}/detection-rules`),
                apiFetch(`${API_BASE}/playbooks`)
            ]);
            const status = await statusRes.json();
            const policies = await policiesRes.json();
            const cases = await casesRes.json();
            const auditRows = await auditRes.json();
            const iocs = await iocsRes.json();
            const rules = await rulesRes.json();
            const playbooks = await playbooksRes.json();

            Object.entries(status.counts || {}).forEach(([key, value]) => {
                const el = document.querySelector(`[data-fw-count="${key}"]`);
                if (el) el.innerText = Number(value || 0).toLocaleString();
            });

            const policiesBody = document.getElementById('framework-policies-table');
            if (policiesBody) {
                policiesBody.innerHTML = policies.length ? policies.map(policy => `
                    <tr class="border-b border-cyber-border/50">
                        <td class="py-3 text-white">${escapeHTML(policy.name)}</td>
                        <td class="py-3 text-cyber-info">${escapeHTML(policy.action)}</td>
                        <td class="py-3 text-gray-300">${escapeHTML(policy.severity)}</td>
                        <td class="py-3">${policy.enabled ? '<span class="text-cyber-neon">Yes</span>' : '<span class="text-gray-500">No</span>'}</td>
                    </tr>
                `).join('') : '<tr><td colspan="4" class="py-6 text-center text-gray-500">No policies configured.</td></tr>';
            }

            const casesBody = document.getElementById('framework-cases-table');
            if (casesBody) {
                casesBody.innerHTML = cases.length ? cases.map(item => `
                    <tr class="border-b border-cyber-border/50">
                        <td class="py-3">
                            <div class="text-white">${escapeHTML(item.title)}</div>
                            <div class="text-xs text-gray-500">${escapeHTML(item.sender || '')}</div>
                        </td>
                        <td class="py-3 text-cyber-warning">${escapeHTML(item.severity)}</td>
                        <td class="py-3 text-gray-300">${escapeHTML(item.status)}</td>
                        <td class="py-3 text-cyber-danger">${Number.parseInt(item.risk_score, 10) || 0}%</td>
                    </tr>
                `).join('') : '<tr><td colspan="4" class="py-6 text-center text-gray-500">No open cases yet.</td></tr>';
            }

            const auditBody = document.getElementById('framework-audit-table');
            if (auditBody) {
                auditBody.innerHTML = auditRows.length ? auditRows.map(row => `
                    <tr class="border-b border-cyber-border/50">
                        <td class="py-3 text-gray-500">${escapeHTML(new Date(row.created_at + 'Z').toLocaleString())}</td>
                        <td class="py-3 text-gray-300">${escapeHTML(row.actor)}</td>
                        <td class="py-3 text-cyber-neon">${escapeHTML(row.action)}</td>
                        <td class="py-3 text-gray-400">${escapeHTML(row.target_type)} #${escapeHTML(row.target_id)}</td>
                        <td class="py-3 text-gray-500">${escapeHTML(row.details)}</td>
                    </tr>
                `).join('') : '<tr><td colspan="5" class="py-6 text-center text-gray-500">No audit events yet.</td></tr>';
            }

            const iocsBody = document.getElementById('framework-iocs-table');
            if (iocsBody) {
                iocsBody.innerHTML = iocs.length ? iocs.map(row => `
                    <tr class="border-b border-cyber-border/50">
                        <td class="py-3 text-cyber-info">${escapeHTML(row.type)}</td>
                        <td class="py-3 text-gray-300 break-all">${escapeHTML(row.value)}</td>
                        <td class="py-3 text-cyber-neon">${Number.parseInt(row.confidence, 10) || 0}%</td>
                    </tr>
                `).join('') : '<tr><td colspan="3" class="py-6 text-center text-gray-500">No IOCs extracted yet.</td></tr>';
            }

            const rulesBody = document.getElementById('framework-rules-table');
            if (rulesBody) {
                rulesBody.innerHTML = rules.length ? rules.map(rule => `
                    <tr class="border-b border-cyber-border/50">
                        <td class="py-3">
                            <div class="text-white">${escapeHTML(rule.name)}</div>
                            <div class="text-xs text-gray-500">${escapeHTML(rule.rule_id)}</div>
                        </td>
                        <td class="py-3 text-cyber-warning">${escapeHTML(rule.severity)}</td>
                        <td class="py-3">${rule.enabled ? '<span class="text-cyber-neon">Yes</span>' : '<span class="text-gray-500">No</span>'}</td>
                    </tr>
                `).join('') : '<tr><td colspan="3" class="py-6 text-center text-gray-500">No detection rules loaded.</td></tr>';
            }

            const playbookList = document.getElementById('framework-playbooks-list');
            if (playbookList) {
                playbookList.innerHTML = playbooks.length ? playbooks.map(playbook => `
                    <div class="bg-cyber-dark border border-cyber-border rounded p-3">
                        <div class="flex justify-between items-center">
                            <div class="text-white font-medium">${escapeHTML(playbook.name)}</div>
                            <div class="text-xs ${playbook.enabled ? 'text-cyber-neon' : 'text-gray-500'}">${playbook.enabled ? 'Enabled' : 'Disabled'}</div>
                        </div>
                        <div class="text-xs text-cyber-info mt-1">Trigger: ${escapeHTML(playbook.trigger_action)}</div>
                        <div class="text-xs text-gray-500 mt-2">${(playbook.steps || []).length} steps</div>
                    </div>
                `).join('') : '<div class="text-sm text-gray-500">No playbooks configured.</div>';
            }
        } catch (error) {
            console.error("Failed to load framework center:", error);
            showCustomAlert("Failed to load framework center.", "Framework Error", true);
        }
    }

    async function initAnalyticsCharts() {
        if (chartInstances.pie) chartInstances.pie.destroy();

        try {
            const res = await apiFetch(`${API_BASE}/analytics`);
            const data = await res.json();

            // Render Pie Chart
            const ctxPie = document.getElementById('threatPieChart');
            if (ctxPie && data.threat_distribution) {
                chartInstances.pie = new Chart(ctxPie, {
                    type: 'pie',
                    data: {
                        labels: data.threat_distribution.labels,
                        datasets: [{
                            data: data.threat_distribution.data,
                            backgroundColor: ['#ff3366', '#ffb84d', '#00ccff', '#1f1f2e'],
                            borderWidth: 1,
                            borderColor: '#0a0a0f'
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { position: 'bottom' } }
                    }
                });
            }

            // Render Department Table
            const deptContainer = document.querySelector('#analytics-view .space-y-4');
            if (deptContainer && data.departments) {
                deptContainer.innerHTML = data.departments.map(d => {
                    const colorMap = {
                        'High': 'text-cyber-danger',
                        'Med': 'text-cyber-warning',
                        'Low': 'text-cyber-neon'
                    };
                    const borderMap = {
                        'High': 'border-cyber-danger',
                        'Med': 'border-cyber-warning',
                        'Low': 'border-cyber-neon'
                    };
                    const riskLevel = ['High', 'Med', 'Low'].includes(d.risk_level) ? d.risk_level : 'Low';
                    const name = escapeHTML(d.name);
                    const incidents = Number.parseInt(d.incidents, 10) || 0;
                    return `
                        <div class="bg-cyber-dark p-3 rounded flex justify-between items-center border-l-4 ${borderMap[riskLevel]}">
                            <div>
                                <div class="text-white font-medium">${name}</div>
                                <div class="text-xs text-gray-500">${incidents} incidents this week</div>
                            </div>
                            <span class="${colorMap[riskLevel]} font-bold text-lg">${riskLevel}</span>
                        </div>
                    `;
                }).join('');
            }
        } catch (error) {
            console.error("Failed to load analytics:", error);
        }
    }
});
