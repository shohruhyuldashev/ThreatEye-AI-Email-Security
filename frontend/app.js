// Navigation and SPA Logic
document.addEventListener('DOMContentLoaded', () => {
    const navButtons = document.querySelectorAll('.nav-btn');
    const viewContainer = document.getElementById('view-container');

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
                                <h3 class="text-3xl font-bold text-white">12,458</h3>
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
                                <h3 class="text-3xl font-bold text-white">142</h3>
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
                                <h3 class="text-3xl font-bold text-white">47</h3>
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
                                <h3 class="text-3xl font-bold text-white">3</h3>
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
                        <div class="flex justify-between items-center mb-4">
                            <h3 class="text-lg font-semibold text-white">7-Day Threat Trend</h3>
                            <select class="bg-cyber-dark border border-cyber-border text-xs rounded px-2 py-1 outline-none">
                                <option>Last 7 Days</option>
                                <option>Last 30 Days</option>
                            </select>
                        </div>
                        <div class="h-64 w-full relative">
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

                <div class="glass-card rounded-xl overflow-hidden border border-cyber-border">
                    <div class="overflow-x-auto min-h-[500px]">
                        <table class="w-full text-left">
                            <thead class="bg-cyber-dark/50 text-xs text-gray-400 uppercase tracking-wider">
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
                                <!-- Standard mock row 1 -->
                                <tr class="cyber-table-row group cursor-pointer">
                                    <td class="py-4 px-6 text-gray-400">10:42 AM</td>
                                    <td class="py-4 px-6">
                                        <div class="font-medium text-white">hr-update@miicrosoft.com</div>
                                        <div class="text-xs text-gray-500">External</div>
                                    </td>
                                    <td class="py-4 px-6 text-gray-300">URGENT: Mandatory Compliance Review</td>
                                    <td class="py-4 px-6">
                                        <div class="flex items-center"><span class="w-2 h-2 rounded-full bg-cyber-danger mr-2"></span>98% (Typosquatting)</div>
                                    </td>
                                    <td class="py-4 px-6">
                                        <div class="w-full bg-cyber-dark rounded-full h-1.5 mt-2">
                                            <div class="bg-cyber-danger h-1.5 rounded-full" style="width: 95%"></div>
                                        </div>
                                        <span class="text-xs text-cyber-danger font-medium">95%</span>
                                    </td>
                                    <td class="py-4 px-6">
                                        <span class="bg-cyber-danger/20 text-cyber-danger px-2.5 py-1 rounded border border-cyber-danger/30 text-xs">Quarantined</span>
                                    </td>
                                    <td class="py-4 px-6 text-right">
                                        <button class="text-gray-500 hover:text-cyber-neon transition-colors"><i class="fa-solid fa-expand"></i></button>
                                    </td>
                                </tr>
                                <!-- Standard mock row 2 -->
                                <tr class="cyber-table-row group cursor-pointer">
                                    <td class="py-4 px-6 text-gray-400">10:38 AM</td>
                                    <td class="py-4 px-6">
                                        <div class="font-medium text-white">john.doe@internal.com</div>
                                        <div class="text-xs text-gray-500">Internal</div>
                                    </td>
                                    <td class="py-4 px-6 text-gray-300">Project Alpha status report</td>
                                    <td class="py-4 px-6">
                                        <div class="flex items-center"><span class="w-2 h-2 rounded-full bg-cyber-neon mr-2"></span>0%</div>
                                    </td>
                                    <td class="py-4 px-6">
                                        <div class="w-full bg-cyber-dark rounded-full h-1.5 mt-2">
                                            <div class="bg-cyber-neon h-1.5 rounded-full" style="width: 5%"></div>
                                        </div>
                                        <span class="text-xs text-cyber-neon font-medium">5%</span>
                                    </td>
                                    <td class="py-4 px-6">
                                        <span class="bg-cyber-neon/10 text-cyber-neon px-2.5 py-1 rounded border border-cyber-neon/20 text-xs">Allowed</span>
                                    </td>
                                    <td class="py-4 px-6 text-right">
                                        <button class="text-gray-500 hover:text-cyber-neon transition-colors"><i class="fa-solid fa-expand"></i></button>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
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
                        <div class="max-h-[600px] overflow-y-auto custom-scrollbar">
                            <table class="w-full text-left">
                                <thead class="text-xs text-gray-500 uppercase bg-cyber-dark/80">
                                    <tr>
                                        <th class="p-4 font-medium">Recipient</th>
                                        <th class="p-4 font-medium">Threat Level</th>
                                        <th class="p-4 font-medium">AI Reason</th>
                                        <th class="p-4 font-medium text-right">Actions</th>
                                    </tr>
                                </thead>
                                <tbody class="text-sm divide-y divide-cyber-border/50">
                                    <tr class="cyber-table-row hover:bg-cyber-panel">
                                        <td class="p-4">
                                            <div class="text-white">finance@corp.com</div>
                                            <div class="text-xs text-gray-500">From: ceo-alert@c0rp.com</div>
                                        </td>
                                        <td class="p-4"><span class="text-cyber-danger font-bold">99%</span></td>
                                        <td class="p-4 text-xs text-gray-400 max-w-[200px] truncate">Sender domain typosquatting detected. Urgency triggers found.</td>
                                        <td class="p-4 text-right space-x-2">
                                            <button class="px-3 py-1 bg-cyber-panel border border-cyber-info/50 text-cyber-info rounded hover:bg-cyber-info/10 transition-colors text-xs">Review</button>
                                            <button class="px-3 py-1 bg-cyber-panel border border-cyber-danger/50 text-cyber-danger rounded hover:bg-cyber-danger/10 transition-colors text-xs">Delete</button>
                                        </td>
                                    </tr>
                                    <tr class="cyber-table-row hover:bg-cyber-panel cursor-pointer bg-cyber-panel/50 border-l-2 border-cyber-neon">
                                        <td class="p-4">
                                            <div class="text-white">marketing@corp.com</div>
                                            <div class="text-xs text-gray-500">From: invoice@vendor.com</div>
                                        </td>
                                        <td class="p-4"><span class="text-cyber-warning font-bold">75%</span></td>
                                        <td class="p-4 text-xs text-gray-400 max-w-[200px] truncate">Suspicious attachment format. Possible macro payload.</td>
                                        <td class="p-4 text-right space-x-2">
                                            <button class="px-3 py-1 bg-cyber-panel border border-cyber-info/50 text-cyber-info rounded hover:bg-cyber-info/10 transition-colors text-xs">Review</button>
                                            <button class="px-3 py-1 bg-cyber-panel border border-cyber-danger/50 text-cyber-danger rounded hover:bg-cyber-danger/10 transition-colors text-xs">Delete</button>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                    
                    <!-- Detail View -->
                    <div class="glass-card rounded-xl border border-cyber-border p-5 flex flex-col h-[600px]">
                        <h3 class="font-medium text-white mb-4 border-b border-cyber-border/50 pb-2">Threat Detail</h3>
                        <div class="flex-1 overflow-y-auto pr-2 custom-scrollbar space-y-4">
                            <div>
                                <label class="text-xs text-gray-500 uppercase tracking-wider block mb-1">Subject</label>
                                <div class="text-white font-medium bg-cyber-dark p-2 rounded border border-cyber-border">Invoice #884920 payment overdue</div>
                            </div>
                            <div>
                                <label class="text-xs text-gray-500 uppercase tracking-wider block mb-1">Headers</label>
                                <div class="text-xs text-gray-400 font-mono bg-cyber-dark p-2 rounded border border-cyber-border break-all">
                                    Return-Path: &lt;invoice@vendor.com&gt;<br>
                                    Received: from mail.vendor.com (unknown [192.168.1.5])
                                </div>
                            </div>
                            <div>
                                <label class="text-xs text-gray-500 uppercase tracking-wider block mb-1">AI Analysis Log</label>
                                <div class="text-sm text-gray-300 bg-cyber-danger/10 border border-cyber-danger/30 p-3 rounded">
                                    <i class="fa-solid fa-robot text-cyber-danger mr-2"></i> 
                                    Email contains manipulative language requesting urgent payment. The attached link redirects to an unknown IP rather than a recognized payment gateway. Risk score evaluated at 75%.
                                </div>
                            </div>
                        </div>
                        <div class="mt-4 pt-4 border-t border-cyber-border space-y-2">
                            <button class="w-full py-2 bg-cyber-danger/80 hover:bg-cyber-danger text-white rounded font-medium transition-colors shadow-lg shadow-cyber-danger/20">Delete Permanently</button>
                            <button class="w-full py-2 bg-transparent border border-cyber-border text-gray-400 hover:text-white hover:border-gray-500 rounded font-medium transition-colors">Release to Inbox (Admin)</button>
                        </div>
                    </div>
                </div>
            </div>
        `,
        simulation: `
            <div class="view-section" id="simulation-view">
                <div class="flex justify-between items-center mb-6">
                    <div>
                        <h2 class="text-2xl font-bold text-white">Simulation Control Panel</h2>
                        <p class="text-sm text-gray-400 mt-1">Configure automated AI phishing tests to evaluate employee readiness.</p>
                    </div>
                </div>

                <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
                    <!-- Configurator -->
                    <div class="glass-card rounded-xl p-6">
                        <!-- Mode Selector Tabs -->
                        <div class="flex bg-cyber-dark rounded-lg p-1 mb-6">
                            <button type="button" id="sim-mode-manual" class="flex-1 py-1.5 text-sm font-medium rounded-md bg-cyber-neon/20 text-cyber-neon transition-colors" onclick="switchSimMode('Manual')">Manual Config</button>
                            <button type="button" id="sim-mode-ai" class="flex-1 py-1.5 text-sm font-medium rounded-md text-gray-400 hover:text-white transition-colors" onclick="switchSimMode('AI')">AI Automated</button>
                        </div>

                        <div class="flex items-center justify-between mb-6 pb-4 border-b border-cyber-border">
                            <h3 class="text-lg font-semibold text-white">Simulation Engine</h3>
                            <!-- Toggle switch -->
                            <div class="relative inline-block w-12 h-6 align-middle select-none transition duration-200 ease-in" title="Delay Mode">
                                <input type="checkbox" name="toggle" id="delayToggle" class="toggle-checkbox absolute block w-6 h-6 rounded-full bg-white border-4 appearance-none cursor-pointer border-gray-600 transition-all z-10" checked/>
                                <label for="delayToggle" class="toggle-label block overflow-hidden h-6 rounded-full bg-cyber-neon cursor-pointer transition-colors"></label>
                            </div>
                        </div>

                        <form class="space-y-6" id="sim-config-form">
                            <!-- AI Mode Specifics -->
                            <div id="sim-ai-settings" class="hidden space-y-6">
                                <div>
                                    <label class="block text-sm font-medium text-gray-300 mb-2">Schedule Running Days</label>
                                    <div class="flex flex-wrap gap-2">
                                        <button type="button" class="px-3 py-1.5 rounded bg-cyber-panel border border-cyber-border text-gray-400 text-sm hover:border-cyber-neon hover:text-white transition-colors">Mon</button>
                                        <button type="button" class="px-3 py-1.5 rounded bg-cyber-neon/20 border border-cyber-neon text-cyber-neon font-medium text-sm transition-colors">Tue</button>
                                        <button type="button" class="px-3 py-1.5 rounded bg-cyber-panel border border-cyber-border text-gray-400 text-sm hover:border-cyber-neon hover:text-white transition-colors">Wed</button>
                                        <button type="button" class="px-3 py-1.5 rounded bg-cyber-neon/20 border border-cyber-neon text-cyber-neon font-medium text-sm transition-colors">Thu</button>
                                        <button type="button" class="px-3 py-1.5 rounded bg-cyber-panel border border-cyber-border text-gray-400 text-sm hover:border-cyber-neon hover:text-white transition-colors">Fri</button>
                                    </div>
                                </div>
    
                                <div>
                                    <label class="block text-sm font-medium text-gray-300 mb-2">Target Audience</label>
                                    <select id="sim-target-group" class="cyber-input w-full rounded-lg px-4 py-2 text-sm text-gray-300">
                                        <option value="random">Random (Entire Company)</option>
                                        <option value="new">New Employees Only</option>
                                        <option value="high_risk">High Risk Users</option>
                                        <option value="sales">Sales Department</option>
                                    </select>
                                </div>
                            </div>

                            <!-- Manual Mode Specifics -->
                            <div id="sim-manual-settings" class="space-y-6">
                                <div>
                                    <label class="block text-sm font-medium text-gray-300 mb-2">Target Emails (.txt or .csv)</label>
                                    <input type="file" id="sim-target-file" accept=".txt,.csv" class="cyber-input w-full rounded-lg px-4 py-2 text-sm text-gray-300 file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:text-sm file:font-semibold file:bg-cyber-neon/20 file:text-cyber-neon hover:file:bg-cyber-neon/30 cursor-pointer">
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-300 mb-2">Scheduled Execution (Optional)</label>
                                    <input type="datetime-local" id="sim-target-date" class="cyber-input w-full rounded-lg px-4 py-2 text-sm text-gray-300">
                                </div>
                            </div>

                            <!-- Global settings for both -->
                            <div>
                                <div class="flex justify-between mb-2">
                                    <label class="block text-sm font-medium text-gray-300">AI Aggressiveness</label>
                                    <span class="text-sm text-cyber-warning font-medium">Medium</span>
                                </div>
                                <input type="range" id="sim-aggressiveness" class="w-full h-2 bg-cyber-dark rounded-lg appearance-none cursor-pointer accent-cyber-warning" min="1" max="3" value="2">
                                <div class="flex justify-between text-xs text-gray-500 mt-1">
                                    <span>Obvious (Low)</span>
                                    <span>Sophisticated (High)</span>
                                </div>
                            </div>
                            
                            <button type="button" onclick="saveSimulationConfig()" class="w-full py-2.5 bg-cyber-panel hover:bg-cyber-border border border-cyber-neon text-cyber-neon font-medium rounded-lg transition-colors mt-4">
                                Save Configuration
                            </button>
                        </form>
                    </div>

                    <!-- Next Run Info & Stats -->
                    <div class="space-y-6">
                        <div class="glass-card rounded-xl p-6 border-l-4 border-l-cyber-info">
                            <h3 class="text-gray-400 font-medium text-sm mb-1 uppercase tracking-wide">Next Scheduled Run</h3>
                            <div class="text-2xl font-bold text-white mb-2">Tomorrow, 10:30 AM</div>
                            <p class="text-sm text-gray-500">Targeting: Random subset (15 employees). Engine: LLaMA 3.</p>
                            <button class="mt-4 px-4 py-1.5 bg-cyber-panel border border-gray-600 hover:border-white text-sm text-white rounded transition-colors" onclick="triggerSimulation()">Trigger Now <i class="fa-solid fa-play ml-1"></i></button>
                        </div>

                        <div class="glass-card rounded-xl p-6">
                            <h3 class="text-lg font-semibold text-white mb-4">Last Campaign Results</h3>
                            <div class="space-y-4">
                                <div>
                                    <div class="flex justify-between text-sm mb-1">
                                        <span class="text-gray-300">Emails Sent</span>
                                        <span class="text-white font-medium">100</span>
                                    </div>
                                    <div class="w-full bg-cyber-dark rounded-full h-1.5"><div class="bg-gray-500 h-1.5 rounded-full" style="width: 100%"></div></div>
                                </div>
                                <div>
                                    <div class="flex justify-between text-sm mb-1">
                                        <span class="text-gray-300">Opened</span>
                                        <span class="text-cyber-info font-medium">45</span>
                                    </div>
                                    <div class="w-full bg-cyber-dark rounded-full h-1.5"><div class="bg-cyber-info h-1.5 rounded-full" style="width: 45%"></div></div>
                                </div>
                                <div>
                                    <div class="flex justify-between text-sm mb-1">
                                        <span class="text-gray-300">Clicked Link</span>
                                        <span class="text-cyber-warning font-medium">12</span>
                                    </div>
                                    <div class="w-full bg-cyber-dark rounded-full h-1.5"><div class="bg-cyber-warning h-1.5 rounded-full" style="width: 12%"></div></div>
                                </div>
                                <div>
                                    <div class="flex justify-between text-sm mb-1">
                                        <span class="text-gray-300">Submitted Data</span>
                                        <span class="text-cyber-danger font-medium">3</span>
                                    </div>
                                    <div class="w-full bg-cyber-dark rounded-full h-1.5"><div class="bg-cyber-danger h-1.5 rounded-full" style="width: 3%"></div></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `,
        urlanalyzer: `
            <div class="view-section" id="urlanalyzer-view">
                 <div class="max-w-4xl mx-auto mt-10 text-center">
                    <i class="fa-solid fa-link text-4xl text-cyber-neon mb-4"></i>
                    <h2 class="text-3xl font-bold text-white mb-2">Deep URL Threat Analyzer</h2>
                    <p class="text-gray-400 mb-8">Scan any URL for typosquatting, hidden redirections, and known malicious domains using the AI Engine.</p>
                    
                    <div class="relative max-w-2xl mx-auto flex mb-12">
                        <div class="absolute inset-y-0 left-0 flex items-center pl-4 pointer-events-none">
                            <i class="fa-solid fa-globe text-gray-500 text-lg"></i>
                        </div>
                        <input type="text" placeholder="https://example-login.com/auth..." class="cyber-input w-full rounded-l-xl pl-12 pr-4 py-4 text-lg focus:shadow-[0_0_20px_rgba(0,255,157,0.2)]">
                        <button class="bg-cyber-neon text-black font-bold px-8 py-4 rounded-r-xl hover:bg-[#00cc7a] transition-colors whitespace-nowrap">
                            Scan URL
                        </button>
                    </div>

                    <!-- Scan Results (Mock) -->
                    <div class="glass-card rounded-xl text-left border-t-4 border-t-cyber-danger overflow-hidden text-sm">
                        <div class="bg-cyber-dark/50 p-4 border-b border-cyber-border flex justify-between items-center">
                            <span class="font-mono text-gray-300">https://micosoft-login-secure.com/auth</span>
                            <span class="bg-cyber-danger/20 text-cyber-danger px-3 py-1 rounded-full font-bold">98% MALICIOUS</span>
                        </div>
                        <div class="p-6 grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div>
                                <h4 class="text-white font-medium mb-3 border-b border-cyber-border pb-1">AI Findings</h4>
                                <ul class="space-y-2 text-gray-400">
                                    <li><i class="fa-solid fa-xmark text-cyber-danger mr-2"></i> <strong>Typosquatting:</strong> "micosoft" targets "microsoft"</li>
                                    <li><i class="fa-solid fa-xmark text-cyber-danger mr-2"></i> <strong>Domain Age:</strong> Registered 2 days ago</li>
                                    <li><i class="fa-solid fa-check text-cyber-neon mr-2"></i> <strong>SSL:</strong> Valid (Let's Encrypt)</li>
                                </ul>
                            </div>
                            <div>
                                <h4 class="text-white font-medium mb-3 border-b border-cyber-border pb-1">Resolution Strategy</h4>
                                <p class="text-gray-400 mb-2">The AI assesses this domain is specifically engineered for credential harvesting. Automatically blocking at DNS level via firewall.</p>
                                <button class="text-xs border border-cyber-danger text-cyber-danger px-3 py-1 rounded hover:bg-cyber-danger/10 transition-colors">Add to Global Blocklist</button>
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
                        <div class="space-y-4">
                            <div class="bg-cyber-dark p-3 rounded flex justify-between items-center border-l-4 border-cyber-danger">
                                <div>
                                    <div class="text-white font-medium">Sales</div>
                                    <div class="text-xs text-gray-500">24 incidents this week</div>
                                </div>
                                <span class="text-cyber-danger font-bold text-lg">High</span>
                            </div>
                            <div class="bg-cyber-dark p-3 rounded flex justify-between items-center border-l-4 border-cyber-warning">
                                <div>
                                    <div class="text-white font-medium">Finance</div>
                                    <div class="text-xs text-gray-500">12 incidents this week</div>
                                </div>
                                <span class="text-cyber-warning font-bold text-lg">Med</span>
                            </div>
                            <div class="bg-cyber-dark p-3 rounded flex justify-between items-center border-l-4 border-cyber-neon">
                                <div>
                                    <div class="text-white font-medium">Engineering</div>
                                    <div class="text-xs text-gray-500">2 incidents this week</div>
                                </div>
                                <span class="text-cyber-neon font-bold text-lg">Low</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `,
        settings: `
            <div class="view-section" id="settings-view">
                <h2 class="text-2xl font-bold text-white mb-6">System Configuration</h2>
                
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-8 max-w-5xl">
                    <!-- Service Configs -->
                    <div class="space-y-6">
                        <div class="glass-card rounded-xl p-6">
                            <h3 class="text-lg font-medium text-white mb-4 flex items-center"><i class="fa-solid fa-server mr-2 text-cyber-info"></i> IMAP / Email Interception</h3>
                            <div class="space-y-4">
                                <div>
                                    <label class="block text-xs text-gray-400 uppercase tracking-widest mb-1">IMAP Server URL</label>
                                    <input type="text" id="setting-imap-server" class="cyber-input w-full p-2 rounded text-sm" placeholder="imap.corporate.com">
                                </div>
                                <div class="grid grid-cols-2 gap-4">
                                    <div>
                                        <label class="block text-xs text-gray-400 uppercase tracking-widest mb-1">Username</label>
                                        <input type="text" id="setting-imap-user" class="cyber-input w-full p-2 rounded text-sm" placeholder="security_bot@corp.com">
                                    </div>
                                    <div>
                                        <label class="block text-xs text-gray-400 uppercase tracking-widest mb-1">Password</label>
                                        <input type="password" id="setting-imap-pass" class="cyber-input w-full p-2 rounded text-sm" placeholder="********">
                                    </div>
                                </div>
                                <button type="button" onclick="testImapConnection()" class="mt-2 text-xs bg-cyber-panel border border-cyber-border hover:border-cyber-info text-white px-3 py-1.5 rounded transition-colors">Test Connection</button>
                            </div>
                        </div>

                        <div class="glass-card rounded-xl p-6">
                            <h3 class="text-lg font-medium text-white mb-4 flex items-center"><i class="fa-solid fa-brain mr-2 text-cyber-neon"></i> AI Engine Settings</h3>
                            <div class="space-y-4">
                                <div>
                                    <label class="block text-xs text-gray-400 uppercase tracking-widest mb-1">Active Model</label>
                                    <select id="setting-ai-model" class="cyber-input w-full p-2 rounded text-sm">
                                        <option value="phi3">Phi3 (Local Container)</option>
                                        <option value="llama3">LLaMA3 (Local Container)</option>
                                        <option value="gpt-4o-mini">gpt-4o-mini (OpenAI Cloud)</option>
                                    </select>
                                </div>
                                <div>
                                    <div class="flex justify-between mb-1">
                                        <label class="block text-xs text-gray-400 uppercase tracking-widest">Auto-Quarantine Threshold</label>
                                        <span id="setting-ai-threshold-val" class="text-xs text-cyber-danger">70%</span>
                                    </div>
                                    <input type="range" id="setting-ai-threshold" class="w-full h-1 bg-cyber-border rounded appearance-none cursor-pointer accent-cyber-danger" min="1" max="100" value="70">
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Roles and API -->
                    <div class="space-y-6">
                        <div class="glass-card rounded-xl p-6">
                            <h3 class="text-lg font-medium text-white mb-4 flex items-center"><i class="fa-solid fa-key mr-2 text-cyber-warning"></i> GoPhish Integration</h3>
                            <div class="space-y-4">
                                <div>
                                    <label class="block text-xs text-gray-400 uppercase tracking-widest mb-1">GoPhish URL</label>
                                    <input type="text" id="setting-gophish-url" class="cyber-input w-full p-2 rounded text-sm" placeholder="http://gophish:3333">
                                </div>
                                <div>
                                    <label class="block text-xs text-gray-400 uppercase tracking-widest mb-1">Admin API Key</label>
                                    <input type="password" id="setting-gophish-key" class="cyber-input w-full p-2 rounded text-sm" placeholder="********************************">
                                </div>
                            </div>
                        </div>

                        <div class="flex justify-end mt-4">
                            <button id="save-settings-btn" class="bg-cyber-neon text-black font-medium px-6 py-2 rounded shadow-[0_0_15px_rgba(0,255,157,0.3)] hover:bg-[#00cc7a] transition-all">Save All Configurations</button>
                        </div>
                    </div>
                </div>
            </div>
        `
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

                // Make the Quarantine card clickable
                const quarantineCard = document.querySelector('#dashboard-view .border-t-cyber-danger');
                if (quarantineCard) {
                    quarantineCard.style.cursor = 'pointer';
                    quarantineCard.addEventListener('click', () => {
                        switchView('quarantine');
                    });
                }
            } else if (target === 'monitoring') {
                loadMonitoringEmails();
            } else if (target === 'quarantine') {
                loadQuarantineEmails();
            } else if (target === 'analytics') {
                initAnalyticsCharts();
            } else if (target === 'urlanalyzer') {
                setupURLAnalyzer();
            } else if (target === 'simulation') {
                setupSimulationTriggers();
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
                const res = await fetch(`${API_BASE}/quarantine/empty/all`, { method: 'DELETE' });
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
        const server = document.getElementById('setting-imap-server').value;
        const user = document.getElementById('setting-imap-user').value;
        const pass = document.getElementById('setting-imap-pass').value;

        if (!server || !user || !pass) {
            await showCustomAlert("Please fill in all IMAP fields before testing.", "Missing Fields", true);
            return;
        }

        try {
            const res = await fetch(`${API_BASE}/settings/test-imap`, {
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

    window.handleQuarantineAction = async function (action, qId) {
        if (action === 'delete') {
            const confirmed = await showCustomConfirm("Are you sure you want to permanently delete this email?");
            if (confirmed) {
                await fetch(`${API_BASE}/quarantine/${qId}`, { method: 'DELETE' });
                loadQuarantineEmails();
                loadDashboardStats();
                document.querySelector('#quarantine-view .glass-card:last-child').innerHTML = '<h3 class="font-medium text-white mb-4 border-b border-cyber-border/50 pb-2">Threat Detail</h3><p class="text-gray-500 text-sm">Select an item to view details</p>';
            }
        } else if (action === 'release') {
            try {
                const res = await fetch(`${API_BASE}/quarantine/${qId}/release`, { method: 'POST' });
                if (res.ok) {
                    await showCustomAlert("Email released to user inbox.", "Success");
                    loadQuarantineEmails();
                    loadDashboardStats();
                    const detailCard = document.querySelector('#quarantine-view .glass-card:last-child');
                    if (detailCard) detailCard.innerHTML = '<h3 class="font-medium text-white mb-4 border-b border-cyber-border/50 pb-2">Threat Detail</h3><p class="text-gray-500 text-sm">Select an item to view details</p>';
                } else {
                    await showCustomAlert("Failed to release email.", "Error", true);
                }
            } catch (e) {
                await showCustomAlert("Network error.", "Error", true);
            }
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

        // Backend SSE Connection
        const sse = new EventSource(`${API_BASE}/stream`);

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
                            const isInternal = r.sender.includes('company') || r.sender.includes('internal');
                            const isDanger = r.risk_score > 70 || r.url_threat_score > 70;
                            const statusColor = r.status === 'Quarantined' ? 'bg-cyber-danger/20 text-cyber-danger border border-cyber-danger/30' : 'bg-cyber-neon/10 text-cyber-neon border border-cyber-neon/20';

                            return `
                            <tr class="cyber-table-row group cursor-pointer monitor-row border-l-2 border-transparent hover:border-cyber-neon transition-colors animate-pulse" data-sender="${r.sender.toLowerCase()}" data-subject="${r.subject.toLowerCase()}" data-risk="${r.risk_score}">
                                <td class="py-4 px-6 text-cyber-neon font-medium">${timeStr}</td>
                                <td class="py-4 px-6">
                                    <div class="font-medium text-white truncate max-w-[250px]">${r.sender}</div>
                                    <div class="text-xs ${isInternal ? 'text-cyber-info' : 'text-gray-500'}">${isInternal ? 'Internal' : 'External'}</div>
                                </td>
                                <td class="py-4 px-6 text-gray-300 truncate max-w-[300px]">${r.subject}</td>
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
                                    <span class="${statusColor} px-2.5 py-1 rounded text-xs">${r.status}</span>
                                </td>
                                <td class="py-4 px-6 text-right">
                                    <button class="text-gray-500 hover:text-cyber-neon transition-colors"><i class="fa-solid fa-expand"></i></button>
                                </td>
                            </tr>
                            `;
                        }).join('');

                        // Use insertAdjacentHTML to prepend instead of overwriting
                        tbody.insertAdjacentHTML('afterbegin', rowsHTML);

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
                        showCustomAlert(`High Risk Email Detected from ${latest.sender}`, "Threat Alert", true);
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
            const res = await fetch(`${API_BASE}/notifications`);
            if (res.ok) {
                const alerts = await res.json();
                if (alerts.length > 0) {
                    notifBadge.classList.remove('hidden');
                    notifList.innerHTML = alerts.map(a => `
                        <li class="p-3 border-b border-cyber-border/50 hover:bg-cyber-panel/50 cursor-pointer transition-colors">
                            <div class="flex items-start">
                                <i class="fa-solid fa-triangle-exclamation text-cyber-danger mt-1 mr-3"></i>
                                <div>
                                    <p class="text-xs font-semibold text-white">${a.subject}</p>
                                    <p class="text-[10px] text-gray-400 mt-1">${a.details}</p>
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

    // Default load
    initNotifications();
    switchView('dashboard');

    async function loadDashboardStats() {
        try {
            const res = await fetch(`${API_BASE}/stats`);
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

            initDashboardCharts(currentRisk, data.trend_labels, data.trend_values);

        } catch (error) {
            console.error("Failed to load dashboard stats:", error);
            initDashboardCharts(50, ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'], [0, 0, 0, 0, 0, 0, 0]); // Fallback
        }
    }

    async function loadRecentThreats() {
        try {
            const res = await fetch(`${API_BASE}/emails?limit=5`);
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

                return `
                <tr class="nav-btn cursor-pointer border-b border-cyber-border/50 hover:bg-cyber-panel/50 transition-colors" data-target="${isDanger ? 'quarantine' : 'monitoring'}">
                    <td class="py-3 px-4">${timeStr}</td>
                    <td class="py-3 px-4 text-gray-300 font-medium truncate max-w-[200px]">${r.subject}</td>
                    <td class="py-3 px-4 truncate max-w-[200px]">${r.sender}</td>
                    <td class="py-3 px-4">
                        <span class="${isDanger ? 'text-cyber-danger' : 'text-cyber-neon'} font-bold">${r.risk_score}%</span>
                    </td>
                    <td class="py-3 px-4">
                        <span class="${r.status === 'Quarantined' ? 'bg-cyber-danger/20 text-cyber-danger border-cyber-danger/30' : 'bg-cyber-neon/10 text-cyber-neon border-cyber-neon/20'} border px-2 py-0.5 rounded text-xs">
                            ${r.status}
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
            const res = await fetch(`${API_BASE}/emails?limit=50`);
            const emails = await res.json();
            const tbody = document.getElementById('monitor-table-body');
            if (!tbody) return;

            if (emails.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" class="py-8 text-center text-gray-500 text-lg">No incoming emails tracked yet. Waiting for inbox events...</td></tr>';
                return;
            }

            tbody.innerHTML = emails.map(r => {
                const dateObj = new Date(r.timestamp + 'Z');
                const timeStr = dateObj.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                const isInternal = r.sender.includes('company') || r.sender.includes('internal');
                const isDanger = r.risk_score > 70 || r.url_threat_score > 70;
                const statusColor = r.status === 'Quarantined' ? 'bg-cyber-danger/20 text-cyber-danger border border-cyber-danger/30' : 'bg-cyber-neon/10 text-cyber-neon border border-cyber-neon/20';

                return `
                <tr class="cyber-table-row group cursor-pointer monitor-row" data-sender="${r.sender.toLowerCase()}" data-subject="${r.subject.toLowerCase()}" data-risk="${r.risk_score}">
                    <td class="py-4 px-6 text-gray-400">${timeStr}</td>
                    <td class="py-4 px-6">
                        <div class="font-medium text-white truncate max-w-[250px]">${r.sender}</div>
                        <div class="text-xs ${isInternal ? 'text-cyber-info' : 'text-gray-500'}">${isInternal ? 'Internal' : 'External'}</div>
                    </td>
                    <td class="py-4 px-6 text-gray-300 truncate max-w-[300px]">${r.subject}</td>
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
                        <span class="${statusColor} px-2.5 py-1 rounded text-xs">${r.status}</span>
                    </td>
                    <td class="py-4 px-6 text-right">
                        <button class="text-gray-500 hover:text-cyber-neon transition-colors"><i class="fa-solid fa-expand"></i></button>
                    </td>
                </tr>
                `;
            }).join('');

            // Apply current filters if any
            applyMonitorFilters();
        } catch (error) {
            console.error("Failed to load monitoring emails:", error);
        }
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
        }
    });

    async function loadQuarantineEmails() {
        try {
            const res = await fetch(`${API_BASE}/quarantine`);
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

                return `
                    <tr class="cyber-table-row hover:bg-cyber-panel cursor-pointer border-l-2 border-transparent" data-id="${item.quarantine_id}">
                        <td class="p-4">
                            <div class="text-white">${item.recipient}</div>
                            <div class="text-xs text-gray-500">${timeStr}</div>
                        </td>
                        <td class="p-4 text-gray-300">${item.subject || 'No Subject'}</td>
                        <td class="p-4">
                            <span class="text-xs text-cyber-danger flex items-center">
                                <i class="fa-solid fa-robot mr-1"></i> ${item.ai_reason || 'High Threat Score'}
                            </span>
                        </td>
                        <td class="p-4">
                            <div class="flex space-x-2">
                                <button data-action="release" data-id="${item.quarantine_id}" class="text-xs border border-cyber-border hover:border-cyber-neon text-gray-400 hover:text-cyber-neon px-3 py-1 rounded transition-colors quarantine-action-btn">Release</button>
                                <button data-action="delete" data-id="${item.quarantine_id}" class="text-xs bg-cyber-danger/10 text-cyber-danger hover:bg-cyber-danger/20 px-3 py-1 rounded transition-colors quarantine-action-btn">Delete</button>
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

            // Add Event Listeners for row click to show details
            document.querySelectorAll('#quarantine-view .cyber-table-row').forEach(row => {
                row.addEventListener('click', () => {
                    const qId = row.getAttribute('data-id');
                    const item = qItems.find(i => i.quarantine_id == qId);
                    if (item) {
                        const detailView = document.querySelector('#quarantine-view .glass-card:last-child');
                        if (detailView) {
                            detailView.innerHTML = `
                                <h3 class="font-medium text-white mb-4 border-b border-cyber-border/50 pb-2">Threat Detail</h3>
                                <div class="flex-1 overflow-y-auto pr-2 custom-scrollbar space-y-4">
                                    <div>
                                        <label class="text-xs text-gray-500 uppercase tracking-wider block mb-1">Subject</label>
                                        <div class="text-white font-medium bg-cyber-dark p-2 rounded border border-cyber-border">${item.subject || 'No Subject'}</div>
                                    </div>
                                    <div>
                                        <label class="text-xs text-gray-500 uppercase tracking-wider block mb-1">Sender</label>
                                        <div class="text-xs text-gray-400 font-mono bg-cyber-dark p-2 rounded border border-cyber-border break-all">
                                            Return-Path: &lt;${item.sender}&gt;
                                        </div>
                                    </div>
                                    <div>
                                        <label class="text-xs text-gray-500 uppercase tracking-wider block mb-1">AI Analysis Log</label>
                                        <div class="text-sm text-gray-300 bg-cyber-danger/10 border border-cyber-danger/30 p-3 rounded">
                                            <i class="fa-solid fa-robot text-cyber-danger mr-2"></i> 
                                            ${item.ai_reason}
                                        </div>
                                    </div>
                                </div>
                                <div class="mt-4 pt-4 border-t border-cyber-border space-y-2">
                                    <button onclick="handleQuarantineAction('delete', ${item.quarantine_id})" class="w-full py-2 bg-cyber-danger/80 hover:bg-cyber-danger text-white rounded font-medium transition-colors shadow-lg shadow-cyber-danger/20">Delete Permanently</button>
                                    <button onclick="handleQuarantineAction('release', ${item.quarantine_id})" class="w-full py-2 bg-transparent border border-cyber-border text-gray-400 hover:text-white hover:border-gray-500 rounded font-medium transition-colors">Release to Inbox (Admin)</button>
                                </div>
                            `;
                        }
                    }
                });
            });

        } catch (error) {
            console.error("Failed to load quarantined emails:", error);
        }
    }

    function setupURLAnalyzer() {
        const analyzeBtn = document.querySelector('#urlanalyzer-view button');
        const inputField = document.querySelector('#urlanalyzer-view input');
        const resultSection = document.querySelector('#urlanalyzer-view .glass-card');

        // Hide result initially
        if (resultSection) resultSection.style.display = 'none';

        if (analyzeBtn && inputField) {
            analyzeBtn.addEventListener('click', async () => {
                const url = inputField.value.trim();
                if (!url) return;

                analyzeBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Scanning...';
                analyzeBtn.disabled = true;

                try {
                    const res = await fetch(`${API_BASE}/analyze-url`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ url: url })
                    });
                    const data = await res.json();

                    if (resultSection) {
                        // Update UI with response data
                        const isMalicious = data.url_threat_score > 50 || data.phishing_score > 60;

                        document.querySelector('#urlanalyzer-view .font-mono').innerText = url;
                        document.querySelector('#urlanalyzer-view .font-bold.text-cyber-danger')?.remove();
                        document.querySelector('#urlanalyzer-view .font-bold.text-cyber-neon')?.remove();

                        const badgeEl = document.createElement('span');
                        badgeEl.className = isMalicious ? 'bg-cyber-danger/20 text-cyber-danger px-3 py-1 rounded-full font-bold' : 'bg-cyber-neon/20 text-cyber-neon px-3 py-1 rounded-full font-bold';
                        badgeEl.innerText = isMalicious ? `${data.url_threat_score}% RISK DETECTED` : `SAFE DOMAIN`;
                        document.querySelector('#urlanalyzer-view .bg-cyber-dark\\/50').appendChild(badgeEl);

                        const findingsList = document.querySelector('#urlanalyzer-view ul');
                        findingsList.innerHTML = `
                            <li><i class="fa-solid fa-robot ${isMalicious ? 'text-cyber-danger' : 'text-cyber-neon'} mr-2"></i> <strong>AI Insight:</strong> ${data.explanation}</li>
                            <li><i class="fa-solid fa-link text-gray-400 mr-2"></i> <strong>Base Phishing Score:</strong> ${data.phishing_score}%</li>
                         `;

                        resultSection.style.display = 'block';
                    }
                } catch (e) {
                    showCustomAlert("Analysis Failed. Ensure backend API is running.", "Error", true);
                } finally {
                    analyzeBtn.innerHTML = 'Scan URL';
                    analyzeBtn.disabled = false;
                }
            });
        }
    }

    function setupSimulationTriggers() {
        const triggerBtn = document.querySelector('#simulation-view button:last-of-type');
        const saveBtn = document.querySelector('#sim-config-form button');

        window.switchSimMode = function (mode) {
            const aiSettings = document.getElementById('sim-ai-settings');
            const manualSettings = document.getElementById('sim-manual-settings');
            const btnManual = document.getElementById('sim-mode-manual');
            const btnAi = document.getElementById('sim-mode-ai');

            if (!aiSettings || !manualSettings) return;

            if (mode === 'Manual') {
                aiSettings.classList.add('hidden');
                manualSettings.classList.remove('hidden');
                btnManual.className = "flex-1 py-1.5 text-sm font-medium rounded-md bg-cyber-neon/20 text-cyber-neon transition-colors";
                btnAi.className = "flex-1 py-1.5 text-sm font-medium rounded-md text-gray-400 hover:text-white transition-colors";
            } else {
                manualSettings.classList.add('hidden');
                aiSettings.classList.remove('hidden');
                btnAi.className = "flex-1 py-1.5 text-sm font-medium rounded-md bg-cyber-neon/20 text-cyber-neon transition-colors";
                btnManual.className = "flex-1 py-1.5 text-sm font-medium rounded-md text-gray-400 hover:text-white transition-colors";
            }
        };

        window.triggerSimulation = async function () {
            if (triggerBtn) {
                const originalText = triggerBtn.innerHTML;
                triggerBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-1"></i> Triggering...';
                triggerBtn.disabled = true;

                try {
                    const modeBtn = document.getElementById('sim-mode-ai');
                    const mode = (modeBtn && modeBtn.classList.contains('bg-cyber-neon/20')) ? 'AI' : 'Manual';
                    let formData = new FormData();
                    formData.append('mode', mode);

                    if (mode === 'Manual') {
                        const fileInput = document.getElementById('sim-target-file');
                        if (fileInput && fileInput.files.length > 0) {
                            formData.append('file', fileInput.files[0]);
                        }
                        const dateInput = document.getElementById('sim-target-date');
                        if (dateInput && dateInput.value) {
                            formData.append('target_date', dateInput.value);
                        }
                    }
                    const delayToggle = document.getElementById('delayToggle');
                    if (delayToggle) {
                        formData.append('delay_mode', delayToggle.checked);
                    }

                    const res = await fetch(`${API_BASE}/simulations/trigger`, {
                        method: 'POST',
                        body: formData
                    });

                    if (res.ok) {
                        showCustomAlert("Campaign successfully triggered via Gophish API!", "Simulation Started");
                    } else {
                        const data = await res.json();
                        showCustomAlert(data.detail || "Failed to trigger campaign.", "Error", true);
                    }
                } catch (e) {
                    showCustomAlert("Error reaching backend API.", "Network Error", true);
                } finally {
                    triggerBtn.innerHTML = originalText;
                    triggerBtn.disabled = false;
                }
            }
        };

        window.saveSimulationConfig = async function () {
            if (saveBtn) {
                const originalText = saveBtn.innerText;
                saveBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-1"></i> Saving...';
                saveBtn.disabled = true;

                setTimeout(() => {
                    showCustomAlert("Simulation settings saved.", "Success");
                    saveBtn.innerHTML = originalText;
                    saveBtn.disabled = false;
                }, 800);
            }
        };

        switchSimMode('Manual');
    }

    async function setupSettings() {
        const saveBtn = document.getElementById('save-settings-btn');
        const rangeSlider = document.getElementById('setting-ai-threshold');
        const rangeVal = document.getElementById('setting-ai-threshold-val');

        // Dynamic slider value display
        if (rangeSlider && rangeVal) {
            rangeSlider.addEventListener('input', (e) => {
                rangeVal.innerText = `${e.target.value}%`;
            });
        }

        // Fetch settings on load
        try {
            const res = await fetch(`${API_BASE}/settings`);
            if (res.ok) {
                const data = await res.json();
                if (data.imap_server) document.getElementById('setting-imap-server').value = data.imap_server;
                if (data.imap_user) document.getElementById('setting-imap-user').value = data.imap_user;
                if (data.imap_pass) document.getElementById('setting-imap-pass').value = data.imap_pass;
                if (data.ai_model) document.getElementById('setting-ai-model').value = data.ai_model;
                if (data.ai_threshold) {
                    document.getElementById('setting-ai-threshold').value = data.ai_threshold;
                    if (rangeVal) rangeVal.innerText = `${data.ai_threshold}%`;
                }
                if (data.gophish_url) document.getElementById('setting-gophish-url').value = data.gophish_url;
                if (data.gophish_key) document.getElementById('setting-gophish-key').value = data.gophish_key;
            }
        } catch (e) {
            console.error("Failed to load settings:", e);
        }

        if (saveBtn) {
            saveBtn.addEventListener('click', async () => {
                const originalText = saveBtn.innerText;
                saveBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-1"></i> Saving...';
                saveBtn.disabled = true;

                const payload = {
                    imap_server: document.getElementById('setting-imap-server').value,
                    imap_user: document.getElementById('setting-imap-user').value,
                    imap_pass: document.getElementById('setting-imap-pass').value,
                    ai_model: document.getElementById('setting-ai-model').value,
                    ai_threshold: document.getElementById('setting-ai-threshold').value,
                    gophish_url: document.getElementById('setting-gophish-url').value,
                    gophish_key: document.getElementById('setting-gophish-key').value
                };

                try {
                    const res = await fetch(`${API_BASE}/settings`, {
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

    async function initAnalyticsCharts() {
        if (chartInstances.pie) chartInstances.pie.destroy();

        try {
            const res = await fetch(`${API_BASE}/analytics`);
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
                    return `
                        <div class="bg-cyber-dark p-3 rounded flex justify-between items-center border-l-4 ${borderMap[d.risk_level]}">
                            <div>
                                <div class="text-white font-medium">${d.name}</div>
                                <div class="text-xs text-gray-500">${d.incidents} incidents this week</div>
                            </div>
                            <span class="${colorMap[d.risk_level]} font-bold text-lg">${d.risk_level}</span>
                        </div>
                    `;
                }).join('');
            }
        } catch (error) {
            console.error("Failed to load analytics:", error);
        }
    }
});
