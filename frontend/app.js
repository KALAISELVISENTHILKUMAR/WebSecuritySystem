// Initialize Lucide Icons
lucide.createIcons();

// --- Chart setup ---
Chart.defaults.color = '#94a3b8';
Chart.defaults.font.family = 'Inter, sans-serif';

const commonOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false }, tooltip: { mode: 'index', intersect: false } },
    scales: {
        x: { grid: { display: false, drawBorder: false } },
        y: { grid: { color: 'rgba(51, 58, 76, 0.4)', drawBorder: false }, beginAtZero: true }
    }
};

// 1. Daily Blocked Flows (Bar Chart)
const ctxBlocked = document.getElementById('blockedFlowsChart').getContext('2d');
const blockedChart = new Chart(ctxBlocked, {
    type: 'bar',
    data: {
        labels: ['Mar 18', 'Mar 19', 'Mar 20', 'Mar 21', 'Mar 22', 'Mar 23', 'Mar 24', 'Mar 25', 'Mar 26', 'Mar 27', 'Mar 28', 'Mar 29', 'Mar 30', 'Mar 31', 'Apr 1', 'Apr 2', 'Apr 3', 'Apr 4', 'Apr 5', 'Apr 6', 'Apr 7', 'Apr 8', 'Apr 9', 'Apr 10', 'Apr 11', 'Apr 12'],
        datasets: [{
            label: 'Blocked Flows',
            // Default visual placeholder data matching the aesthetic, to be replaced by backend
            data: [150, 180, 290, 450, 320, 270, 240, 210, 180, 190, 300, 280, 220, 150, 160, 190, 260, 230, 230, 180, 190, 270, 270, 230, 230, 180],
            backgroundColor: '#0ea5e9',
            borderRadius: 2
        }]
    },
    options: Object.assign({}, commonOptions, {
        scales: {
            x: { grid: { display: false }, ticks: { maxTicksLimit: 8, font: { size: 10 } } },
            y: { grid: { color: 'rgba(51, 58, 76, 0.4)' }, ticks: { maxTicksLimit: 5, font: { size: 10 } } }
        }
    })
});

// 2. Daily Alarms & Rules (Line Chart)
const ctxAlarms = document.getElementById('alarmsRulesChart').getContext('2d');
const alarmsChart = new Chart(ctxAlarms, {
    type: 'line',
    data: {
        labels: ['Mar 18', 'Mar 21', 'Mar 24', 'Mar 27', 'Mar 30', 'Apr 2', 'Apr 5', 'Apr 8', 'Apr 11', 'Apr 12'],
        datasets: [
            {
                label: 'Alarms',
                data: [12, 14, 18, 15, 12, 10, 14, 25, 45, 15],
                borderColor: '#0ea5e9',
                backgroundColor: 'transparent',
                borderWidth: 2,
                tension: 0.4,
                pointRadius: 0
            },
            {
                label: 'Rules',
                data: [8, 9, 11, 20, 14, 12, 11, 15, 18, 12],
                borderColor: '#ef4444',
                backgroundColor: 'transparent',
                borderWidth: 2,
                tension: 0.4,
                pointRadius: 0
            }
        ]
    },
    options: Object.assign({}, commonOptions, {
        scales: {
            x: { grid: { display: false }, ticks: { autoSkip: true, maxTicksLimit: 7, font: { size: 10 } } },
            y: { grid: { color: 'rgba(51, 58, 76, 0.4)' }, ticks: { maxTicksLimit: 5, font: { size: 10 } } }
        }
    })
});


// --- Backend Data Integration ---
const API = 'http://127.0.0.1:8000';
let token = localStorage.nexaf_token || '';

const $ = id => document.getElementById(id);

function headers() {
    return { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token };
}

async function api(path, opt = {}) {
    opt.headers = { ...(opt.headers || {}), ...headers() };
    let r = await fetch(API + path, opt);
    if (r.status === 401) {
        logout();
        throw Error('Unauthorized');
    }
    return r;
}

function logout() {
    token = '';
    localStorage.removeItem('nexaf_token');
    $('login-overlay').style.display = 'flex';
    $('who').textContent = 'NOT LOGGED IN';
}

function showApp(role) {
    $('login-overlay').style.display = 'none';
    $('who').textContent = role;
    load();
}

let currentView = 'dashboard';
let activeDeviceId = null;

function switchView(viewId, el) {
    if (el) {
        document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
        el.classList.add('active');
    }
    ['view-dashboard', 'view-devices', 'view-device-detail', 'view-incidents', 'view-rules'].forEach(id => {
        let node = document.getElementById(id);
        if (node) node.style.display = 'none';
    });
    let target = document.getElementById('view-' + (viewId === 'device-detail' ? 'device-detail' : viewId));
    if (target) target.style.display = 'block';

    currentView = viewId;
    load();
}

async function load() {
    if (currentView === 'devices') return loadDevices();
    if (currentView === 'incidents') return loadIncidents();
    if (currentView === 'device-detail' && activeDeviceId) return loadDeviceDetail(activeDeviceId);

    try {
        let decisionQuery = $('event-decision') ? $('event-decision').value : '';
        let attackQuery = $('event-attack') ? encodeURIComponent($('event-attack').value) : '';
        let sdQuery = $('event-start-date') ? $('event-start-date').value : '';
        let edQuery = $('event-end-date') ? $('event-end-date').value : '';

        let [h, s, p, r, e] = await Promise.all([
            fetch(API + '/health'),
            api('/events/stats'),
            fetch(API + '/protections'),
            api('/self-healing/status'),
            api(`/events?limit=25&decision=${decisionQuery}&attack_type=${attackQuery}&start_date=${sdQuery}&end_date=${edQuery}`)
        ]);

        let hd = await h.json(), sd = await s.json(), pd = await p.json(), rd = await r.json(), ed = await e.json();

        if ($('who')) $('who').textContent = `ADMIN User [${hd.ai_provider}]`;


        // Populate core stats if present
        if ($('chart-total-val')) $('chart-total-val').textContent = sd.total_events || 0;
        if ($('chart-blocked-val')) $('chart-blocked-val').textContent = sd.blocked || 0;
        if ($('rules-val')) $('rules-val').textContent = pd.active_rules?.length || 0;

        // Mock resource values visually as requested
        $('wan-up').textContent = '1.47 Mb/s';
        $('wan-down').textContent = '22.57 Kb/s';
        $('cpu-bar').style.width = '38.1%';
        $('cpu-val').textContent = '38.1%';
        $('mem-bar').style.width = '59.1%';
        $('mem-val').textContent = '59.1%';

        // Intelligent Remediation / Self Healing Status Integration
        if (rd.temporary_blocks > 0) {
            $('l5-status').textContent = 'ACTIVE';
            $('l5-status').className = 'tag green';
            $('l5-desc').textContent = `${rd.temporary_blocks} active intelligent protection rules currently deployed. (Threshold: ${rd.threshold})`;
            $('l6-status').textContent = 'MITIGATING';
            $('l6-desc').textContent = `System currently enforcing Temporary Drops. Source IP blocks active.`;
        } else {
            $('l5-status').textContent = 'MONITORING';
            $('l5-status').className = 'tag';
            $('l5-desc').textContent = `Monitoring inbound requests. Threshold: ${rd.threshold} req / ${rd.window_seconds}s.`;
            $('l6-status').textContent = 'RECOVERED';
            $('l6-desc').textContent = `Previous block mitigations automatically resolved safely.`;
        }

        // Populate Activity Log Table
        if ($('events')) {
            $('events').innerHTML = ed.events.map(x => {
                const isBlock = x.decision === 'BLOCK';
                const time = new Date(x.timestamp).toLocaleTimeString();
                return `
                <tr>
                    <td style="color:var(--text-tertiary);">${time}</td>
                    <td class="status-text ${isBlock ? 'block' : 'allow'}">TRAFFIC_${x.decision}</td>
                    <td class="url-text" title="${x.request_path}">${x.request_path.slice(0, 50)}${x.request_path.length > 50 ? '...' : ''}</td>
                    <td class="url-text" style="color:var(--text-tertiary);">${isBlock ? `<i data-lucide="triangle-alert" style="width:12px; margin-right:4px;"></i> ${x.attack_type}` : ''}</td>
                </tr>`;
            }).join('');
            lucide.createIcons();
        }

    } catch (e) {
        console.error('Failed to load API data', e);
    }
}

async function loadDevices() {
    try {
        let r = await api('/devices');
        let d = await r.json();

        $('devices-list').innerHTML = d.devices.map(x => `
            <tr style="border-bottom:1px solid #1e293b;">
                <td style="padding:12px; color:var(--info); cursor:pointer;" onclick="viewDevice('${x.device_id}')">
                    ${x.display_name}<br><span style="font-size:10px; color:var(--text-tertiary);">${x.device_id}</span>
                </td>
                <td style="padding:12px;">
                    <span class="tag ${x.online_status === 'ONLINE' ? 'green' : ''}" style="font-size:10px;">${x.online_status}</span>
                </td>
                <td style="padding:12px; font-size:11px;">${x.browser} / ${x.operating_system}</td>
                <td style="padding:12px; font-size:11px;">${new Date(x.last_seen).toLocaleString()}</td>
                <td style="padding:12px;">
                    <span class="tag ${x.current_risk_level === 'CRITICAL' ? 'red' : x.current_risk_level === 'HIGH' ? '' : 'green'}" style="font-size:10px;">
                        ${x.current_risk_level} (${x.blocked_events} blocked)
                    </span>
                </td>
                <td style="padding:12px;">
                    <button class="primary" style="padding:4px 8px; font-size:10px;" onclick="viewDevice('${x.device_id}')">View</button>
                </td>
            </tr>
        `).join('');
    } catch (e) { }
}

async function loadIncidents() {
    try {
        let r = await api('/incidents');
        let d = await r.json();
        $('incidents-list').innerHTML = d.incidents.map(x => `
            <tr style="border-bottom:1px solid #1e293b;">
                <td style="padding:12px; font-family:monospace;">${x.incident_id}</td>
                <td style="padding:12px;">
                    <span style="color:var(--text-primary);">${x.device_id}</span><br>
                    <span style="font-size:10px; color:var(--text-tertiary);">${x.source_ip}</span>
                </td>
                <td style="padding:12px; font-size:11px;">${x.threat_categories.join(', ')}</td>
                <td style="padding:12px;">
                    <span class="tag ${x.max_risk_score >= 80 ? 'red' : ''}" style="font-size:10px;">Score: ${x.max_risk_score}</span>
                </td>
                <td style="padding:12px;">
                    <span class="tag" style="background:#1e293b; font-size:10px;">${x.current_status}</span>
                </td>
            </tr>
        `).join('');
    } catch (e) { }
}

function viewDevice(id) {
    activeDeviceId = id;
    switchView('device-detail');
}

async function loadDeviceDetail(id) {
    try {
        let [dr, er] = await Promise.all([
            api('/devices/' + id),
            api(`/events/export?decision=&attack_type=&start_date=&end_date=`)
        ]);
        let d = await dr.json();

        $('dd-name').textContent = d.display_name;
        $('dd-id').textContent = d.device_id;
        $('dd-browser').textContent = d.browser;
        $('dd-os').textContent = d.operating_system;
        $('dd-ext').textContent = d.extension_version;
        $('dd-status').textContent = d.online_status;
        $('dd-first').textContent = new Date(d.first_seen).toLocaleString();

        $('dd-total').textContent = d.total_events;
        $('dd-blocked').textContent = d.blocked_events;
        $('dd-incidents').textContent = d.active_incidents;
        $('dd-risk').textContent = d.current_risk_level;

        let csvUrl = API + `/devices/${id}/events/export?format=csv`;
        let jsonUrl = API + `/devices/${id}/events/export?format=json`;

        $('btn-device-csv').onclick = () => window.open(csvUrl);
        $('btn-device-json').onclick = () => window.open(jsonUrl);

        // Manual poor-man's filter for device events from the main array for demo 
        // Real implementation would use dedicated DB query but export is fine for small scale demo
        let evData = await (await api(`/events`)).json();
        let devEvents = evData.events.filter(e => e.device_id === id).slice(0, 50);

        $('dd-events').innerHTML = devEvents.map(x => `
            <tr style="border-bottom:1px solid #1e293b;">
                <td style="padding:8px;">${new Date(x.timestamp).toLocaleString()}</td>
                <td style="padding:8px;" class="${x.decision === 'BLOCK' ? 'block' : 'allow'}">${x.decision}</td>
                <td style="padding:8px; color:var(--info);">${x.attack_type === 'None' ? 'Clean' : x.attack_type}</td>
                <td style="padding:8px;">${x.request_path.slice(0, 60)}${x.request_path.length > 60 ? '...' : ''}</td>
            </tr>
        `).join('');
    } catch (e) { }
}

// Bindings for new UI filters and buttons
if ($('event-decision')) $('event-decision').onchange = load;
if ($('event-attack')) $('event-attack').onchange = load;
if ($('btn-refresh')) $('btn-refresh').onclick = load;

if ($('event-start-date')) $('event-start-date').onchange = load;
if ($('event-end-date')) $('event-end-date').onchange = load;

if ($('btn-download')) {
    $('btn-download').onclick = async () => {
        let decision = $('event-decision') ? $('event-decision').value : '';
        let attack = $('event-attack') ? encodeURIComponent($('event-attack').value) : '';
        let sd = $('event-start-date') ? $('event-start-date').value : '';
        let ed = $('event-end-date') ? $('event-end-date').value : '';
        let req = await api(`/events/export?decision=${decision}&attack_type=${attack}&start_date=${sd}&end_date=${ed}`);
        let blob = await req.blob();
        let a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'nexaf-security-log.csv';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
    };
}

// Login Form Handling
$('loginForm').onsubmit = async e => {
    e.preventDefault();
    try {
        let r = await fetch(API + '/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: $('username').value, password: $('password').value })
        });
        let d = await r.json();
        if (!r.ok) throw Error(d.detail);
        token = d.access_token;
        localStorage.nexaf_token = token;
        showApp(d.role);
    } catch (e) {
        $('loginError').textContent = e.message;
    }
};

// Logout Binding
if ($('logout')) {
    $('logout').onclick = logout;
}

// Analyzer Handling
if ($('analyzeForm')) {
    $('analyzeForm').onsubmit = async e => {
        e.preventDefault();

        $('diag-status').textContent = 'ANALYZING...';
        $('diag-status').style.color = 'var(--warning)';

        try {
            let r = await fetch(API + '/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: $('url').value, method: 'GET', source: 'dashboard' })
            });
            let d = await r.json();

            const isBlock = d.decision === 'BLOCK';

            $('diag-status').textContent = d.decision;
            $('diag-status').style.color = isBlock ? 'var(--danger)' : 'var(--success)';

            $('diag-attack').textContent = d.attack_type || '-';

            $('diag-risk-bar').style.width = d.risk_score + '%';
            $('diag-risk-bar').style.background = isBlock ? 'var(--danger)' : 'var(--warning)';

            $('diag-why').textContent = d.explanation;
            $('diag-action').textContent = `${d.action} [${d.execution_layer || ''}] (${d.ai_provider})`;

            let ruleId = d.protection_rule?.rule_id || 'none';
            $('diag-healing').innerHTML = `Verified protection. Rule: <b>${ruleId}</b>`;

            load();
        } catch (err) {
            $('diag-status').textContent = 'ERRORED';
        }
    };
}

// Initial Authentication check
if (token) {
    api('/users/me')
        .then(r => r.json())
        .then(u => showApp(u.role))
        .catch(() => { $('login-overlay').style.display = 'flex'; });
} else {
    $('login-overlay').style.display = 'flex';
}

setInterval(() => token && load(), 3000);
