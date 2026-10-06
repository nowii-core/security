'use strict';

/* =========================================================
   NOWII·SENTINEL — Security Operations Center
   ========================================================= */
const $  = (s, c = document) => c.querySelector(s);
const $$ = (s, c = document) => [...c.querySelectorAll(s)];

const KEYS = {
  THEME: 'sentinel_theme',
  DENSITY: 'sentinel_density',
  LIVE_FEED: 'sentinel_live_feed',
  AUTO_RESPONSE: 'sentinel_auto_response',
  SOUND: 'sentinel_sound',
  ALERT_THRESHOLD: 'sentinel_alert_threshold',
  API_KEY: 'sentinel_api_key',
  TENANT: 'sentinel_tenant',
  ONBOARDING: 'sentinel_onboarding_done'
};

/* =========================================================
   STATE
   ========================================================= */
let state = {
  currentView: 'overview',
  currentRange: '1h',
  threats: [],
  incidents: [],
  vulnerabilities: [],
  logs: [],
  notifications: [],
  playbooks: [],
  compliance: [],
  tenants: [],
  selectedThreats: new Set(),
  threatFilter: { sev: 'all', type: '', search: '', sortField: 'timestamp', sortDir: 'desc' },
  vulnFilter: { sev: '', status: '', search: '' },
  incidentFilter: { status: 'all' },
  logFilter: { level: 'all', search: '' },
  feedPaused: false,
  feedTimer: null,
  logTimer: null,
  clockTimer: null,
  mapRAF: null,
  theme: localStorage.getItem(KEYS.THEME) || 'dark',
  density: localStorage.getItem(KEYS.DENSITY) || 'default',
  liveFeed: localStorage.getItem(KEYS.LIVE_FEED) !== 'false',
  autoResponse: localStorage.getItem(KEYS.AUTO_RESPONSE) === 'true',
  sound: localStorage.getItem(KEYS.SOUND) === 'true',
  alertThreshold: localStorage.getItem(KEYS.ALERT_THRESHOLD) || 'high',
  tenant: localStorage.getItem(KEYS.TENANT) || 'acme',
  cmdSelectedIndex: 0,
  cmdFlatItems: []
};

/* =========================================================
   ICONS
   ========================================================= */
const ICONS = {
  shield: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
  alert: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><path d="M12 9v4M12 17h.01"/></svg>`,
  check: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M5 13l4 4L19 7"/></svg>`,
  x: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M18 6L6 18M6 6l12 12"/></svg>`,
  eye: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`,
  block: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><path d="M4.93 4.93l14.14 14.14"/></svg>`,
  bolt: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>`,
  sparkle: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l2 5 5 2-5 2-2 5-2-5-5-2 5-2 2-5z"/></svg>`
};

/* =========================================================
   DATA CONSTANTS
   ========================================================= */
const COUNTRIES = [
  { name: 'Russia', code: 'RU', flag: '🇷🇺', x: 0.62, y: 0.28 },
  { name: 'China', code: 'CN', flag: '🇨🇳', x: 0.75, y: 0.38 },
  { name: 'USA', code: 'US', flag: '🇺🇸', x: 0.22, y: 0.40 },
  { name: 'Brazil', code: 'BR', flag: '🇧🇷', x: 0.30, y: 0.68 },
  { name: 'India', code: 'IN', flag: '🇮🇳', x: 0.68, y: 0.52 },
  { name: 'Iran', code: 'IR', flag: '🇮🇷', x: 0.60, y: 0.42 },
  { name: 'North Korea', code: 'KP', flag: '🇰🇵', x: 0.82, y: 0.36 },
  { name: 'Nigeria', code: 'NG', flag: '🇳🇬', x: 0.50, y: 0.60 },
  { name: 'Vietnam', code: 'VN', flag: '🇻🇳', x: 0.78, y: 0.48 },
  { name: 'Ukraine', code: 'UA', flag: '🇺🇦', x: 0.56, y: 0.32 },
  { name: 'Romania', code: 'RO', flag: '🇷🇴', x: 0.54, y: 0.34 },
  { name: 'Indonesia', code: 'ID', flag: '🇮🇩', x: 0.80, y: 0.60 }
];

const ATTACK_TYPES = [
  { name: 'SQL Injection', mitre: ['T1190'] },
  { name: 'XSS', mitre: ['T1059.007'] },
  { name: 'Brute Force', mitre: ['T1110'] },
  { name: 'DDoS', mitre: ['T1498'] },
  { name: 'Malware', mitre: ['T1204'] },
  { name: 'Port Scan', mitre: ['T1046'] },
  { name: 'Privilege Escalation', mitre: ['T1068'] },
  { name: 'Data Exfiltration', mitre: ['T1041'] },
  { name: 'Credential Stuffing', mitre: ['T1110.004'] },
  { name: 'Ransomware', mitre: ['T1486'] }
];

const TARGETS = [
  'web-01.prod.acme.com', 'web-02.prod.acme.com', 'api-gateway.prod.acme.com',
  'db-primary.internal', 'db-replica.internal', 'auth-service.prod.acme.com',
  'billing.acme.com', 'admin-panel.acme.com', 'vpn.acme.com',
  'mail.acme.com', 'cdn-edge.acme.com', 'search-indexer.internal'
];

const ASSIGNEES = ['nowii-core', 'Marco Rossi', 'Giulia Bianchi', 'Luca Ferrari', 'Elena Greco', 'Sofia Marchetti'];

const COMPLIANCE_FRAMEWORKS = [
  { name: 'ISO 27001:2022', full: 'Information Security Management', score: 87 },
  { name: 'SOC 2 Type II', full: 'Service Organization Control', score: 92 },
  { name: 'GDPR', full: 'General Data Protection Regulation', score: 78 },
  { name: 'PCI DSS v4.0', full: 'Payment Card Industry', score: 71 },
  { name: 'NIST CSF', full: 'Cybersecurity Framework', score: 84 },
  { name: 'HIPAA', full: 'Health Insurance Portability', score: 65 }
];

const PLAYBOOK_LIBRARY = [
  { id: 'pb-001', name: 'Phishing Email Response', desc: 'Quarantine email, notify users, scan mail server', tags: ['phishing', 'email'], automation: 'auto', icon: 'shield',
    steps: [
      { title: 'Quarantine email', desc: 'Sposta l\'email in quarantena su tutti i gateway' },
      { title: 'Identify recipients', desc: 'Trova utenti che hanno aperto l\'email' },
      { title: 'Force password reset', desc: 'Forza reset password per utenti compromessi' },
      { title: 'Scan for IOCs', desc: 'Scansiona endpoint per indicatori di compromissione' },
      { title: 'Notify security team', desc: 'Invia report a Slack #security' }
    ]},
  { id: 'pb-002', name: 'DDoS Mitigation', desc: 'Activate rate limiting, enable CDN scrubbing', tags: ['ddos', 'network'], automation: 'auto', icon: 'bolt',
    steps: [
      { title: 'Enable rate limiting', desc: 'Attiva rate limit su WAF' },
      { title: 'Geo-block source', desc: 'Blocca traffico da paesi sospetti' },
      { title: 'Enable CDN scrubbing', desc: 'Attiva protezione anti-DDoS su Cloudflare' },
      { title: 'Scale infrastructure', desc: 'Aumenta repliche backend' }
    ]},
  { id: 'pb-003', name: 'Ransomware Containment', desc: 'Isolate host, snapshot volumes, restore', tags: ['ransomware', 'critical'], automation: 'manual', icon: 'alert',
    steps: [
      { title: 'Isolate infected hosts', desc: 'Disconnetti host dalla rete' },
      { title: 'Snapshot volumes', desc: 'Crea snapshot prima della remediation' },
      { title: 'Identify patient zero', desc: 'Trova host origine' },
      { title: 'Restore from backup', desc: 'Ripristina da backup più recente' },
      { title: 'Post-incident review', desc: 'Root cause analysis' }
    ]},
  { id: 'pb-004', name: 'Compromised Credentials', desc: 'Revoke sessions, rotate keys, monitor', tags: ['identity', 'iam'], automation: 'auto', icon: 'shield',
    steps: [
      { title: 'Revoke active sessions', desc: 'Termina tutte le sessioni utente' },
      { title: 'Force MFA', desc: 'Richiedi nuovo setup MFA' },
      { title: 'Rotate API keys', desc: 'Genera nuove chiavi per il team' },
      { title: 'Monitor access logs', desc: 'Attiva monitoraggio 24h' }
    ]},
  { id: 'pb-005', name: 'Suspicious Admin Activity', desc: 'Verify actions, alert if unauthorized', tags: ['insider', 'audit'], automation: 'manual', icon: 'eye',
    steps: [
      { title: 'Review admin actions', desc: 'Analizza ultimi 50 comandi admin' },
      { title: 'Contact admin user', desc: 'Verifica attività via canale secondario' },
      { title: 'Revoke elevated permissions', desc: 'Revoca privilegi se sospetto confermato' }
    ]},
  { id: 'pb-006', name: 'Data Exfiltration Attempt', desc: 'Block egress, alert DPO, preserve evidence', tags: ['exfiltration', 'gdpr'], automation: 'auto', icon: 'alert',
    steps: [
      { title: 'Block egress', desc: 'Blocca traffico in uscita da host sospetto' },
      { title: 'Preserve evidence', desc: 'Screenshot, log, memory dump' },
      { title: 'Notify DPO', desc: 'Invia report al Data Protection Officer' },
      { title: 'Legal hold', desc: 'Applica legal hold sui sistemi' }
    ]}
];

const TENANTS = [
  { id: 'acme', name: 'Acme Industries', plan: 'Enterprise · 42 seats', color: '#8b5cf6', initials: 'AI' },
  { id: 'northwind', name: 'Northwind Retail', plan: 'Pro · 12 seats', color: '#10b981', initials: 'NR' },
  { id: 'globex', name: 'Globex Corporation', plan: 'Enterprise · 87 seats', color: '#f59e0b', initials: 'GC' }
];

/* =========================================================
   UTILS
   ========================================================= */
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

function randomFrom(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function randomInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function uid(prefix = 'ID') { return prefix + '-' + Math.random().toString(36).slice(2, 8).toUpperCase(); }
function randomIP() { return `${randomInt(1,254)}.${randomInt(0,254)}.${randomInt(0,254)}.${randomInt(1,254)}`; }
function formatTime(ts) { return new Date(ts).toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit', second: '2-digit' }); }
function formatDate(ts) { return new Date(ts).toLocaleDateString('it-IT', { day: '2-digit', month: 'short', year: 'numeric' }); }

function timeAgo(ts) {
  const diff = (Date.now() - ts) / 1000;
  if (diff < 60) return 'ora';
  if (diff < 3600) return Math.floor(diff / 60) + 'min fa';
  if (diff < 86400) return Math.floor(diff / 3600) + 'h fa';
  return Math.floor(diff / 86400) + 'g fa';
}

function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

function downloadFile(filename, content, mime = 'text/csv') {
  const blob = new Blob([content], { type: mime + ';charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 500);
}

function toast(text, type = 'info') {
  const container = $('#toastContainer');
  if (!container) return;
  const iconMap = { success: ICONS.check, info: ICONS.shield, warning: ICONS.alert, error: ICONS.x };
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `<span class="toast-icon">${iconMap[type] || ICONS.shield}</span><span>${escapeHtml(text)}</span>`;
  container.appendChild(el);
  setTimeout(() => { el.classList.add('out'); setTimeout(() => el.remove(), 250); }, 3200);
}

/* =========================================================
   DATA GENERATION
   ========================================================= */
function generateThreat(ageMs = 0) {
  const country = randomFrom(COUNTRIES);
  const attack = randomFrom(ATTACK_TYPES);
  const target = randomFrom(TARGETS);
  const sevMap = {
    'Ransomware': 'critical', 'Data Exfiltration': 'critical',
    'Privilege Escalation': 'high', 'SQL Injection': 'high', 'DDoS': 'high', 'Malware': 'high',
    'Brute Force': 'medium', 'Credential Stuffing': 'medium', 'XSS': 'medium',
    'Port Scan': 'low'
  };
  const severity = sevMap[attack.name] || 'medium';
  const blocked = Math.random() > 0.25;
  const ts = Date.now() - ageMs;
  const ip = randomIP();
  const id = uid('THR');

  return {
    id, timestamp: ts, sourceIP: ip,
    country: country.name, countryCode: country.code, flag: country.flag,
    x: country.x, y: country.y,
    type: attack.name, mitre: attack.mitre, target, severity,
    action: blocked ? 'blocked' : 'pending',
    port: randomInt(1, 65535),
    userAgent: randomFrom(['Mozilla/5.0', 'curl/7.68', 'python-requests/2.28', 'sqlmap/1.7', 'Nmap Scripting Engine']),
    log: `[${formatTime(ts)}] INBOUND from ${ip} (${country.name})\n[${formatTime(ts)}] PAYLOAD: ${attack.name}\n[${formatTime(ts)}] TARGET: ${target}\n[${formatTime(ts)}] ${blocked ? '[OK] Blocked by WAF' : '[ERR] Allowed — manual review required'}`
  };
}

function generateIncident(ageHours = 0) {
  const priority = randomFrom(['P1', 'P2', 'P2', 'P3', 'P3', 'P4']);
  const category = randomFrom(['Unauthorized Access', 'Malware Infection', 'Data Breach', 'DDoS Attack', 'Insider Threat', 'Phishing']);
  const status = randomFrom(['open', 'investigating', 'investigating', 'contained', 'resolved']);
  const ts = Date.now() - ageHours * 3600000;
  const id = uid('INC');

  const titleMap = {
    'Unauthorized Access': 'Suspicious authentication activity detected',
    'Malware Infection': 'Malware detected on endpoint',
    'Data Breach': 'Potential data exfiltration from database',
    'DDoS Attack': 'Volumetric DDoS against API gateway',
    'Insider Threat': 'Unusual privileged access pattern',
    'Phishing': 'Phishing campaign targeting employees'
  };

  return {
    id, timestamp: ts,
    title: titleMap[category] + ' — ' + randomFrom(TARGETS).split('.')[0],
    description: `${category} rilevato su ${randomFrom(TARGETS)}. Severity scoring automatico: ${priority}. Analisi in corso da parte del SOC.`,
    priority, category, status,
    assignee: randomFrom(ASSIGNEES),
    assets: [...new Set([randomFrom(TARGETS), randomFrom(TARGETS)])],
    timeline: [
      { time: ts, event: 'Incident created', actor: 'system' },
      { time: ts + 5 * 60000, event: 'Assigned to ' + randomFrom(ASSIGNEES), actor: 'system' },
      ...(status !== 'open' ? [{ time: ts + 15 * 60000, event: 'Investigation started', actor: 'analyst' }] : []),
      ...(status === 'contained' || status === 'resolved' ? [{ time: ts + 45 * 60000, event: 'Threat contained', actor: 'analyst' }] : []),
      ...(status === 'resolved' ? [{ time: ts + 120 * 60000, event: 'Incident resolved', actor: 'analyst' }] : [])
    ]
  };
}

function generateVulnerability() {
  const year = randomInt(2023, 2025);
  const num = randomInt(1000, 45000);
  const cvss = +(Math.random() * 9 + 1).toFixed(1);
  let severity;
  if (cvss >= 9) severity = 'critical';
  else if (cvss >= 7) severity = 'high';
  else if (cvss >= 4) severity = 'medium';
  else severity = 'low';

  const vendors = ['Apache', 'Nginx', 'OpenSSL', 'Redis', 'PostgreSQL', 'WordPress', 'OpenSSH', 'Kubernetes', 'Docker', 'Log4j'];
  const vendor = randomFrom(vendors);
  const descMap = {
    'Apache': 'Remote code execution via crafted HTTP request',
    'Nginx': 'Memory corruption in HTTP/2 module',
    'OpenSSL': 'Buffer overflow in TLS handshake',
    'Redis': 'Unauthenticated command execution',
    'PostgreSQL': 'SQL injection via extended protocol',
    'WordPress': 'Authenticated file upload vulnerability',
    'OpenSSH': 'Pre-authentication denial of service',
    'Kubernetes': 'Container escape via privileged pod',
    'Docker': 'Privilege escalation via runc',
    'Log4j': 'JNDI injection leading to RCE'
  };

  return {
    cve: `CVE-${year}-${num}`,
    cvss, severity,
    description: `${vendor}: ${descMap[vendor] || 'Security flaw'}`,
    vendor, asset: randomFrom(TARGETS),
    status: randomFrom(['open', 'open', 'patching', 'patched', 'wontfix']),
    published: Date.now() - randomInt(1, 365) * 86400000
  };
}

function generateLogLine() {
  const levels = ['INFO', 'INFO', 'INFO', 'INFO', 'WARN', 'WARN', 'ERROR', 'CRITICAL'];
  const lvl = randomFrom(levels);
  const msgs = {
    INFO: [
      'Authentication successful for user=%USER% from %IP%',
      'Request completed: GET /api/v1/health 200 in %MS%ms',
      'Session created for user=%USER%',
      'TLS handshake completed with %IP%',
      'Cache hit for key=%KEY%'
    ],
    WARN: [
      'Rate limit exceeded for %IP% (limit=100/min)',
      'Slow query detected: %MS%ms on table=users',
      'Multiple failed logins for user=%USER% (%N% attempts)',
      'Certificate expiring in %N% days'
    ],
    ERROR: [
      'Authentication failed for user=%USER% from %IP%',
      'Database connection timeout after %MS%ms',
      'Unhandled exception in worker thread'
    ],
    CRITICAL: [
      'SECURITY: Possible SQL injection attempt from %IP%',
      'SECURITY: Unauthorized admin access from %IP%',
      'SERVICE DOWN: api-gateway unreachable',
      'INTRUSION DETECTED: anomalous pattern from %IP%'
    ]
  };
  let msg = randomFrom(msgs[lvl]);
  msg = msg.replace('%IP%', randomIP())
    .replace('%USER%', randomFrom(['admin', 'root', 'john.doe', 'giulia.b', 'svc-billing']))
    .replace('%MS%', randomInt(10, 5000))
    .replace('%N%', randomInt(3, 50))
    .replace('%KEY%', 'session:' + Math.random().toString(36).slice(2, 10));

  return {
    ts: Date.now(), level: lvl,
    source: randomFrom(['api-gateway', 'auth-service', 'web-01', 'db-primary', 'waf', 'cdn-edge']),
    message: msg
  };
}

/* =========================================================
   SEED
   ========================================================= */
function seedData() {
  state.threats = Array.from({ length: 60 }, () => generateThreat(randomInt(0, 24 * 3600 * 1000)))
    .sort((a, b) => b.timestamp - a.timestamp);

  state.incidents = Array.from({ length: 8 }, () => generateIncident(randomInt(1, 72)))
    .sort((a, b) => b.timestamp - a.timestamp);

  state.vulnerabilities = Array.from({ length: 15 }, generateVulnerability);
  state.logs = Array.from({ length: 30 }, generateLogLine);
  state.playbooks = PLAYBOOK_LIBRARY;
  state.compliance = COMPLIANCE_FRAMEWORKS;
  state.tenants = TENANTS;

  state.notifications = [
    { type: 'critical', title: 'search-indexer down', desc: 'Regione ap-south-1 · pod in CrashLoopBackOff', time: '2 min fa', read: false },
    { type: 'warning', title: 'High CPU su billing-worker', desc: 'Sopra 80% da 15 minuti', time: '18 min fa', read: false },
    { type: 'success', title: 'Deploy completato', desc: 'api-gateway v2.14.3 · produzione', time: '1 ora fa', read: false },
    { type: 'info', title: 'Nuovo cliente onboarded', desc: 'Pinnacle Group ha attivato il piano Enterprise', time: '2 ore fa', read: true }
  ];
}

/* =========================================================
   SETTINGS
   ========================================================= */
function applySettings() {
  document.documentElement.setAttribute('data-theme', state.theme);
  document.documentElement.setAttribute('data-density', state.density);

  $$('#themeSegmented button').forEach(b => b.classList.toggle('active', b.dataset.theme === state.theme));
  $$('#densitySegmented button').forEach(b => b.classList.toggle('active', b.dataset.density === state.density));

  const lf = $('#liveFeedToggle'); if (lf) lf.checked = state.liveFeed;
  const ar = $('#autoResponseToggle'); if (ar) ar.checked = state.autoResponse;
  const sd = $('#soundToggle'); if (sd) sd.checked = state.sound;
  const at = $('#alertThreshold'); if (at) at.value = state.alertThreshold;
  const ak = $('#apiKeyInput'); if (ak) ak.value = localStorage.getItem(KEYS.API_KEY) || '';

  if (state.liveFeed) startLiveFeed(); else stopLiveFeed();
}

function toggleTheme() {
  state.theme = state.theme === 'dark' ? 'light' : 'dark';
  localStorage.setItem(KEYS.THEME, state.theme);
  applySettings();
  redrawCanvas();
  toast(`Tema: ${state.theme === 'dark' ? 'scuro' : 'chiaro'}`, 'info');
}

/* =========================================================
   LIVE CLOCK
   ========================================================= */
function tickClock() {
  const el = $('#liveClock');
  if (el) el.textContent = new Date().toLocaleTimeString('it-IT');
}

/* =========================================================
   SPLASH ANIMATION
   ========================================================= */
function animateSplash() {
  const steps = $$('.splash-status-item');
  let i = 0;
  const tick = () => {
    if (i > 0) { steps[i - 1].classList.remove('active'); steps[i - 1].classList.add('done'); }
    if (i >= steps.length) return;
    steps[i].classList.add('active');
    i++;
    if (i < steps.length) setTimeout(tick, 400);
  };
  tick();
}

/* =========================================================
   LIVE FEED
   ========================================================= */
function startLiveFeed() {
  stopLiveFeed();
  state.feedTimer = setInterval(() => {
    if (document.hidden || state.feedPaused) return;
    const newThreat = generateThreat(0);
    state.threats.unshift(newThreat);
    if (state.threats.length > 200) state.threats.pop();

    if (state.autoResponse && newThreat.severity === 'critical' && newThreat.action === 'pending') {
      newThreat.action = 'blocked';
    }

    prependFeedItem(newThreat);
    updateOverviewKPIs();
    if (state.currentView === 'threats') renderThreatsTable();

    const badge = $('#threatsBadge');
    if (badge) badge.textContent = state.threats.filter(t => Date.now() - t.timestamp < 3600000).length;

    // Sound alert
    if (state.sound && newThreat.severity === 'critical') {
      playAlertBeep();
    }

    // Auto-add notification for critical
    if (newThreat.severity === 'critical') {
      state.notifications.unshift({
        type: 'critical',
        title: `${newThreat.type} da ${newThreat.country}`,
        desc: `Target: ${newThreat.target}`,
        time: 'ora',
        read: false
      });
      if (state.notifications.length > 20) state.notifications.pop();
      updateNotifBadge();
    }
  }, 2800);
}

function stopLiveFeed() {
  if (state.feedTimer) { clearInterval(state.feedTimer); state.feedTimer = null; }
}

function prependFeedItem(threat) {
  const feed = $('#threatFeed');
  if (!feed) return;
  const el = document.createElement('div');
  el.className = 'feed-item';
  el.innerHTML = `
    <span class="feed-time">${formatTime(threat.timestamp)}</span>
    <span class="feed-sev ${threat.severity}">${threat.severity}</span>
    <div class="feed-body">
      <b>${escapeHtml(threat.type)}</b> da <b>${escapeHtml(threat.sourceIP)}</b> (${threat.flag} ${escapeHtml(threat.country)})
      <span class="feed-meta">→ ${escapeHtml(threat.target)} · ${threat.action === 'blocked' ? 'BLOCCATO' : 'REVIEW'}</span>
    </div>
  `;
  feed.prepend(el);
  while (feed.children.length > 40) feed.lastChild.remove();
}

/* =========================================================
   LOG STREAM
   ========================================================= */
function startLogStream() {
  stopLogStream();
  state.logTimer = setInterval(() => {
    if (document.hidden) return;
    const log = generateLogLine();
    state.logs.push(log);
    if (state.logs.length > 300) state.logs.shift();
    if (state.currentView === 'logs') appendLogLine(log);
  }, 1400);
}

function stopLogStream() {
  if (state.logTimer) { clearInterval(state.logTimer); state.logTimer = null; }
}

function appendLogLine(log) {
  const el = $('#logsBody');
  if (!el || !matchesLogFilter(log)) return;
  const div = document.createElement('div');
  div.className = 'log-line';
  div.innerHTML = `
    <span class="log-ts">${formatTime(log.ts)}</span>
    <span class="log-level ${log.level}">${log.level}</span>
    <span class="log-src">[${escapeHtml(log.source)}]</span>
    <span class="log-msg">${escapeHtml(log.message)}</span>
  `;
  el.appendChild(div);
  while (el.children.length > 200) el.firstChild.remove();

  const autoScroll = $('#logsAutoScroll');
  if (autoScroll && autoScroll.checked) el.scrollTop = el.scrollHeight;
}

function matchesLogFilter(log) {
  if (state.logFilter.level !== 'all' && log.level !== state.logFilter.level) return false;
  if (state.logFilter.search) {
    const q = state.logFilter.search.toLowerCase();
    if (!log.message.toLowerCase().includes(q) && !log.source.toLowerCase().includes(q)) return false;
  }
  return true;
}

/* =========================================================
   KPI RENDERING
   ========================================================= */
function updateOverviewKPIs() {
  const last24h = state.threats.filter(t => Date.now() - t.timestamp < 86400000);
  const last1h = state.threats.filter(t => Date.now() - t.timestamp < 3600000);
  const blocked = last24h.filter(t => t.action === 'blocked').length;
  const blockedPct = last24h.length ? Math.round(blocked / last24h.length * 100) : 0;
  const criticalCount = last24h.filter(t => t.severity === 'critical').length;
  const openIncidents = state.incidents.filter(i => i.status === 'open' || i.status === 'investigating').length;

  const kpis = [
    { label: 'Threats (24h)', value: last24h.length.toLocaleString('it-IT'), delta: '+12.4%', trend: 'up', icon: 'alert', accent: 'kpi-critical' },
    { label: 'Attacks / hour', value: last1h.length.toString(), delta: 'live', trend: 'neutral', icon: 'bolt', accent: 'kpi-warning' },
    { label: 'Blocked rate', value: blockedPct + '%', delta: '+2.1%', trend: 'up', icon: 'shield', accent: 'kpi-success' },
    { label: 'Open incidents', value: openIncidents.toString(), delta: criticalCount > 0 ? criticalCount + ' critical' : 'stable', trend: criticalCount > 0 ? 'up' : 'down', icon: 'alert', accent: 'kpi-info' }
  ];

  const grid = $('#kpiGrid');
  if (!grid) return;

  if (!grid.children.length) {
    grid.innerHTML = kpis.map(k => `
      <div class="kpi-card ${k.accent}">
        <div class="kpi-head">
          <span class="kpi-label">${escapeHtml(k.label)}</span>
          <span class="kpi-icon">${ICONS[k.icon] || ICONS.shield}</span>
        </div>
        <div class="kpi-value" data-value="${escapeHtml(k.value)}">${escapeHtml(k.value)}</div>
        <div class="kpi-meta">
          <span class="kpi-delta ${k.trend}">${escapeHtml(k.delta)}</span>
          <span class="kpi-period">vs periodo prec.</span>
        </div>
      </div>
    `).join('');
  } else {
    const cards = grid.querySelectorAll('.kpi-value');
    kpis.forEach((k, i) => { if (cards[i]) cards[i].textContent = k.value; });
  }

  renderSeverityRing(last24h);
}

/* =========================================================
   SEVERITY RING
   ========================================================= */
function renderSeverityRing(threats) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  threats.forEach(t => counts[t.severity] = (counts[t.severity] || 0) + 1);

  const ring = $('#severityRing');
  if (ring) {
    if (!ring.querySelector('canvas')) {
      ring.innerHTML = `<canvas></canvas>
        <div class="severity-ring-center">
          <div class="severity-ring-value" id="sevTotal">0</div>
          <div class="severity-ring-label">Threats 24h</div>
        </div>`;
    }
    const totalEl = $('#sevTotal');
    if (totalEl) totalEl.textContent = threats.length.toLocaleString('it-IT');
    drawSeverityCanvas(counts);
  }

  const list = $('#severityList');
  if (list) {
    const colors = { critical: '#dc2626', high: '#ef4444', medium: '#f59e0b', low: '#06b6d4' };
    list.innerHTML = Object.entries(counts).map(([sev, count]) => `
      <div class="severity-item">
        <span class="severity-dot" style="background:${colors[sev]}"></span>
        <span class="severity-label">${sev.charAt(0).toUpperCase() + sev.slice(1)}</span>
        <span class="severity-value">${count}</span>
      </div>
    `).join('');
  }
}

function drawSeverityCanvas(counts) {
  const canvas = $('#severityRing canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  if (rect.width === 0) return;

  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

  const W = rect.width, H = rect.height;
  const cx = W / 2, cy = H / 2;
  const r = Math.min(W, H) / 2 - 14;
  const ir = r * 0.7;

  ctx.clearRect(0, 0, W, H);

  const colors = { critical: '#dc2626', high: '#ef4444', medium: '#f59e0b', low: '#06b6d4' };
  const total = Object.values(counts).reduce((s, v) => s + v, 0);
  let start = -Math.PI / 2;

  if (total === 0) {
    ctx.beginPath();
    ctx.arc(cx, cy, r, 0, Math.PI * 2);
    ctx.arc(cx, cy, ir, Math.PI * 2, 0, true);
    ctx.fillStyle = '#2a2f3a';
    ctx.fill();
  } else {
    Object.entries(counts).forEach(([sev, count]) => {
      if (count === 0) return;
      const angle = (count / total) * Math.PI * 2;
      ctx.beginPath();
      ctx.arc(cx, cy, r, start, start + angle);
      ctx.arc(cx, cy, ir, start + angle, start, true);
      ctx.closePath();
      ctx.fillStyle = colors[sev];
      ctx.fill();
      start += angle;
    });
  }
}

/* =========================================================
   ATTACK MAP
   ========================================================= */
function drawAttackMap() {
  const canvas = $('#attackMap');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  if (rect.width === 0) return;

  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

  const W = rect.width, H = rect.height;

  const css = getComputedStyle(document.body);
  const borderC = css.getPropertyValue('--border').trim();
  const brandC = css.getPropertyValue('--brand').trim();
  const textDim = css.getPropertyValue('--text-dim').trim();

  ctx.clearRect(0, 0, W, H);

  ctx.strokeStyle = borderC;
  ctx.lineWidth = 0.5;
  for (let x = 0; x < W; x += 40) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke(); }
  for (let y = 0; y < H; y += 40) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke(); }

  const dcs = [
    { x: 0.46, y: 0.34, label: 'EU-West' },
    { x: 0.22, y: 0.40, label: 'US-East' },
    { x: 0.12, y: 0.44, label: 'US-West' },
    { x: 0.68, y: 0.52, label: 'AP-South' },
    { x: 0.80, y: 0.44, label: 'AP-NE' }
  ];

  const recent = state.threats.filter(t => Date.now() - t.timestamp < 30 * 60000);
  recent.forEach(t => {
    const target = dcs[randomInt(0, dcs.length - 1)];
    const sx = t.x * W, sy = t.y * H;
    const tx = target.x * W, ty = target.y * H;
    const mx = (sx + tx) / 2, my = (sy + ty) / 2 - 60;

    const colors = {
      critical: 'rgba(220,38,38,.4)',
      high: 'rgba(239,68,68,.3)',
      medium: 'rgba(245,158,11,.25)',
      low: 'rgba(6,182,212,.2)'
    };

    ctx.beginPath();
    ctx.moveTo(sx, sy);
    ctx.quadraticCurveTo(mx, my, tx, ty);
    ctx.strokeStyle = colors[t.severity] || colors.medium;
    ctx.lineWidth = 1;
    ctx.stroke();
  });

  const t = Date.now() / 1000;
  COUNTRIES.forEach(c => {
    const x = c.x * W, y = c.y * H;
    const pulse = 1 + Math.sin(t + c.x * 10) * 0.3;

    const grad = ctx.createRadialGradient(x, y, 0, x, y, 12 * pulse);
    grad.addColorStop(0, 'rgba(220,38,38,.5)');
    grad.addColorStop(1, 'rgba(220,38,38,0)');
    ctx.fillStyle = grad;
    ctx.beginPath(); ctx.arc(x, y, 12 * pulse, 0, Math.PI * 2); ctx.fill();

    ctx.beginPath(); ctx.arc(x, y, 3, 0, Math.PI * 2);
    ctx.fillStyle = '#dc2626'; ctx.fill();
    ctx.beginPath(); ctx.arc(x, y, 1.5, 0, Math.PI * 2);
    ctx.fillStyle = '#fff'; ctx.fill();
  });

  dcs.forEach(dc => {
    const x = dc.x * W, y = dc.y * H;
    ctx.beginPath(); ctx.arc(x, y, 5, 0, Math.PI * 2);
    ctx.fillStyle = brandC; ctx.fill();
    ctx.beginPath(); ctx.arc(x, y, 2.5, 0, Math.PI * 2);
    ctx.fillStyle = '#fff'; ctx.fill();
    ctx.font = '9px JetBrains Mono, monospace';
    ctx.fillStyle = textDim;
    ctx.textAlign = 'center';
    ctx.fillText(dc.label, x, y + 16);
  });

  const mapAttacks = $('#mapAttacks');
  if (mapAttacks) mapAttacks.textContent = Math.round(recent.length / 30) || 0;
  const mapCountries = $('#mapCountries');
  if (mapCountries) mapCountries.textContent = COUNTRIES.length;
  const mapBlocked = $('#mapBlocked');
  if (mapBlocked) mapBlocked.textContent = recent.filter(t => t.action === 'blocked').length;
}

function redrawCanvas() {
  drawAttackMap();
  const last24h = state.threats.filter(t => Date.now() - t.timestamp < 86400000);
  renderSeverityRing(last24h);
}

/* =========================================================
   ASSETS LIST
   ========================================================= */
function renderAssets() {
  const el = $('#assetsList');
  if (!el) return;
  const counts = {};
  state.threats.filter(t => Date.now() - t.timestamp < 86400000).forEach(t => {
    counts[t.target] = (counts[t.target] || 0) + 1;
  });
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const max = sorted[0] ? sorted[0][1] : 1;

  el.innerHTML = sorted.map(([target, count]) => `
    <div class="asset-item" data-target="${escapeHtml(target)}">
      <div class="asset-head">
        <span class="asset-name">${escapeHtml(target)}</span>
        <span class="asset-count">${count}</span>
      </div>
      <div class="asset-bar"><span style="width:${(count / max) * 100}%"></span></div>
      <div class="asset-meta">
        <span>${randomInt(1, 5)} vulnerabilità</span>
        <span>${Math.random() > 0.7 ? 'CRITICAL' : 'monitored'}</span>
      </div>
    </div>
  `).join('');

  el.querySelectorAll('.asset-item').forEach(item => {
    item.addEventListener('click', () => {
      const target = item.dataset.target;
      state.threatFilter.search = target;
      const searchInput = $('#threatsSearch');
      if (searchInput) searchInput.value = target;
      switchView('threats');
      toast(`Filtrate minacce per ${target}`, 'info');
    });
  });
}

/* =========================================================
   INCIDENTS MINI (overview)
   ========================================================= */
function renderIncidentsMini() {
  const el = $('#incidentsMini');
  if (!el) return;
  const list = state.incidents.slice(0, 5);

  el.innerHTML = list.map(inc => `
    <div class="incident-mini" data-incident="${inc.id}">
      <span class="incident-priority ${inc.priority.toLowerCase()}">${inc.priority}</span>
      <div class="incident-info">
        <div class="incident-title">${escapeHtml(inc.title)}</div>
        <div class="incident-meta">${inc.id} · ${escapeHtml(inc.assignee)}</div>
      </div>
      <span class="incident-status ${inc.status}">${statusLabel(inc.status)}</span>
      <span class="incident-time">${timeAgo(inc.timestamp)}</span>
    </div>
  `).join('');

  el.querySelectorAll('.incident-mini').forEach(el => {
    el.addEventListener('click', () => openIncidentModal(el.dataset.incident));
  });
}

function statusLabel(s) {
  const map = { open: 'Open', investigating: 'Investigating', contained: 'Contained', resolved: 'Resolved' };
  return map[s] || s;
}

/* =========================================================
   THREATS TABLE
   ========================================================= */
function getFilteredThreats() {
  let list = [...state.threats];
  if (state.threatFilter.sev !== 'all') list = list.filter(t => t.severity === state.threatFilter.sev);
  if (state.threatFilter.type) list = list.filter(t => t.type === state.threatFilter.type);
  if (state.threatFilter.search) {
    const q = state.threatFilter.search.toLowerCase();
    list = list.filter(t =>
      t.sourceIP.toLowerCase().includes(q) ||
      t.type.toLowerCase().includes(q) ||
      t.target.toLowerCase().includes(q) ||
      t.country.toLowerCase().includes(q) ||
      t.id.toLowerCase().includes(q)
    );
  }

  const { sortField, sortDir } = state.threatFilter;
  list.sort((a, b) => {
    let va = a[sortField], vb = b[sortField];
    if (sortField === 'timestamp') { va = a.timestamp; vb = b.timestamp; }
    if (typeof va === 'string') return sortDir === 'asc' ? va.localeCompare(vb) : vb.localeCompare(va);
    return sortDir === 'asc' ? va - vb : vb - va;
  });

  return list;
}

function renderThreatsTable() {
  const tbody = $('#threatsBody');
  if (!tbody) return;
  const list = getFilteredThreats();

  if (!list.length) {
    tbody.innerHTML = `<tr><td colspan="9" style="text-align:center;padding:40px;color:var(--text-muted)">Nessuna minaccia trovata</td></tr>`;
    return;
  }

  tbody.innerHTML = list.slice(0, 100).map(t => `
    <tr data-threat="${t.id}" class="${state.selectedThreats.has(t.id) ? 'selected' : ''}">
      <td class="col-check"><input type="checkbox" ${state.selectedThreats.has(t.id) ? 'checked' : ''} data-check-threat="${t.id}" /></td>
      <td class="cell-mono">${formatTime(t.timestamp)}</td>
      <td class="cell-mono">${escapeHtml(t.sourceIP)}</td>
      <td>${t.flag} ${escapeHtml(t.country)}</td>
      <td>${escapeHtml(t.type)}</td>
      <td class="cell-mono">${escapeHtml(t.target)}</td>
      <td><span class="severity-pill ${t.severity}">${t.severity}</span></td>
      <td><span class="action-pill ${t.action}">${t.action}</span></td>
      <td>
        <div class="row-actions">
          <button class="row-action" data-action="view" title="Dettagli">${ICONS.eye}</button>
          <button class="row-action" data-action="block" title="Blocca IP">${ICONS.block}</button>
        </div>
      </td>
    </tr>
  `).join('');

  tbody.querySelectorAll('tr').forEach(row => {
    row.addEventListener('click', (e) => {
      if (e.target.closest('input[type="checkbox"]') || e.target.closest('.row-action')) return;
      openThreatModal(row.dataset.threat);
    });
  });

  tbody.querySelectorAll('[data-check-threat]').forEach(cb => {
    cb.addEventListener('change', (e) => {
      const id = e.target.dataset.checkThreat;
      if (e.target.checked) state.selectedThreats.add(id);
      else state.selectedThreats.delete(id);
      updateThreatsBulk();
      e.target.closest('tr').classList.toggle('selected', e.target.checked);
    });
  });

  tbody.querySelectorAll('.row-action').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const id = btn.closest('tr').dataset.threat;
      if (btn.dataset.action === 'block') blockThreat(id);
      else openThreatModal(id);
    });
  });

  updateThreatsBulk();
}

function updateThreatsBulk() {
  const bar = $('#threatsBulkBar');
  const count = state.selectedThreats.size;
  if (bar) bar.classList.toggle('hidden', count === 0);
  const c = $('#threatsSelectedCount');
  if (c) c.textContent = count;
}

function blockThreat(id) {
  const t = state.threats.find(x => x.id === id);
  if (!t) return;
  t.action = 'blocked';
  toast(`IP ${t.sourceIP} bloccato`, 'success');
  renderThreatsTable();
  updateOverviewKPIs();
}

/* =========================================================
   THREATS STATS
   ========================================================= */
function renderThreatsStats() {
  const el = $('#threatsStats');
  if (!el) return;
  const last24h = state.threats.filter(t => Date.now() - t.timestamp < 86400000);
  const critical = last24h.filter(t => t.severity === 'critical').length;
  const high = last24h.filter(t => t.severity === 'high').length;
  const blocked = last24h.filter(t => t.action === 'blocked').length;
  const uniqueIPs = new Set(last24h.map(t => t.sourceIP)).size;

  el.innerHTML = `
    <div class="stat-card">
      <div class="stat-card-label">Total threats</div>
      <div class="stat-card-value">${last24h.length}</div>
      <div class="stat-card-meta">Ultime 24 ore</div>
    </div>
    <div class="stat-card">
      <div class="stat-card-label">Critical</div>
      <div class="stat-card-value" style="color:var(--critical)">${critical}</div>
      <div class="stat-card-meta">Richiedono azione</div>
    </div>
    <div class="stat-card">
      <div class="stat-card-label">High</div>
      <div class="stat-card-value" style="color:var(--danger)">${high}</div>
      <div class="stat-card-meta">Review entro 1h</div>
    </div>
    <div class="stat-card">
      <div class="stat-card-label">Blocked</div>
      <div class="stat-card-value" style="color:var(--success)">${blocked}</div>
      <div class="stat-card-meta">${Math.round(blocked / last24h.length * 100) || 0}% del totale</div>
    </div>
    <div class="stat-card">
      <div class="stat-card-label">Unique IPs</div>
      <div class="stat-card-value">${uniqueIPs}</div>
      <div class="stat-card-meta">Attaccanti distinti</div>
    </div>
  `;
}

/* =========================================================
   INCIDENTS
   ========================================================= */
function getFilteredIncidents() {
  let list = [...state.incidents];
  if (state.incidentFilter.status !== 'all') list = list.filter(i => i.status === state.incidentFilter.status);
  return list.sort((a, b) => b.timestamp - a.timestamp);
}

function renderIncidentsView() {
  renderIncidentsStats();
  const el = $('#incidentsList');
  if (!el) return;
  const list = getFilteredIncidents();

  if (!list.length) {
    el.innerHTML = `<div style="text-align:center;padding:60px 20px;color:var(--text-muted)">Nessun incidente trovato</div>`;
    return;
  }

  el.innerHTML = list.map((inc, i) => `
    <div class="incident-card ${inc.priority.toLowerCase()}" data-incident="${inc.id}" style="animation-delay:${i * 40}ms">
      <div class="incident-card-head">
        <div>
          <div class="incident-card-title">${escapeHtml(inc.title)}</div>
          <div class="incident-card-id">${inc.id} · ${inc.category}</div>
        </div>
        <span class="incident-priority ${inc.priority.toLowerCase()}">${inc.priority}</span>
      </div>
      <div class="incident-card-desc">${escapeHtml(inc.description)}</div>
      <div class="incident-card-meta">
        <span>Status: <strong>${statusLabel(inc.status)}</strong></span>
        <span>Assignee: <strong>${escapeHtml(inc.assignee)}</strong></span>
        <span>Opened: <strong>${timeAgo(inc.timestamp)}</strong></span>
        <span>Assets: <strong>${inc.assets.length}</strong></span>
      </div>
    </div>
  `).join('');

  el.querySelectorAll('.incident-card').forEach(card => {
    card.addEventListener('click', () => openIncidentModal(card.dataset.incident));
  });
}

function renderIncidentsStats() {
  const el = $('#incidentsStats');
  if (!el) return;
  const total = state.incidents.length;
  const open = state.incidents.filter(i => i.status === 'open').length;
  const investigating = state.incidents.filter(i => i.status === 'investigating').length;
  const p1 = state.incidents.filter(i => i.priority === 'P1' && i.status !== 'resolved').length;

  el.innerHTML = `
    <div class="stat-card">
      <div class="stat-card-label">Total incidents</div>
      <div class="stat-card-value">${total}</div>
      <div class="stat-card-meta">Ultimi 30 giorni</div>
    </div>
    <div class="stat-card">
      <div class="stat-card-label">Open</div>
      <div class="stat-card-value" style="color:var(--critical)">${open}</div>
      <div class="stat-card-meta">Da assegnare</div>
    </div>
    <div class="stat-card">
      <div class="stat-card-label">Investigating</div>
      <div class="stat-card-value" style="color:var(--warning)">${investigating}</div>
      <div class="stat-card-meta">In analisi</div>
    </div>
    <div class="stat-card">
      <div class="stat-card-label">Active P1</div>
      <div class="stat-card-value" style="color:var(--critical)">${p1}</div>
      <div class="stat-card-meta">Critici aperti</div>
    </div>
  `;
}

/* =========================================================
   VULNERABILITIES
   ========================================================= */
function getFilteredVulns() {
  let list = [...state.vulnerabilities];
  if (state.vulnFilter.sev) list = list.filter(v => v.severity === state.vulnFilter.sev);
  if (state.vulnFilter.status) list = list.filter(v => v.status === state.vulnFilter.status);
  if (state.vulnFilter.search) {
    const q = state.vulnFilter.search.toLowerCase();
    list = list.filter(v =>
      v.cve.toLowerCase().includes(q) ||
      v.description.toLowerCase().includes(q) ||
      v.asset.toLowerCase().includes(q) ||
      v.vendor.toLowerCase().includes(q)
    );
  }
  return list.sort((a, b) => b.cvss - a.cvss);
}

function renderVulnStats() {
  const el = $('#vulnStats');
  if (!el) return;
  const critical = state.vulnerabilities.filter(v => v.severity === 'critical').length;
  const high = state.vulnerabilities.filter(v => v.severity === 'high').length;
  const open = state.vulnerabilities.filter(v => v.status === 'open').length;
  const avgCvss = (state.vulnerabilities.reduce((s, v) => s + v.cvss, 0) / state.vulnerabilities.length).toFixed(1);

  el.innerHTML = `
    <div class="stat-card">
      <div class="stat-card-label">Total CVEs</div>
      <div class="stat-card-value">${state.vulnerabilities.length}</div>
      <div class="stat-card-meta">Rilevate dallo scanner</div>
    </div>
    <div class="stat-card">
      <div class="stat-card-label">Critical</div>
      <div class="stat-card-value" style="color:var(--critical)">${critical}</div>
      <div class="stat-card-meta">CVSS ≥ 9.0</div>
    </div>
    <div class="stat-card">
      <div class="stat-card-label">High</div>
      <div class="stat-card-value" style="color:var(--danger)">${high}</div>
      <div class="stat-card-meta">CVSS 7.0-8.9</div>
    </div>
    <div class="stat-card">
      <div class="stat-card-label">Open</div>
      <div class="stat-card-value" style="color:var(--warning)">${open}</div>
      <div class="stat-card-meta">Non patched</div>
    </div>
    <div class="stat-card">
      <div class="stat-card-label">Avg CVSS</div>
      <div class="stat-card-value">${avgCvss}</div>
      <div class="stat-card-meta">Score medio</div>
    </div>
  `;
}

function renderVulnTable() {
  renderVulnStats();
  const tbody = $('#vulnBody');
  if (!tbody) return;
  const list = getFilteredVulns();

  if (!list.length) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:40px;color:var(--text-muted)">Nessuna vulnerabilità trovata</td></tr>`;
    return;
  }

  tbody.innerHTML = list.map(v => `
    <tr data-cve="${escapeHtml(v.cve)}">
      <td class="cell-mono">${escapeHtml(v.cve)}</td>
      <td class="cell-mono" style="font-weight:700">${v.cvss}</td>
      <td><span class="severity-pill ${v.severity}">${v.severity}</span></td>
      <td>${escapeHtml(v.description)}</td>
      <td class="cell-mono">${escapeHtml(v.asset)}</td>
      <td><span class="action-pill ${v.status === 'patched' ? 'blocked' : v.status === 'patching' ? 'pending' : 'allowed'}">${v.status}</span></td>
      <td class="cell-mono muted">${formatDate(v.published)}</td>
    </tr>
  `).join('');

  tbody.querySelectorAll('tr').forEach(row => {
    row.addEventListener('click', () => openCveModal(row.dataset.cve));
  });
}

/* =========================================================
   LOGS
   ========================================================= */
function renderLogsView() {
  const el = $('#logsBody');
  if (!el) return;
  el.innerHTML = '';
  state.logs.filter(matchesLogFilter).forEach(log => {
    const div = document.createElement('div');
    div.className = 'log-line';
    div.innerHTML = `
      <span class="log-ts">${formatTime(log.ts)}</span>
      <span class="log-level ${log.level}">${log.level}</span>
      <span class="log-src">[${escapeHtml(log.source)}]</span>
      <span class="log-msg">${escapeHtml(log.message)}</span>
    `;
    el.appendChild(div);
  });
  el.scrollTop = el.scrollHeight;
}

/* =========================================================
   PLAYBOOKS
   ========================================================= */
function renderPlaybooks() {
  const el = $('#playbooksGrid');
  if (!el) return;

  el.innerHTML = state.playbooks.map((pb, i) => `
    <div class="playbook-card" data-playbook="${pb.id}" style="animation-delay:${i * 40}ms">
      <div class="playbook-icon">${ICONS[pb.icon] || ICONS.shield}</div>
      <div class="playbook-body">
        <div class="playbook-title">${escapeHtml(pb.name)}</div>
        <div class="playbook-desc">${escapeHtml(pb.desc)}</div>
        <div class="playbook-tags">
          ${pb.tags.map(t => `<span class="playbook-tag">${escapeHtml(t)}</span>`).join('')}
        </div>
      </div>
      <div class="playbook-meta">
        <span>${pb.steps.length} steps</span>
        <span class="playbook-automation ${pb.automation}">
          ${pb.automation === 'auto' ? '⚡ Automatic' : '👤 Manual'}
        </span>
      </div>
    </div>
  `).join('');

  el.querySelectorAll('.playbook-card').forEach(card => {
    card.addEventListener('click', () => openPlaybookModal(card.dataset.playbook));
  });
}

/* =========================================================
   COMPLIANCE
   ========================================================= */
function renderCompliance() {
  const el = $('#complianceGrid');
  if (!el) return;

  el.innerHTML = state.compliance.map((fw, i) => {
    const scoreClass = fw.score >= 85 ? 'good' : fw.score >= 70 ? 'warn' : 'bad';
    const total = randomInt(60, 200);
    const passed = Math.round(total * fw.score / 100);
    const failed = Math.round(total * (100 - fw.score) / 100 * 0.6);
    const partial = total - passed - failed;

    return `
      <div class="compliance-card" data-framework="${escapeHtml(fw.name)}" style="animation-delay:${i * 40}ms">
        <div class="compliance-head">
          <div>
            <div class="compliance-name">${escapeHtml(fw.name)}</div>
            <div class="compliance-full">${escapeHtml(fw.full)}</div>
          </div>
          <div class="compliance-score ${scoreClass}">${fw.score}%</div>
        </div>
        <div class="compliance-bar"><span class="${scoreClass}" style="width:${fw.score}%"></span></div>
        <div class="compliance-stats">
          <div class="compliance-stat">
            <div class="compliance-stat-value" style="color:var(--success)">${passed}</div>
            <div class="compliance-stat-label">Passed</div>
          </div>
          <div class="compliance-stat">
            <div class="compliance-stat-value" style="color:var(--warning)">${partial}</div>
            <div class="compliance-stat-label">Partial</div>
          </div>
          <div class="compliance-stat">
            <div class="compliance-stat-value" style="color:var(--danger)">${failed}</div>
            <div class="compliance-stat-label">Failed</div>
          </div>
        </div>
      </div>
    `;
  }).join('');

  el.querySelectorAll('.compliance-card').forEach(card => {
    card.addEventListener('click', () => openComplianceModal(card.dataset.framework));
  });
}

/* =========================================================
   NOTIFICATIONS
   ========================================================= */
function updateNotifBadge() {
  const badge = $('#notifBadge');
  const sub = $('#notifModalSub');
  const unread = state.notifications.filter(n => !n.read).length;
  if (badge) {
    badge.textContent = unread;
    badge.style.display = unread ? 'grid' : 'none';
  }
  if (sub) sub.textContent = `${unread} non lette`;
}

function renderNotifList() {
  const list = $('#notifList');
  if (!list) return;
  if (!state.notifications.length) {
    list.innerHTML = `<div class="notif-empty">Nessuna notifica</div>`;
    return;
  }
  const iconMap = { critical: 'alert', warning: 'alert', success: 'check', info: 'sparkle' };
  list.innerHTML = state.notifications.map((n, i) => `
    <div class="notif-item ${n.read ? '' : 'unread'} ${n.type}" data-notif="${i}">
      <span class="notif-item-icon ${n.type}">${ICONS[iconMap[n.type]] || ICONS.sparkle}</span>
      <div class="notif-item-body">
        <div class="notif-item-title">${escapeHtml(n.title)}</div>
        <div class="notif-item-desc">${escapeHtml(n.desc)}</div>
        <span class="notif-item-time">${escapeHtml(n.time)}</span>
      </div>
    </div>
  `).join('');

  list.querySelectorAll('.notif-item').forEach(item => {
    item.addEventListener('click', () => {
      const i = Number(item.dataset.notif);
      state.notifications[i].read = true;
      renderNotifList();
      updateNotifBadge();
    });
  });
}

/* =========================================================
   TENANTS
   ========================================================= */
function renderTenantList() {
  const el = $('#tenantList');
  if (!el) return;
  el.innerHTML = state.tenants.map(t => `
    <button class="tenant-item ${t.id === state.tenant ? 'active' : ''}" data-tenant="${t.id}">
      <span class="tenant-item-avatar" style="background:${t.color}">${t.initials}</span>
      <div class="tenant-item-info">
        <strong>${escapeHtml(t.name)}</strong>
        <small>${escapeHtml(t.plan)}</small>
      </div>
      <span class="tenant-item-check">${ICONS.check}</span>
    </button>
  `).join('');

  el.querySelectorAll('.tenant-item').forEach(btn => {
    btn.addEventListener('click', () => {
      const t = state.tenants.find(x => x.id === btn.dataset.tenant);
      if (!t) return;
      state.tenant = t.id;
      localStorage.setItem(KEYS.TENANT, t.id);
      const nameEl = $('#tenantName');
      const bcEl = $('#bcTenant');
      if (nameEl) nameEl.textContent = t.name;
      if (bcEl) bcEl.textContent = t.name;
      closeModal('tenantModal');
      toast(`Tenant: ${t.name}`, 'success');
      renderTenantList();
    });
  });
}

/* =========================================================
   VIEW SWITCHING
   ========================================================= */
function switchView(view) {
  state.currentView = view;
  $$('.view').forEach(v => v.classList.toggle('active', v.id === `view-${view}`));
  $$('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.view === view));

  const titles = {
    overview: 'Overview',
    threats: 'Threat Intelligence',
    incidents: 'Incident Response',
    vulnerabilities: 'Vulnerability Management',
    logs: 'Log Analyzer',
    playbooks: 'Response Playbooks',
    compliance: 'Compliance',
    settings: 'Settings'
  };
  const bc = $('#bcCurrent');
  if (bc) bc.textContent = titles[view] || 'Overview';

  const vc = $('#viewContainer');
  if (vc) vc.scrollTop = 0;

  if (view === 'threats') { renderThreatsStats(); renderThreatsTable(); }
  if (view === 'incidents') renderIncidentsView();
  if (view === 'vulnerabilities') renderVulnTable();
  if (view === 'logs') renderLogsView();
  if (view === 'playbooks') renderPlaybooks();
  if (view === 'compliance') renderCompliance();
  if (view === 'overview') {
    requestAnimationFrame(() => {
      drawAttackMap();
      updateOverviewKPIs();
    });
  }
}

/* =========================================================
   MODALS
   ========================================================= */
function openModal(id) { const el = $(`#${id}`); if (el) el.classList.add('open'); }
function closeModal(id) { const el = $(`#${id}`); if (el) el.classList.remove('open'); }

/* Threat detail */
function openThreatModal(id) {
  const t = state.threats.find(x => x.id === id);
  if (!t) return;

  const titleEl = $('#threatModalTitle');
  const subEl = $('#threatModalSub');
  const bodyEl = $('#threatModalBody');
  if (titleEl) titleEl.textContent = t.type;
  if (subEl) subEl.textContent = `${t.id} · ${formatTime(t.timestamp)}`;

  if (bodyEl) {
    bodyEl.innerHTML = `
      <div class="threat-detail-grid">
        <div class="threat-detail-item"><label>Source IP</label><span>${escapeHtml(t.sourceIP)}</span></div>
        <div class="threat-detail-item"><label>Country</label><span>${t.flag} ${escapeHtml(t.country)}</span></div>
        <div class="threat-detail-item"><label>Target</label><span>${escapeHtml(t.target)}</span></div>
        <div class="threat-detail-item"><label>Port</label><span>${t.port}</span></div>
        <div class="threat-detail-item"><label>Severity</label><span><span class="severity-pill ${t.severity}">${t.severity}</span></span></div>
        <div class="threat-detail-item"><label>Action</label><span><span class="action-pill ${t.action}">${t.action}</span></span></div>
      </div>
      <div class="detail-section">
        <div class="detail-section-title">User Agent</div>
        <div class="cell-mono">${escapeHtml(t.userAgent)}</div>
      </div>
      <div class="detail-section">
        <div class="detail-section-title">MITRE ATT&CK Techniques</div>
        <div class="mitre-tags">${t.mitre.map(m => `<span class="mitre-tag">${escapeHtml(m)}</span>`).join('')}</div>
      </div>
      <div class="detail-section">
        <div class="detail-section-title">Attack Log</div>
        <div class="attack-log">${escapeHtml(t.log)
          .replace(/\[OK\]/g, '<span class="log-ok">[OK]</span>')
          .replace(/\[ERR\]/g, '<span class="log-err">[ERR]</span>')
          .replace(/\[WARN\]/g, '<span class="log-warn">[WARN]</span>')}</div>
      </div>
    `;
  }

  const blockBtn = $('#threatBlockBtn');
  if (blockBtn) blockBtn.onclick = () => { blockThreat(t.id); closeModal('threatModal'); };

  const incBtn = $('#threatIncidentBtn');
  if (incBtn) incBtn.onclick = () => {
    const newInc = {
      id: uid('INC'), timestamp: Date.now(),
      title: `${t.type} attack from ${t.sourceIP}`,
      description: `Threat rilevato: ${t.type} da ${t.sourceIP} (${t.country}). Target: ${t.target}. Severity: ${t.severity}.`,
      priority: t.severity === 'critical' ? 'P1' : t.severity === 'high' ? 'P2' : 'P3',
      category: 'Unauthorized Access', status: 'open',
      assignee: randomFrom(ASSIGNEES), assets: [t.target],
      timeline: [{ time: Date.now(), event: 'Incident created from threat ' + t.id, actor: 'system' }]
    };
    state.incidents.unshift(newInc);
    closeModal('threatModal');
    toast(`Incidente ${newInc.id} creato`, 'success');
    if (state.currentView === 'incidents') renderIncidentsView();
    renderIncidentsMini();
  };

  openModal('threatModal');
}

/* Incident detail */
function openIncidentModal(id) {
  const inc = state.incidents.find(x => x.id === id);
  if (!inc) return;

  const titleEl = $('#incidentModalTitle');
  const subEl = $('#incidentModalSub');
  const bodyEl = $('#incidentModalBody');
  if (titleEl) titleEl.textContent = inc.title;
  if (subEl) subEl.textContent = `${inc.id} · ${inc.priority} · ${formatDate(inc.timestamp)}`;

  if (bodyEl) {
    bodyEl.innerHTML = `
      <div class="threat-detail-grid">
        <div class="threat-detail-item"><label>Priority</label><span><span class="incident-priority ${inc.priority.toLowerCase()}">${inc.priority}</span></span></div>
        <div class="threat-detail-item"><label>Status</label><span><span class="incident-status ${inc.status}">${statusLabel(inc.status)}</span></span></div>
        <div class="threat-detail-item"><label>Category</label><span>${escapeHtml(inc.category)}</span></div>
        <div class="threat-detail-item"><label>Assignee</label><span>${escapeHtml(inc.assignee)}</span></div>
        <div class="threat-detail-item"><label>Opened</label><span>${formatDate(inc.timestamp)} ${formatTime(inc.timestamp)}</span></div>
        <div class="threat-detail-item"><label>Assets</label><span>${inc.assets.length}</span></div>
      </div>
      <div class="detail-section">
        <div class="detail-section-title">Description</div>
        <p style="font-size:.86rem;color:var(--text-muted);line-height:1.7">${escapeHtml(inc.description)}</p>
      </div>
      <div class="detail-section">
        <div class="detail-section-title">Affected Assets</div>
        <div class="mitre-tags">${inc.assets.map(a => `<span class="mitre-tag">${escapeHtml(a)}</span>`).join('')}</div>
      </div>
      <div class="detail-section">
        <div class="detail-section-title">Timeline</div>
        <div class="playbook-steps">
          ${inc.timeline.map((e, i) => `
            <div class="playbook-step">
              <div class="playbook-step-num">${i + 1}</div>
              <div class="playbook-step-body">
                <div class="playbook-step-title">${escapeHtml(e.event)}</div>
                <div class="playbook-step-desc">${escapeHtml(e.actor)} · ${formatTime(e.time)}</div>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  const advBtn = $('#incidentAdvanceBtn');
  if (advBtn) advBtn.onclick = () => {
    const order = ['open', 'investigating', 'contained', 'resolved'];
    const idx = order.indexOf(inc.status);
    if (idx < order.length - 1) {
      inc.status = order[idx + 1];
      inc.timeline.push({ time: Date.now(), event: 'Status changed to ' + statusLabel(inc.status), actor: 'nowii-core' });
      toast(`Incidente aggiornato: ${statusLabel(inc.status)}`, 'success');
      openIncidentModal(id);
      renderIncidentsView();
      renderIncidentsMini();
    } else {
      toast('Incidente già risolto', 'info');
    }
  };

  openModal('incidentModal');
}

/* Playbook detail */
function openPlaybookModal(id) {
  const pb = state.playbooks.find(x => x.id === id);
  if (!pb) return;

  const titleEl = $('#playbookModalTitle');
  const subEl = $('#playbookModalSub');
  const bodyEl = $('#playbookModalBody');
  if (titleEl) titleEl.textContent = pb.name;
  if (subEl) subEl.textContent = pb.desc;

  if (bodyEl) {
    bodyEl.innerHTML = `
      <div class="detail-section">
        <div class="detail-section-title">Steps (${pb.steps.length})</div>
        <div class="playbook-steps">
          ${pb.steps.map((s, i) => `
            <div class="playbook-step">
              <div class="playbook-step-num">${i + 1}</div>
              <div class="playbook-step-body">
                <div class="playbook-step-title">${escapeHtml(s.title)}</div>
                <div class="playbook-step-desc">${escapeHtml(s.desc)}</div>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  const runBtn = $('#playbookRunBtn');
  if (runBtn) runBtn.onclick = () => {
    toast(`Playbook "${pb.name}" avviato`, 'info');
    closeModal('playbookModal');
    setTimeout(() => toast(`Playbook completato con successo`, 'success'), 1500);
  };

  openModal('playbookModal');
}

/* CVE detail */
function openCveModal(cveId) {
  const v = state.vulnerabilities.find(x => x.cve === cveId);
  if (!v) return;

  const titleEl = $('#cveModalTitle');
  const subEl = $('#cveModalSub');
  const bodyEl = $('#cveModalBody');
  if (titleEl) titleEl.textContent = v.cve;
  if (subEl) subEl.textContent = `${v.vendor} · ${v.asset}`;

  if (bodyEl) {
    bodyEl.innerHTML = `
      <div class="cve-score-hero">
        <div class="cve-score-circle ${v.severity}">${v.cvss}</div>
        <div class="cve-score-info">
          <h3>${escapeHtml(v.cve)}</h3>
          <p>${escapeHtml(v.description)}</p>
        </div>
      </div>
      <div class="threat-detail-grid">
        <div class="threat-detail-item"><label>Vendor</label><span>${escapeHtml(v.vendor)}</span></div>
        <div class="threat-detail-item"><label>Affected Asset</label><span>${escapeHtml(v.asset)}</span></div>
        <div class="threat-detail-item"><label>CVSS Score</label><span>${v.cvss}</span></div>
        <div class="threat-detail-item"><label>Severity</label><span><span class="severity-pill ${v.severity}">${v.severity}</span></span></div>
        <div class="threat-detail-item"><label>Status</label><span><span class="action-pill ${v.status === 'patched' ? 'blocked' : v.status === 'patching' ? 'pending' : 'allowed'}">${v.status}</span></span></div>
        <div class="threat-detail-item"><label>Published</label><span>${formatDate(v.published)}</span></div>
      </div>
    `;
  }

  const patchBtn = $('#cvePatchBtn');
  if (patchBtn) patchBtn.onclick = () => {
    v.status = 'patched';
    toast(`${v.cve} marcata come patched`, 'success');
    closeModal('cveModal');
    renderVulnTable();
  };

  openModal('cveModal');
}

/* Compliance detail */
function openComplianceModal(name) {
  const fw = state.compliance.find(x => x.name === name);
  if (!fw) return;

  const titleEl = $('#complianceModalTitle');
  const subEl = $('#complianceModalSub');
  const bodyEl = $('#complianceModalBody');
  if (titleEl) titleEl.textContent = fw.name;
  if (subEl) subEl.textContent = fw.full;

  if (bodyEl) {
    const controls = Array.from({ length: 20 }, (_, i) => {
      const statuses = ['passed', 'passed', 'passed', 'partial', 'failed'];
      const status = randomFrom(statuses);
      return { id: `A.${randomInt(5, 18)}.${randomInt(1, 3)}`, status };
    });

    bodyEl.innerHTML = `
      <div class="compliance-detail">
        <div class="threat-detail-grid">
          <div class="threat-detail-item"><label>Framework</label><span>${escapeHtml(fw.name)}</span></div>
          <div class="threat-detail-item"><label>Score</label><span>${fw.score}%</span></div>
        </div>
      </div>
      <div class="detail-section">
        <div class="detail-section-title">Controlli (sample)</div>
        <div class="compliance-controls-list">
          ${controls.map(c => `
            <div class="compliance-control">
              <span><span class="compliance-control-id">${c.id}</span>Control description</span>
              <span class="compliance-control-status ${c.status}">${c.status}</span>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  const exportBtn = $('#exportComplianceBtn');
  if (exportBtn) exportBtn.onclick = () => {
    downloadFile(`compliance-${fw.name.replace(/\s+/g, '-')}.csv`,
      `Framework,Full,Score\n"${fw.name}","${fw.full}","${fw.score}%"`);
    toast('Report compliance esportato', 'success');
  };

  openModal('complianceModal');
}

/* =========================================================
   EXPORT
   ========================================================= */
function exportThreatsCSV() {
  const list = getFilteredThreats();
  const headers = ['ID', 'Timestamp', 'Source IP', 'Country', 'Attack Type', 'Target', 'Severity', 'Action', 'Port'];
  const rows = list.map(t => [t.id, new Date(t.timestamp).toISOString(), t.sourceIP, t.country, t.type, t.target, t.severity, t.action, t.port]);
  const csv = [headers, ...rows].map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n');
  downloadFile(`sentinel-threats-${Date.now()}.csv`, csv);
  toast(`Esportate ${list.length} minacce`, 'success');
}

function exportLogsCSV() {
  const list = state.logs.filter(matchesLogFilter);
  const headers = ['Timestamp', 'Level', 'Source', 'Message'];
  const rows = list.map(l => [new Date(l.ts).toISOString(), l.level, l.source, l.message]);
  const csv = [headers, ...rows].map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n');
  downloadFile(`sentinel-logs-${Date.now()}.csv`, csv);
  toast(`Esportati ${list.length} log`, 'success');
}

function exportAllJSON() {
  const dump = {
    exported: new Date().toISOString(),
    threats: state.threats.slice(0, 100),
    incidents: state.incidents,
    vulnerabilities: state.vulnerabilities,
    compliance: state.compliance
  };
  downloadFile(`sentinel-export-${Date.now()}.json`, JSON.stringify(dump, null, 2), 'application/json');
  toast('Export completo generato', 'success');
}

/* =========================================================
   COMMAND PALETTE
   ========================================================= */
function openCmdPalette() {
  state.cmdSelectedIndex = 0;
  renderCmdResults('');
  openModal('cmdBackdrop');
  setTimeout(() => { const inp = $('#cmdInput'); if (inp) inp.focus(); }, 50);
}

function renderCmdResults(query) {
  const el = $('#cmdResults');
  if (!el) return;
  const q = query.trim().toLowerCase();

  const allViews = [
    { label: 'Overview', desc: 'Dashboard principale', action: () => switchView('overview') },
    { label: 'Threats', desc: 'Feed minacce live', action: () => switchView('threats') },
    { label: 'Incidents', desc: 'Gestione incidenti', action: () => switchView('incidents') },
    { label: 'Vulnerabilities', desc: 'CVE management', action: () => switchView('vulnerabilities') },
    { label: 'Logs', desc: 'Log analyzer', action: () => switchView('logs') },
    { label: 'Playbooks', desc: 'Response playbooks', action: () => switchView('playbooks') },
    { label: 'Compliance', desc: 'Framework compliance', action: () => switchView('compliance') },
    { label: 'Settings', desc: 'Configurazione', action: () => switchView('settings') }
  ];

  const allActions = [
    { label: 'Nuovo incidente', desc: 'Crea un incidente', action: () => openModal('newIncidentModal') },
    { label: 'Esporta threats CSV', desc: 'Scarica minacce', action: exportThreatsCSV },
    { label: 'Esporta logs CSV', desc: 'Scarica log', action: exportLogsCSV },
    { label: 'Export completo JSON', desc: 'Backup dati', action: exportAllJSON },
    { label: 'Cambia tema', desc: 'Dark / Light', action: toggleTheme },
    { label: 'Aiuto', desc: 'Scorciatoie tastiera', action: () => openModal('helpModal') }
  ];

  const results = { views: [], actions: [], threats: [], incidents: [] };

  if (q) {
    results.views = allViews.filter(v => v.label.toLowerCase().includes(q) || v.desc.toLowerCase().includes(q));
    results.actions = allActions.filter(a => a.label.toLowerCase().includes(q) || a.desc.toLowerCase().includes(q));
    results.threats = state.threats.filter(t =>
      t.sourceIP.toLowerCase().includes(q) || t.type.toLowerCase().includes(q) || t.target.toLowerCase().includes(q)
    ).slice(0, 5);
    results.incidents = state.incidents.filter(i =>
      i.title.toLowerCase().includes(q) || i.id.toLowerCase().includes(q)
    ).slice(0, 5);
  } else {
    results.views = allViews;
    results.actions = allActions;
  }

  state.cmdFlatItems = [];
  let html = '';

  const renderSection = (title, items, renderer) => {
    if (!items.length) return;
    html += `<div class="cmd-section">${title}</div>`;
    items.forEach(item => {
      const idx = state.cmdFlatItems.length;
      state.cmdFlatItems.push(item);
      html += renderer(item, idx);
    });
  };

  renderSection('Viste', results.views, (v, i) => `
    <button class="cmd-item" data-idx="${i}">${ICONS.shield}<div class="cmd-item-text"><strong>${escapeHtml(v.label)}</strong><small>${escapeHtml(v.desc)}</small></div></button>
  `);
  renderSection('Azioni', results.actions, (a, i) => `
    <button class="cmd-item" data-idx="${i}">${ICONS.bolt}<div class="cmd-item-text"><strong>${escapeHtml(a.label)}</strong><small>${escapeHtml(a.desc)}</small></div></button>
  `);
  renderSection('Threats', results.threats, (t, i) => `
    <button class="cmd-item" data-idx="${i}">${ICONS.alert}<div class="cmd-item-text"><strong>${escapeHtml(t.type)} — ${escapeHtml(t.sourceIP)}</strong><small>${escapeHtml(t.country)} → ${escapeHtml(t.target)}</small></div></button>
  `);
  renderSection('Incidents', results.incidents, (inc, i) => `
    <button class="cmd-item" data-idx="${i}">${ICONS.alert}<div class="cmd-item-text"><strong>${escapeHtml(inc.title)}</strong><small>${inc.id} · ${inc.priority}</small></div></button>
  `);

  if (!state.cmdFlatItems.length) {
    html = `<div style="padding:40px;text-align:center;color:var(--text-muted);font-size:.82rem">Nessun risultato per "<b>${escapeHtml(query)}</b>"</div>`;
  }

  el.innerHTML = html;

  el.querySelectorAll('[data-idx]').forEach(btn => {
    btn.addEventListener('click', () => {
      const item = state.cmdFlatItems[Number(btn.dataset.idx)];
      closeModal('cmdBackdrop');
      if (!item) return;
      setTimeout(() => {
        if (item.action) item.action();
        else if (item.id && item.sourceIP) openThreatModal(item.id);
        else if (item.id && item.priority) openIncidentModal(item.id);
      }, 100);
    });
  });

  updateCmdSelection();
}

function updateCmdSelection() {
  const items = $$('.cmd-item');
  items.forEach((el, i) => el.classList.toggle('selected', i === state.cmdSelectedIndex));
}

/* =========================================================
   SOUND
   ========================================================= */
function playAlertBeep() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.frequency.value = 880;
    osc.type = 'sine';
    gain.gain.setValueAtTime(0.1, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.2);
    osc.start();
    osc.stop(ctx.currentTime + 0.2);
  } catch (e) { /* ignore */ }
}

/* =========================================================
   ONBOARDING
   ========================================================= */
const ONBOARDING_STEPS = [
  {
    title: 'Benvenuto in nowii·sentinel',
    body: 'Questa è la piattaforma di Security Operations per monitorare minacce, gestire incidenti e garantire la conformità.',
    list: [
      'Threat feed in tempo reale da tutto il mondo',
      'Gestione completa del ciclo di vita degli incidenti',
      'Scansione CVE e vulnerability management'
    ]
  },
  {
    title: 'Monitora le minacce live',
    body: 'Il feed aggiorna ogni pochi secondi mostrando attacchi in corso contro la tua infrastruttura.',
    list: ['<strong>R</strong> per aggiornare manualmente', '<strong>P</strong> per pausare il feed', 'Click su una riga per i dettagli']
  },
  {
    title: 'Command Palette',
    body: 'Accedi velocemente a qualsiasi azione, vista o dato con la palette dei comandi.',
    list: ['<kbd>⌘</kbd><kbd>K</kbd> per aprirla', 'Cerca tra minacce, incidenti, CVE, comandi', '<kbd>1</kbd> - <kbd>7</kbd> per navigare tra le viste']
  },
  {
    title: 'Pronto a iniziare',
    body: 'Premi <kbd>?</kbd> in qualsiasi momento per rivedere le scorciatoie.',
    list: ['Importa la tua API key OpenAI nelle Settings', 'Attiva auto-response per bloccare IP critici', 'Configura soglie di allerta personalizzate']
  }
];

let onboardingStep = 0;

function startOnboarding() {
  onboardingStep = 0;
  renderOnboarding();
  const el = $('#onboarding');
  if (el) el.classList.add('active');
}

function renderOnboarding() {
  const el = $('#onboardingContent');
  const step = ONBOARDING_STEPS[onboardingStep];
  if (!el) return;
  el.innerHTML = `
    <h2>${step.title}</h2>
    <p>${step.body}</p>
    <ul>${step.list.map(l => `<li>${l}</li>`).join('')}</ul>
  `;

  $$('.onboarding-dot').forEach((dot, i) => {
    dot.classList.toggle('active', i === onboardingStep);
  });

  const nextBtn = $('#onboardingNext');
  if (nextBtn) {
    nextBtn.textContent = onboardingStep === ONBOARDING_STEPS.length - 1 ? 'Inizia' : 'Avanti';
  }
}

/* =========================================================
   INIT
   ========================================================= */
function init() {
  seedData();

  // Apply stored tenant
  const t = state.tenants.find(x => x.id === state.tenant) || state.tenants[0];
  const nameEl = $('#tenantName');
  const bcEl = $('#bcTenant');
  if (nameEl) nameEl.textContent = t.name;
  if (bcEl) bcEl.textContent = t.name;

  applySettings();
  renderAssets();
  renderIncidentsMini();
  updateOverviewKPIs();
  updateNotifBadge();
  renderNotifList();

  // Populate attack types filter
  const typeFilter = $('#threatsTypeFilter');
  if (typeFilter) {
    ATTACK_TYPES.forEach(at => {
      const opt = document.createElement('option');
      opt.value = at.name;
      opt.textContent = at.name;
      typeFilter.appendChild(opt);
    });
  }

  bindEvents();

  tickClock();
  setInterval(tickClock, 1000);

  startLogStream();

  function mapLoop() {
    if (state.currentView === 'overview' && !document.hidden) drawAttackMap();
    requestAnimationFrame(mapLoop);
  }
  requestAnimationFrame(mapLoop);

  animateSplash();
  setTimeout(() => {
    const splash = $('#splash');
    if (splash) {
      splash.classList.add('hidden');
      setTimeout(() => splash.remove(), 600);
    }
    const app = $('#app');
    if (app) app.classList.add('ready');
    setTimeout(() => toast('🛡️ Benvenuto nel SOC di ' + t.name, 'info'), 500);

    // Show onboarding only first time
    if (!localStorage.getItem(KEYS.ONBOARDING)) {
      setTimeout(() => startOnboarding(), 1200);
    }
  }, 1900);
}

/* =========================================================
   EVENTS
   ========================================================= */
function bindEvents() {
  // Nav
  $$('.nav-item[data-view]').forEach(btn => {
    btn.addEventListener('click', () => { switchView(btn.dataset.view); closeSidebar(); });
  });

  $$('[data-nav]').forEach(btn => {
    btn.addEventListener('click', () => switchView(btn.dataset.nav));
  });

  // Help nav
  const helpNavBtn = $('#helpNavBtn');
  if (helpNavBtn) helpNavBtn.addEventListener('click', () => openModal('helpModal'));

  // Sidebar mobile
  const menuBtn = $('#menuBtn');
  const sidebarClose = $('#sidebarClose');
  const sidebarOverlay = $('#sidebarOverlay');
  function openSidebar() { $('#sidebar').classList.add('open'); sidebarOverlay.classList.add('active'); }
  function closeSidebar() { $('#sidebar').classList.remove('open'); sidebarOverlay.classList.remove('active'); }
  if (menuBtn) menuBtn.addEventListener('click', openSidebar);
  if (sidebarClose) sidebarClose.addEventListener('click', closeSidebar);
  if (sidebarOverlay) sidebarOverlay.addEventListener('click', closeSidebar);

  // Theme
  const themeBtn = $('#themeBtn');
  if (themeBtn) themeBtn.addEventListener('click', toggleTheme);

  // Refresh
  const refreshBtn = $('#refreshBtn');
  if (refreshBtn) refreshBtn.addEventListener('click', () => {
    refreshBtn.classList.add('spinning');
    setTimeout(() => refreshBtn.classList.remove('spinning'), 700);
    for (let i = 0; i < 5; i++) state.threats.unshift(generateThreat(0));
    toast('Dati aggiornati', 'success');
    updateOverviewKPIs();
    if (state.currentView === 'threats') renderThreatsTable();
    drawAttackMap();
  });

  // Range
  $$('#rangeControl button').forEach(btn => {
    btn.addEventListener('click', () => {
      state.currentRange = btn.dataset.range;
      $$('#rangeControl button').forEach(b => b.classList.toggle('active', b === btn));
      updateOverviewKPIs();
    });
  });

  // Search
  const searchBtn = $('#searchBtn');
  if (searchBtn) searchBtn.addEventListener('click', openCmdPalette);

  // Notifications
  const notifBtn = $('#notifBtn');
  if (notifBtn) notifBtn.addEventListener('click', () => {
    renderNotifList();
    openModal('notifModal');
  });

  const notifMarkAllBtn = $('#notifMarkAllBtn');
  if (notifMarkAllBtn) notifMarkAllBtn.addEventListener('click', () => {
    state.notifications.forEach(n => n.read = true);
    renderNotifList();
    updateNotifBadge();
    toast('Tutte le notifiche lette', 'success');
  });

  // Tenant
  const tenantBtn = $('#tenantBtn');
  if (tenantBtn) tenantBtn.addEventListener('click', () => {
    renderTenantList();
    openModal('tenantModal');
  });

  // User
  const userBtn = $('#userBtn');
  if (userBtn) userBtn.addEventListener('click', () => openModal('userModal'));

  // Threats filters
  $$('#threatsSeverityFilter .chip').forEach(chip => {
    chip.addEventListener('click', () => {
      state.threatFilter.sev = chip.dataset.sev;
      $$('#threatsSeverityFilter .chip').forEach(c => c.classList.toggle('active', c === chip));
      renderThreatsTable();
    });
  });

  const threatsSearch = $('#threatsSearch');
  if (threatsSearch) threatsSearch.addEventListener('input', debounce(e => {
    state.threatFilter.search = e.target.value;
    renderThreatsTable();
  }, 200));

  const threatsTypeFilter = $('#threatsTypeFilter');
  if (threatsTypeFilter) threatsTypeFilter.addEventListener('change', e => {
    state.threatFilter.type = e.target.value;
    renderThreatsTable();
  });

  const threatsSelectAll = $('#threatsSelectAll');
  if (threatsSelectAll) threatsSelectAll.addEventListener('change', e => {
    const list = getFilteredThreats();
    if (e.target.checked) list.forEach(t => state.selectedThreats.add(t.id));
    else list.forEach(t => state.selectedThreats.delete(t.id));
    renderThreatsTable();
  });

  $$('[data-bulk-threat]').forEach(btn => {
    btn.addEventListener('click', () => {
      const action = btn.dataset.bulkThreat;
      const count = state.selectedThreats.size;
      if (!count) return;
      if (action === 'block') {
        state.selectedThreats.forEach(id => {
          const t = state.threats.find(x => x.id === id);
          if (t) t.action = 'blocked';
        });
        toast(`${count} IP bloccati`, 'success');
      } else if (action === 'investigate') {
        toast(`${count} threat in investigazione`, 'info');
      } else if (action === 'ignore') {
        state.threats = state.threats.filter(t => !state.selectedThreats.has(t.id));
        toast(`${count} threat ignorati`, 'warning');
      }
      state.selectedThreats.clear();
      renderThreatsTable();
      updateOverviewKPIs();
    });
  });

  // Export
  const exportThreatsBtn = $('#exportThreatsBtn');
  if (exportThreatsBtn) exportThreatsBtn.addEventListener('click', exportThreatsCSV);
  const exportLogsBtn = $('#exportLogsBtn');
  if (exportLogsBtn) exportLogsBtn.addEventListener('click', exportLogsCSV);
  const exportAllBtn = $('#exportAllBtn');
  if (exportAllBtn) exportAllBtn.addEventListener('click', exportAllJSON);

  // Clear logs
  const clearLogsBtn = $('#clearLogsBtn');
  if (clearLogsBtn) clearLogsBtn.addEventListener('click', () => {
    state.logs = [];
    renderLogsView();
    toast('Log puliti', 'warning');
  });

  // Logs filters
  $$('#logsLevelFilter .chip').forEach(chip => {
    chip.addEventListener('click', () => {
      state.logFilter.level = chip.dataset.level;
      $$('#logsLevelFilter .chip').forEach(c => c.classList.toggle('active', c === chip));
      renderLogsView();
    });
  });
  const logsSearch = $('#logsSearch');
  if (logsSearch) logsSearch.addEventListener('input', debounce(e => {
    state.logFilter.search = e.target.value;
    renderLogsView();
  }, 200));

  // Incidents filter
  $$('#incidentsStatusFilter .chip').forEach(chip => {
    chip.addEventListener('click', () => {
      state.incidentFilter.status = chip.dataset.status;
      $$('#incidentsStatusFilter .chip').forEach(c => c.classList.toggle('active', c === chip));
      renderIncidentsView();
    });
  });

  // Vuln filters
  const vulnSearch = $('#vulnSearch');
  if (vulnSearch) vulnSearch.addEventListener('input', debounce(e => {
    state.vulnFilter.search = e.target.value;
    renderVulnTable();
  }, 200));
  const vulnSev = $('#vulnSeverityFilter');
  if (vulnSev) vulnSev.addEventListener('change', e => {
    state.vulnFilter.sev = e.target.value;
    renderVulnTable();
  });
  const vulnStatus = $('#vulnStatusFilter');
  if (vulnStatus) vulnStatus.addEventListener('change', e => {
    state.vulnFilter.status = e.target.value;
    renderVulnTable();
  });

  // New incident
  const newIncBtn = $('#newIncidentBtn');
  if (newIncBtn) newIncBtn.addEventListener('click', () => openModal('newIncidentModal'));
  const createIncBtn = $('#createIncidentBtn');
  if (createIncBtn) createIncBtn.addEventListener('click', () => {
    const title = $('#niTitle').value.trim();
    if (!title) { toast('Inserisci un titolo', 'error'); return; }
    const inc = {
      id: uid('INC'), timestamp: Date.now(), title,
      description: $('#niDesc').value.trim() || 'Nessuna descrizione fornita.',
      priority: $('#niPriority').value,
      category: $('#niCategory').value,
      status: 'open',
      assignee: $('#niAssignee').value,
      assets: $('#niAssets').value.split(',').map(s => s.trim()).filter(Boolean),
      timeline: [{ time: Date.now(), event: 'Incident created by nowii-core', actor: 'nowii-core' }]
    };
    state.incidents.unshift(inc);
    closeModal('newIncidentModal');
    $('#niTitle').value = '';
    $('#niDesc').value = '';
    $('#niAssets').value = '';
    renderIncidentsView();
    renderIncidentsMini();
    toast(`Incidente ${inc.id} creato`, 'success');
  });

  // Pause feed
  const pauseFeed = $('#pauseFeed');
  if (pauseFeed) pauseFeed.addEventListener('click', () => {
    state.feedPaused = !state.feedPaused;
    pauseFeed.textContent = state.feedPaused ? 'Riprendi' : 'Pausa';
    toast(state.feedPaused ? 'Live feed in pausa' : 'Live feed ripreso', 'info');
  });

  // Settings toggles
  $$('#themeSegmented button').forEach(btn => {
    btn.addEventListener('click', () => {
      state.theme = btn.dataset.theme;
      localStorage.setItem(KEYS.THEME, state.theme);
      applySettings();
      redrawCanvas();
    });
  });
  $$('#densitySegmented button').forEach(btn => {
    btn.addEventListener('click', () => {
      state.density = btn.dataset.density;
      localStorage.setItem(KEYS.DENSITY, state.density);
      applySettings();
    });
  });
  const liveFeedToggle = $('#liveFeedToggle');
  if (liveFeedToggle) liveFeedToggle.addEventListener('change', e => {
    state.liveFeed = e.target.checked;
    localStorage.setItem(KEYS.LIVE_FEED, state.liveFeed);
    applySettings();
    toast(`Live feed ${state.liveFeed ? 'attivato' : 'disattivato'}`, 'info');
  });
  const autoResponseToggle = $('#autoResponseToggle');
  if (autoResponseToggle) autoResponseToggle.addEventListener('change', e => {
    state.autoResponse = e.target.checked;
    localStorage.setItem(KEYS.AUTO_RESPONSE, state.autoResponse);
    toast(`Auto-response ${state.autoResponse ? 'attivato' : 'disattivato'}`, 'warning');
  });
  const soundToggle = $('#soundToggle');
  if (soundToggle) soundToggle.addEventListener('change', e => {
    state.sound = e.target.checked;
    localStorage.setItem(KEYS.SOUND, state.sound);
    toast(`Sound alerts ${state.sound ? 'attivati' : 'disattivati'}`, 'info');
  });
  const alertThreshold = $('#alertThreshold');
  if (alertThreshold) alertThreshold.addEventListener('change', e => {
    state.alertThreshold = e.target.value;
    localStorage.setItem(KEYS.ALERT_THRESHOLD, state.alertThreshold);
    toast('Soglia allerta aggiornata', 'success');
  });
  const apiKeyInput = $('#apiKeyInput');
  if (apiKeyInput) {
    apiKeyInput.value = localStorage.getItem(KEYS.API_KEY) || '';
    apiKeyInput.addEventListener('change', () => {
      localStorage.setItem(KEYS.API_KEY, apiKeyInput.value);
      toast('API Key salvata', 'success');
    });
  }
  const testWebhookBtn = $('#testWebhookBtn');
  if (testWebhookBtn) testWebhookBtn.addEventListener('click', () => {
    toast('Webhook inviato (demo)', 'info');
  });
  const resetDataBtn = $('#resetDataBtn');
  if (resetDataBtn) resetDataBtn.addEventListener('click', () => {
    if (!confirm('Ripristinare i dati demo?')) return;
    seedData();
    updateOverviewKPIs();
    renderAssets();
    renderIncidentsMini();
    renderThreatsTable();
    renderThreatsStats();
    renderIncidentsView();
    renderVulnTable();
    renderLogsView();
    updateNotifBadge();
    renderNotifList();
    toast('Dati ripristinati', 'success');
  });

  // Modals close
  $$('[data-close]').forEach(btn => {
    btn.addEventListener('click', () => closeModal(btn.dataset.close));
  });
  $$('.modal-backdrop').forEach(backdrop => {
    backdrop.addEventListener('click', e => {
      if (e.target === backdrop) backdrop.classList.remove('open');
    });
  });

  // Command palette
  const cmdInput = $('#cmdInput');
  if (cmdInput) {
    cmdInput.addEventListener('input', e => renderCmdResults(e.target.value));
    cmdInput.addEventListener('keydown', e => {
      const items = $$('.cmd-item');
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        state.cmdSelectedIndex = Math.min(state.cmdSelectedIndex + 1, items.length - 1);
        updateCmdSelection();
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        state.cmdSelectedIndex = Math.max(state.cmdSelectedIndex - 1, 0);
        updateCmdSelection();
      } else if (e.key === 'Enter') {
        e.preventDefault();
        const item = state.cmdFlatItems[state.cmdSelectedIndex];
        closeModal('cmdBackdrop');
        if (!item) return;
        setTimeout(() => {
          if (item.action) item.action();
          else if (item.id && item.sourceIP) openThreatModal(item.id);
          else if (item.id && item.priority) openIncidentModal(item.id);
        }, 100);
      }
    });
  }

  // Onboarding
  const onbNext = $('#onboardingNext');
  if (onbNext) onbNext.addEventListener('click', () => {
    if (onboardingStep < ONBOARDING_STEPS.length - 1) {
      onboardingStep++;
      renderOnboarding();
    } else {
      closeOnboarding();
    }
  });
  const onbSkip = $('#onboardingSkip');
  if (onbSkip) onbSkip.addEventListener('click', closeOnboarding);

  function closeOnboarding() {
    const el = $('#onboarding');
    if (el) el.classList.remove('active');
    localStorage.setItem(KEYS.ONBOARDING, '1');
  }

  // Keyboard shortcuts
  document.addEventListener('keydown', e => {
    const inInput = ['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName);

    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      openCmdPalette();
      return;
    }
    if (e.key === 'Escape') {
      $$('.modal-backdrop.open').forEach(b => b.classList.remove('open'));
      return;
    }
    if (inInput) return;

    const map = { '1': 'overview', '2': 'threats', '3': 'incidents', '4': 'vulnerabilities', '5': 'logs', '6': 'playbooks', '7': 'compliance' };
    if (map[e.key]) { e.preventDefault(); switchView(map[e.key]); return; }
    if (e.key === 'r' || e.key === 'R') { e.preventDefault(); const b = $('#refreshBtn'); if (b) b.click(); }
    if (e.key === 't' || e.key === 'T') { e.preventDefault(); toggleTheme(); }
    if (e.key === 'n' || e.key === 'N') { e.preventDefault(); openModal('newIncidentModal'); }
    if (e.key === 'p' || e.key === 'P') { e.preventDefault(); const b = $('#pauseFeed'); if (b) b.click(); }
    if (e.key === '?') { e.preventDefault(); openModal('helpModal'); }
  });

  // Resize
  window.addEventListener('resize', debounce(() => {
    if (state.currentView === 'overview') {
      drawAttackMap();
      renderSeverityRing(state.threats.filter(t => Date.now() - t.timestamp < 86400000));
    }
  }, 200));
}

/* =========================================================
   BOOT
   ========================================================= */
document.addEventListener('DOMContentLoaded', init);