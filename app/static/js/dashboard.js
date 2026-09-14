// ============================================================
// Linux Security Auditor — Dashboard Logic
// ============================================================

const state = {
    system: null,      // /api/system  (check dict, details = info)
    checks: [],        // /api/security (array of check dicts)
    score: null,       // /api/score
    processes: null,   // /api/processes (check dict, details = process info)
    ports: [],         // listening ports (normalized)
    lastScan: null,
};

let auditRunning = false;
let auditStatusFilter = 'ALL';

// ---------------- Helpers ----------------

function esc(value) {
    return String(value ?? '').replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
}

async function fetchJSON(url) {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.json();
}

function scoreColor(score) {
    if (score >= 90) return 'var(--ok)';
    if (score >= 75) return 'var(--accent)';
    if (score >= 50) return 'var(--warn)';
    return 'var(--crit)';
}

function statusBadge(status) {
    return `<span class="check-status ${esc(status)}">${esc(status)}</span>`;
}

function setMeter(id, pct) {
    const el = document.getElementById(id);
    if (!el) return;
    el.style.width = Math.max(0, Math.min(100, pct)) + '%';
    el.classList.toggle('hot', pct >= 70);
}

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

function systemInfo() {
    return (state.system && state.system.details) || {};
}

// ---------------- View switching ----------------

function showView(view) {
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    const target = document.getElementById('view-' + view);
    if (target) target.classList.add('active');

    document.querySelectorAll('.sidebar nav a').forEach(a =>
        a.classList.toggle('active', a.dataset.view === view)
    );

    if (view === 'network') loadNetwork();
    if (view === 'processes') loadProcessesView();
    if (view === 'system') loadSystemView();
    if (view === 'audit') renderAuditCenter();
    if (view === 'overview') renderOverview();
}

// ---------------- Data loading ----------------

async function runFullAudit() {
    if (auditRunning) return;
    auditRunning = true;

    const overlay = document.getElementById('audit-overlay');
    overlay.classList.remove('hidden');
    overlay.classList.add('visible');

    const steps = [
        ['Collecting system information', '/api/system', 10],
        ['Running all security checks', '/api/security', 45],
        ['Calculating security score', '/api/score', 70],
        ['Analyzing running processes', '/api/processes', 90],
    ];

    try {
        for (const [label, url, pct] of steps) {
            setAuditStep(label, pct);
            const data = await fetchJSON(url);
            if (url === '/api/system') state.system = data;
            if (url === '/api/security') state.checks = Array.isArray(data) ? data : [];
            if (url === '/api/score') state.score = data;
            if (url === '/api/processes') state.processes = data;
        }

        await refreshPorts();
        setAuditStep('Finalizing report', 100);

        state.lastScan = new Date();
        renderAll();

        setTimeout(() => {
            overlay.classList.add('hidden');
            overlay.classList.remove('visible');
        }, 350);
    } catch (err) {
        console.error('Full audit failed:', err);
        setAuditStep('Error: ' + err.message, 100);
        setTimeout(() => {
            overlay.classList.add('hidden');
            overlay.classList.remove('visible');
        }, 1600);
    } finally {
        auditRunning = false;
    }
}

function setAuditStep(label, pct) {
    setText('audit-progress-step', label);
    const fill = document.getElementById('audit-progress-fill');
    if (fill) fill.style.width = pct + '%';
}

async function refreshPorts() {
    try {
        const data = await fetchJSON('/api/ports');
        // /api/ports returns a check-dict with the port list inside details.connections
        if (Array.isArray(data)) {
            state.ports = data;
        } else {
            const det = (data && data.details) || {};
            state.ports = Array.isArray(det.connections) ? det.connections
                : Array.isArray(det.exposed_ports) ? det.exposed_ports
                : [];
        }
    } catch (err) {
        console.error('Port scan failed:', err);
        state.ports = [];
    }
}

function renderAll() {
    renderOverview();
    renderAuditCenter();
    renderNetworkView();
    renderProcessesView();
    renderSystemView();
    const t = state.lastScan;
    setText('scan-state', t ? `Last scan: ${t.toLocaleTimeString()}` : 'Last scan: never');
}

// ---------------- Overview ----------------

function renderOverview() {
    const info = systemInfo();

    // Resource cards
    if (info.cpu_usage_percent !== undefined) {
        setText('cpu', info.cpu_usage_percent.toFixed(1) + '%');
        setMeter('cpu-meter', info.cpu_usage_percent);
    }
    if (info.ram_used_percent !== undefined) {
        setText('ram', info.ram_used_percent.toFixed(1) + '%');
        setMeter('ram-meter', info.ram_used_percent);
    }
    if (info.disk_used_percent !== undefined) {
        setText('disk', info.disk_used_percent.toFixed(1) + '%');
        setMeter('disk-meter', info.disk_used_percent);
    }

    setText('ports', state.ports.length || '--');
    const exposed = state.ports.filter(p => p.exposure === 'EXPOSED' || p.exposure === 'NETWORK').length;
    setText('ports-note', exposed ? `${exposed} exposed externally` : 'all local only');

    setText('hostname', info.hostname || '--');
    setText('os', info.os || '--');
    setText('kernel', info.kernel || '--');
    setText('architecture', info.architecture || '--');

    // Score panel
    if (state.score) {
        const s = state.score;
        setText('score', s.score);
        setText('rating', s.rating || 'UNKNOWN');
        document.getElementById('score').style.color = scoreColor(s.score);

        const gauge = document.getElementById('gauge-fill');
        if (gauge) {
            gauge.style.width = (s.score || 0) + '%';
            gauge.style.background = scoreColor(s.score);
        }

        const c = s.checks || {};
        setText('pass-count', c.pass ?? 0);
        setText('warning-count', c.warning ?? 0);
        setText('critical-count', c.critical ?? c.failed ?? 0);
    }

    // Findings count card
    const problems = state.checks.filter(c => c.status === 'WARNING' || c.status === 'CRITICAL' || c.status === 'FAIL');
    setText('finding-count', state.checks.length ? problems.length : '--');
    setText('finding-note', problems.length ? 'need attention' : (state.checks.length ? 'all clear' : 'run an audit'));

    renderTopFindings();
}

function renderTopFindings() {
    const container = document.getElementById('top-findings');
    if (!container) return;

    const order = { CRITICAL: 0, FAIL: 0, WARNING: 1, UNKNOWN: 2, INFO: 3, PASS: 4 };
    const problems = state.checks
        .filter(c => (order[c.status] ?? 9) < 4)
        .sort((a, b) =>
            ((order[a.status] ?? 9) - (order[b.status] ?? 9)) ||
            ((a.score ?? 0) / (a.max_score || 10)) - ((b.score ?? 0) / (b.max_score || 10))
        )
        .slice(0, 5);

    if (!state.checks.length) {
        container.innerHTML = '<div class="empty-state">Run a full audit to see your worst findings here.</div>';
        return;
    }

    if (!problems.length) {
        container.innerHTML = '<div class="empty-state">🎉 No issues found — every check passed.</div>';
        return;
    }

    container.innerHTML = problems.map(c => {
        const idx = state.checks.indexOf(c);
        return `
            <div class="finding-row" onclick="openCheckModal(${idx})">
                <span class="finding-badge">${statusBadge(c.status)}</span>
                <span class="check-name">${esc(c.name)}</span>
                <span class="check-message">${esc(c.summary || '')}</span>
            </div>
        `;
    }).join('');
}

// ---------------- Audit Center ----------------

function filterAudit(status, btn) {
    auditStatusFilter = status;
    document.querySelectorAll('#status-filter .chip').forEach(c => c.classList.remove('active'));
    if (btn) btn.classList.add('active');
    renderAuditCenter();
}

function renderAuditCenter() {
    const grid = document.getElementById('audit-grid');
    const empty = document.getElementById('audit-empty');
    if (!grid) return;

    const term = (document.getElementById('audit-filter')?.value || '').toLowerCase();

    const filtered = state.checks.filter(c => {
        const statusOk = auditStatusFilter === 'ALL' ||
            c.status === auditStatusFilter ||
            (auditStatusFilter === 'CRITICAL' && (c.status === 'FAIL' || c.status === 'CRITICAL'));
        const text = `${c.name} ${c.category} ${c.summary} ${c.recommendation}`.toLowerCase();
        return statusOk && (!term || text.includes(term));
    });

    if (!state.checks.length) {
        grid.innerHTML = '';
        empty.classList.remove('hidden');
        empty.textContent = 'No audit results yet — run a full audit.';
        return;
    }

    if (!filtered.length) {
        grid.innerHTML = '';
        empty.classList.remove('hidden');
        empty.textContent = 'No checks match this filter.';
        return;
    }

    empty.classList.add('hidden');
    grid.innerHTML = filtered.map(c => {
        const idx = state.checks.indexOf(c);
        return `
            <div class="check-item ${esc(c.status)}" onclick="openCheckModal(${idx})">
                <div class="check-header">
                    <div>
                        <span class="check-name">${esc(c.name)}</span>
                        <span class="check-category">${esc(c.category || 'SYSTEM')}</span>
                    </div>
                    ${statusBadge(c.status)}
                </div>
                <p class="check-message">${esc(c.summary || '')}</p>
                <div class="check-footer">
                    <span class="check-score">Score ${c.score ?? 0}/${c.max_score ?? 10}</span>
                    <span>View details →</span>
                </div>
            </div>
        `;
    }).join('');
}

// ---------------- Check details modal ----------------

function openCheckModal(index) {
    const check = state.checks[index];
    if (!check) return;

    const modal = document.getElementById('details-modal');
    setText('details-title', check.name || 'Details');
    setText('details-subtitle', `${check.category || 'CHECK'} · Score ${check.score ?? 0}/${check.max_score ?? 10}`);

    const sections = [];

    sections.push(`
        <div class="detail-section">
            <div class="detail-box">
                <strong>${statusBadge(check.status)}</strong>
                <span class="check-message" style="margin-left:8px">${esc(check.summary || '')}</span>
            </div>
        </div>
    `);

    if (check.why_it_matters) {
        sections.push(`
            <div class="detail-section">
                <h3>Why it matters</h3>
                <div class="detail-box">${esc(check.why_it_matters)}</div>
            </div>
        `);
    }

    if (check.recommendation) {
        sections.push(`
            <div class="detail-section">
                <h3>Recommendation</h3>
                <div class="reco-box">${esc(check.recommendation)}</div>
            </div>
        `);
    }

    if (Array.isArray(check.evidence) && check.evidence.length) {
        sections.push(`
            <div class="detail-section">
                <h3>Evidence</h3>
                <ul class="detail-list">
                    ${check.evidence.map(e => `<li>${esc(typeof e === 'object' ? JSON.stringify(e) : e)}</li>`).join('')}
                </ul>
            </div>
        `);
    }

    if (check.details && Object.keys(check.details).length) {
        sections.push(`
            <div class="detail-section">
                <h3>Collected data</h3>
                ${renderDetailsDict(check.details)}
            </div>
        `);
    }

    const content = document.getElementById('details-content');
    content.innerHTML = `<div class="modal-body">${sections.join('')}</div>`;

    modal.classList.remove('hidden');
    modal.classList.add('visible');
}

function renderDetailsDict(details) {
    return Object.entries(details).map(([key, value]) => `
        <div class="detail-section" style="margin-bottom:12px">
            <h3>${esc(key.replace(/_/g, ' '))}</h3>
            ${renderDetailValue(value)}
        </div>
    `).join('');
}

function renderDetailValue(value) {
    if (value === null || value === undefined) return '<div class="detail-box"><em>—</em></div>';

    if (Array.isArray(value)) {
        if (!value.length) return '<div class="detail-box"><em>None</em></div>';
        if (typeof value[0] === 'object' && value[0] !== null) {
            const keys = [...new Set(value.flatMap(item => Object.keys(item)))];
            const shown = value.slice(0, 12);
            let html = '<div class="table-wrap"><table class="table"><thead><tr>' +
                keys.map(k => `<th>${esc(k)}</th>`).join('') +
                '</tr></thead><tbody>' +
                shown.map(item => '<tr>' + keys.map(k => `<td>${esc(item[k] ?? '—')}</td>`).join('') + '</tr>').join('') +
                '</tbody></table></div>';
            if (value.length > 12) html += `<p class="process-note">Showing 12 of ${value.length} entries.</p>`;
            return html;
        }
        const shown = value.slice(0, 12).map(v => `<li>${esc(v)}</li>`).join('');
        const more = value.length > 12 ? `<li><em>…and ${value.length - 12} more</em></li>` : '';
        return `<ul class="detail-list">${shown}${more}</ul>`;
    }

    if (typeof value === 'object') {
        return `<ul class="detail-list">` +
            Object.entries(value).map(([k, v]) => `<li><strong>${esc(k)}:</strong> ${esc(v)}</li>`).join('') +
            `</ul>`;
    }

    return `<div class="detail-box">${esc(value)}</div>`;
}

// ---------------- Network view ----------------

async function loadNetwork() {
    if (!state.ports.length) await refreshPorts();
    renderNetworkView();
}

function renderNetworkView() {
    const total = state.ports.length;
    const exposed = state.ports.filter(p => p.exposure === 'EXPOSED' || p.exposure === 'NETWORK').length;

    setText('net-listening', total || '--');
    setText('net-exposed', exposed || '0');
    setText('ports', total || '--');
    setText('ports-note', exposed ? `${exposed} exposed externally` : (total ? 'all local only' : 'Listening'));

    const container = document.getElementById('network-table');
    if (!container) return;

    if (!total) {
        container.innerHTML = '<div class="empty-state">No listening ports detected.</div>';
        return;
    }

    container.innerHTML = `
        <div class="table-wrap">
            <table class="table">
                <thead>
                    <tr><th>Address</th><th>Port</th><th>Proto</th><th>Process</th><th>Exposure</th></tr>
                </thead>
                <tbody>
                    ${state.ports.map(p => `
                        <tr>
                            <td>${esc(p.ip || '—')}</td>
                            <td>${esc(p.port ?? '—')}</td>
                            <td>${esc(p.protocol || 'TCP')}</td>
                            <td>${esc(p.process || p.message || '—')}${p.pid ? ` <em>(pid ${esc(p.pid)})</em>` : ''}</td>
                            <td><span class="pill ${esc(p.exposure)}">${esc(p.exposure || '—')}</span></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

// ---------------- Processes view ----------------

let procVisibleCount = 50;

async function loadProcessesView() {
    try {
        state.processes = await fetchJSON('/api/processes');
    } catch (err) {
        console.error('Process scan failed:', err);
    }
    renderProcessesView();
}

function kindBadge(kind) {
    return `<span class="kind kind-${esc(kind || 'USER')}">${esc(kind || 'USER')}</span>`;
}

function stateClass(state) {
    return 'state-' + String(state || 'unknown').replace(/\s+/g, '-');
}

function fmtMB(mb) {
    if (mb == null) return '—';
    if (mb >= 1024) return (mb / 1024).toFixed(2) + ' GB';
    return mb.toFixed(1) + ' MB';
}

function procRow(p, columns) {
    const kind = p.kind || 'USER';
    const cells = columns.map(col => {
        switch (col) {
            case 'kind': return `<td>${kindBadge(kind)}</td>`;
            case 'pid': return `<td>${esc(p.pid ?? '—')}</td>`;
            case 'name': return `<td class="proc-name" title="${esc(p.cmdline || p.name || '')}">${esc(p.name || '—')}</td>`;
            case 'user': return `<td class="proc-user">${esc(p.username || '—')}</td>`;
            case 'state': return `<td><span class="${stateClass(p.state)}">${esc(p.state || '—')}</span></td>`;
            case 'cpu': return `<td>${(p.cpu_percent ?? 0).toFixed(1)}%</td>`;
            case 'mem': return `<td>${(p.memory_percent ?? 0).toFixed(1)}% <em>(${fmtMB(p.rss_mb)})</em></td>`;
            case 'rss': return `<td>${fmtMB(p.rss_mb)}</td>`;
            case 'started': return `<td class="proc-user">${esc(p.started || '—')}</td>`;
            default: return `<td>—</td>`;
        }
    }).join('');
    return `<tr class="proc-row-${esc(kind)}">${cells}</tr>`;
}

function renderProcessesView() {
    const d = (state.processes && state.processes.details) || {};

    setText('proc-total', d.total_processes ?? '--');
    setText('proc-kernel', d.kernel_threads ?? '--');
    setText('proc-system', d.system_services ?? '--');
    setText('proc-user', d.user_processes ?? '--');
    setText('proc-root', d.privileged_processes ?? '--');

    renderProcTable('proc-mem-table', d.top_memory_consumers || [],
        ['name', 'pid', 'user', 'rss', 'mem'], ['Process', 'PID', 'User', 'RSS', '% MEM']);
    renderProcTable('proc-cpu-table', d.top_cpu_consumers || [],
        ['name', 'pid', 'user', 'cpu'], ['Process', 'PID', 'User', 'CPU']);

    procVisibleCount = 50;
    renderAllProcesses();
}

function renderAllProcesses() {
    const body = document.getElementById('proc-all-body');
    const note = document.getElementById('proc-shown-note');
    const moreBtn = document.getElementById('proc-more-btn');
    if (!body) return;

    const all = (state.processes && state.processes.details && state.processes.details.processes) || [];
    if (!all.length) {
        body.innerHTML = '<tr><td colspan="8"><div class="empty-state">No process data yet — run an audit.</div></td></tr>';
        if (moreBtn) moreBtn.classList.add('hidden');
        if (note) note.textContent = '';
        return;
    }

    const term = (document.getElementById('proc-filter')?.value || '').toLowerCase();
    const kindSel = document.getElementById('proc-kind')?.value || 'ALL';
    const sortBy = document.getElementById('proc-sort')?.value || 'rss';

    const rows = all.filter(p => {
        if (kindSel !== 'ALL' && (p.kind || 'USER') !== kindSel) return false;
        if (!term) return true;
        return `${p.name} ${p.username} ${p.cmdline} ${p.pid}`.toLowerCase().includes(term);
    });

    const sorters = {
        rss: (a, b) => (b.rss_mb || 0) - (a.rss_mb || 0),
        cpu: (a, b) => (b.cpu_percent || 0) - (a.cpu_percent || 0),
        pid: (a, b) => (a.pid || 0) - (b.pid || 0),
        name: (a, b) => String(a.name || '').localeCompare(String(b.name || '')),
    };
    rows.sort(sorters[sortBy] || sorters.rss);

    const visible = rows.slice(0, procVisibleCount);
    body.innerHTML = visible.map(p => procRow(p, ['kind', 'pid', 'name', 'user', 'state', 'cpu', 'mem', 'started'])).join('');

    if (note) note.textContent = `Showing ${visible.length} of ${rows.length} matching · ${all.length} total on system`;
    if (moreBtn) moreBtn.classList.toggle('hidden', rows.length <= procVisibleCount);
}

function showMoreProcesses() {
    procVisibleCount += 100;
    renderAllProcesses();
}

function renderProcTable(id, rows, columns, headers) {
    const el = document.getElementById(id);
    if (!el) return;

    if (!Array.isArray(rows) || !rows.length) {
        el.innerHTML = '<div class="empty-state">No notable processes right now.</div>';
        return;
    }

    el.innerHTML = `
        <div class="table-wrap">
            <table class="table proc-table">
                <thead><tr>${headers.map(h => `<th>${esc(h)}</th>`).join('')}</tr></thead>
                <tbody>
                    ${rows.map(p => procRow(p, columns)).join('')}
                </tbody>
            </table>
        </div>
    `;
}

// ---------------- System view ----------------

async function loadSystemView() {
    try {
        state.system = await fetchJSON('/api/system');
    } catch (err) {
        console.error('System scan failed:', err);
    }
    renderSystemView();
}

function renderSystemView() {
    const info = systemInfo();

    if (info.cpu_usage_percent !== undefined) {
        setText('sys-cpu', info.cpu_usage_percent.toFixed(1) + '%');
        setMeter('sys-cpu-meter', info.cpu_usage_percent);
    }
    if (info.ram_used_percent !== undefined) {
        setText('sys-ram', info.ram_used_percent.toFixed(1) + '%');
        setMeter('sys-ram-meter', info.ram_used_percent);
    }
    if (info.disk_used_percent !== undefined) {
        setText('sys-disk', info.disk_used_percent.toFixed(1) + '%');
        setMeter('sys-disk-meter', info.disk_used_percent);
    }

    const container = document.getElementById('system-details');
    if (!container) return;

    const labels = {
        hostname: 'Hostname', os: 'Operating System', kernel: 'Kernel',
        architecture: 'Architecture', cpu: 'CPU Model', cpu_count: 'CPU Cores',
        ram_total_gb: 'RAM Total (GB)', disk_total_gb: 'Disk Total (GB)',
        boot_time: 'Last Boot', uptime_hours: 'Uptime (hours)',
    };

    const rows = Object.entries(labels)
        .filter(([k]) => info[k] !== undefined)
        .map(([k, label]) => `<tr><td>${esc(label)}</td><td>${esc(info[k])}</td></tr>`)
        .join('');

    container.innerHTML = rows
        ? `<div class="table-wrap"><table class="table"><tbody>${rows}</tbody></table></div>`
        : '<div class="empty-state">No system information available yet.</div>';
}

// ---------------- Ports modal (overview card) ----------------

async function showPorts() {
    const modal = document.getElementById('ports-modal');
    modal.classList.remove('hidden');
    modal.classList.add('visible');

    if (!state.ports.length) await refreshPorts();

    setText('modal-port-count', state.ports.length);
    const list = document.getElementById('port-list');

    if (!state.ports.length) {
        list.innerHTML = '<p class="no-ports">No listening ports detected.</p>';
        return;
    }

    const severityFor = p => (p.severity || (p.exposure === 'EXPOSED' || p.exposure === 'NETWORK' ? 'WARNING' : 'INFO'));

    list.innerHTML = `
        <div class="modal-body">
            <div class="table-wrap">
                <table class="table">
                    <thead><tr><th>Address</th><th>Port</th><th>Exposure</th><th>Severity</th></tr></thead>
                    <tbody>
                        ${state.ports.map(p => `
                            <tr>
                                <td>${esc(p.ip || '—')}</td>
                                <td>${esc(p.port ?? '—')}</td>
                                <td><span class="pill ${esc(p.exposure)}">${esc(p.exposure || '—')}</span></td>
                                <td><span class="pill ${esc(severityFor(p))}">${esc(severityFor(p))}</span></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;
}

// ---------------- Report download ----------------

async function downloadReport() {
    try {
        const res = await fetch('/api/report');
        if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `security-report-${new Date().toISOString().slice(0, 10)}.json`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
    } catch (err) {
        alert('Failed to download report: ' + err.message);
    }
}

// ---------------- Modal plumbing / compatibility ----------------

function closeDetails() {
    const m = document.getElementById('details-modal');
    m.classList.add('hidden');
    m.classList.remove('visible');
}

function closePorts() {
    const m = document.getElementById('ports-modal');
    m.classList.add('hidden');
    m.classList.remove('visible');
}

// Legacy entry points kept so old links/shortcuts still work
function showDetails(section) {
    const map = {
        security: 'audit', checks: 'audit', system: 'system',
        network: 'network', processes: 'processes', dashboard: 'overview',
    };
    showView(map[section] || 'overview');
}

function loadData() {
    runFullAudit();
}

window.addEventListener('click', event => {
    if (event.target.classList.contains('modal')) {
        event.target.classList.add('hidden');
        event.target.classList.remove('visible');
    }
});

window.addEventListener('keydown', event => {
    if (event.key === 'Escape') {
        document.querySelectorAll('.modal.visible').forEach(m => {
            m.classList.add('hidden');
            m.classList.remove('visible');
        });
    }
});

// ---------------- Init ----------------

document.addEventListener('DOMContentLoaded', () => {
    runFullAudit();
});
