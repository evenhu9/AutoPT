/**
 * AutoPT 前端控制逻辑 - 自动化渗透测试平台
 */
const API = '';
let allVulns = [], currentTaskId = null, logPollTimer = null, logOffset = 0, _envCache = null;

const MODEL_NAMES = {
    gpt35turbo: 'GPT-3.5 Turbo', gpt4omini: 'GPT-4o-mini', gpt4o: 'GPT-4o', 
    'qwen-plus': '通义千问 Qwen-Plus', 'qwen-max': '通义千问 Qwen-Max', 'glm-4': '智谱 GLM-4',
    'deepseek-chat': 'DeepSeek Chat', 'deepseek-reasoner': 'DeepSeek Reasoner'
};
const PRESET_MODELS = Object.keys(MODEL_NAMES);

// ==================== 通用工具 ====================
async function apiFetch(url, { method = 'GET', body, retries = 2, timeout = 15000 } = {}) {
    for (let i = 0; i <= retries; i++) {
        try {
            const ctrl = new AbortController();
            const tid = setTimeout(() => ctrl.abort(), timeout);
            const opts = { method, signal: ctrl.signal };
            if (body) { opts.headers = { 'Content-Type': 'application/json' }; opts.body = JSON.stringify(body); }
            const res = await fetch(API + url, opts);
            clearTimeout(tid);
            if (!res.ok) {
                const text = await res.text().catch(() => '');
                console.warn(`[API] ${method} ${url} → ${res.status}: ${text.slice(0, 200)}`);
                try { return JSON.parse(text); } catch (_) {}
                return { status: 'error', message: `服务器返回 ${res.status}` };
            }
            return await res.json();
        } catch (e) {
            const msg = e.name === 'AbortError' ? '请求超时' : (e.message || '网络连接失败');
            console.warn(`[API] ${method} ${url} 失败 (${i+1}/${retries+1}): ${msg}`);
            if (i < retries) { await new Promise(r => setTimeout(r, 1000 * (i + 1))); continue; }
            return { status: 'error', message: msg };
        }
    }
}
const apiGet = url => apiFetch(url);
const apiPost = (url, data) => apiFetch(url, { method: 'POST', body: data, retries: 0, timeout: 30000 });

function escapeHtml(text) { const d = document.createElement('div'); d.textContent = text; return d.innerHTML; }
function $(id) { return document.getElementById(id); }
function togglePassword(id) { const el = $(id); el.type = el.type === 'password' ? 'text' : 'password'; }

// ==================== 页面导航 ====================
const PAGE_TITLES = { dashboard: '控制台', vulns: '漏洞库', attack: '渗透测试', docker: '靶机管理', results: '测试报告', settings: '系统设置' };
const PAGE_LOADERS = {
    dashboard: loadDashboard, vulns: loadVulns,
    docker: () => { refreshDocker(); loadDockerEnvs(); },
    results: loadResults, settings: () => { loadConfig(); loadSystemInfo(); }
};

function switchPage(name) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    $(`page-${name}`)?.classList.add('active');
    document.querySelector(`.nav-item[data-page="${name}"]`)?.classList.add('active');
    $('pageTitle').textContent = PAGE_TITLES[name] || name;
    PAGE_LOADERS[name]?.();
}

document.querySelectorAll('.nav-item').forEach(item => item.addEventListener('click', () => switchPage(item.dataset.page)));
$('menuToggle').addEventListener('click', () => $('sidebar').classList.toggle('open'));

// ==================== 控制台 ====================
async function loadDashboard() {
    try {
        const [statsRes, vulnRes] = await Promise.all([apiGet('/api/results/stats'), apiGet('/api/vulns')]);
        if (statsRes.status === 'ok' && statsRes.data) {
            const d = statsRes.data;
            $('statVulns').textContent = d.total_vulns ?? '-';
            $('statSuccess').textContent = d.success_count ?? '-';
            $('statFailed').textContent = d.failed_count ?? '-';
            $('statRate').textContent = (d.success_rate ?? 0) + '%';
            $('statAvgTime').textContent = (d.avg_runtime ?? 0) + 's';
        }
        if (vulnRes.status === 'ok' && vulnRes.data) renderOwaspGrid(vulnRes.data);
        const cfgRes = await apiGet('/api/config');
        if (cfgRes.status === 'ok' && cfgRes.data?.test) {
            const m = (cfgRes.data.test.models || [])[0];
            $('statModel').textContent = MODEL_NAMES[m] || m || 'N/A';
        }
    } catch (e) { console.warn('[Dashboard]', e.message || e); }
}

function renderOwaspGrid(vulns) {
    const typeMap = {};
    vulns.forEach(v => { const t = v.type || 'Unknown'; typeMap[t] = (typeMap[t] || 0) + 1; });
    const max = Math.max(...Object.values(typeMap), 1);
    $('owaspGrid').innerHTML = Object.entries(typeMap).map(([name, count]) => `
        <div class="owasp-item"><div class="owasp-count">${count}</div>
            <div class="owasp-info"><div class="owasp-name">${name}</div>
            <div class="owasp-bar"><div class="owasp-bar-fill" style="width:${(count/max*100).toFixed(0)}%"></div></div></div></div>`).join('');
}

// ==================== 漏洞库 ====================
async function loadVulns() {
    const res = await apiGet('/api/vulns');
    if (res.status !== 'ok') return;
    allVulns = res.data;
    // 填充筛选器（仅首次）
    const sel = $('vulnTypeFilter');
    if (sel.options.length <= 1) [...new Set(allVulns.map(v => v.type))].sort().forEach(t => sel.add(new Option(t, t)));
    const aSel = $('attackVuln');
    if (aSel.options.length <= 1) allVulns.forEach(v => aSel.add(new Option(`${v.name} (${v.difficulty})`, v.name)));
    renderVulns(allVulns);
}

function filterVulns() {
    const s = $('vulnSearch').value.toLowerCase(), tf = $('vulnTypeFilter').value, df = $('vulnDiffFilter').value;
    renderVulns(allVulns.filter(v =>
        (!s || v.name.toLowerCase().includes(s) || (v.description || '').toLowerCase().includes(s)) &&
        (!tf || v.type === tf) && (!df || v.difficulty === df)));
}

function renderVulns(vulns) {
    $('vulnGrid').innerHTML = vulns.length ? vulns.map(v => `
        <div class="vuln-card" onclick="showVulnDetail('${v.name}')">
            <div class="vuln-card-header"><div class="vuln-name">${v.name}</div>
                <span class="vuln-difficulty ${v.difficulty.toLowerCase()}">${v.difficulty === 'Simple' ? '简单' : '复杂'}</span></div>
            <div class="vuln-desc">${v.description || '暂无描述'}</div>
            <div class="vuln-footer"><span class="vuln-type">${v.type}</span>
                <span class="vuln-action"><i class="ri-arrow-right-s-line"></i> 详情</span></div>
        </div>`).join('') : '<div class="loading-spinner">未找到匹配的漏洞</div>';
}

function showVulnDetail(name) {
    const v = allVulns.find(x => x.name === name);
    if (!v) return;
    $('modalTitle').textContent = v.name;
    $('modalBody').innerHTML = `
        <div style="margin-bottom:16px">
            <span class="badge badge-info">${v.type}</span>
            <span class="badge ${v.difficulty === 'Simple' ? 'badge-success' : 'badge-danger'}" style="margin-left:8px">${v.difficulty === 'Simple' ? '简单' : '复杂'}</span></div>
        <h4 style="margin-bottom:8px;color:var(--text-primary)">漏洞描述</h4>
        <p style="margin-bottom:16px">${v.description || '暂无描述'}</p>
        <h4 style="margin-bottom:8px;color:var(--text-primary)">攻击目标</h4>
        <p style="margin-bottom:16px;padding:12px;background:var(--bg-input);border-radius:8px;font-family:var(--font-mono);font-size:13px;color:var(--accent-cyan)">${v.target}</p>
        <div style="margin-top:20px"><button class="btn btn-primary" onclick="quickAttack('${v.name}')"><i class="ri-crosshair-2-line"></i> 直接测试此漏洞</button></div>`;
    $('modalOverlay').classList.add('active');
}

function quickAttack(name) { closeModal(); switchPage('attack'); $('attackVuln').value = name; }
function closeModal() { $('modalOverlay').classList.remove('active'); }

// ==================== 渗透测试 ====================
async function startAttack() {
    const name = $('attackVuln').value, ip = $('attackIP').value;
    if (!name) return showToast('请选择目标漏洞', 'warning', '参数缺失');
    if (!ip) return showToast('请输入目标IP地址', 'warning', '参数缺失');

    const cfgRes = await apiGet('/api/config');
    if (cfgRes.status !== 'ok') return showToast('无法读取系统配置，请先在系统设置中配置AI模型', 'error', '配置读取失败');
    const model = (cfgRes.data.test?.models || [])[0] || '';
    if (!model) { showToast('未配置AI模型，请先在系统设置中选择模型', 'warning', '模型未配置'); switchPage('settings'); return; }

    const btn = $('startAttackBtn');
    btn.disabled = true;
    btn.innerHTML = '<i class="ri-loader-4-line ri-spin"></i> 启动中...';
    $('taskBadge').className = 'task-badge running';
    $('taskBadge').textContent = '运行中';
    $('logContainer').innerHTML = '';
    logOffset = 0;

    const res = await apiPost('/api/task/start', { name, ip_addr: ip, model });
    if (res.status === 'ok') {
        currentTaskId = res.data.id;
        addLogLine('系统', `任务 ${currentTaskId} 已启动`, 'system');
        addLogLine('系统', `目标: ${name} -> ${ip}`, 'system');
        addLogLine('系统', `模型: ${model}`, 'system');
        $('statusDot').style.background = 'var(--accent-blue)';
        $('statusText').textContent = '测试中';
        btn.disabled = false;
        btn.innerHTML = '<i class="ri-stop-circle-line"></i> 停止测试';
        btn.classList.add('btn-danger');
        btn.onclick = stopAttack;
        startLogPolling();
    } else {
        addLogLine('错误', res.message, 'error');
        resetAttackBtn();
        $('taskBadge').className = 'task-badge';
        $('taskBadge').textContent = '错误';
    }
}

function addLogLine(time, message, type = '') {
    const container = $('logContainer'), line = document.createElement('div');
    line.className = 'log-line';
    if (message.startsWith('[执行命令] $ ')) {
        const cmd = message.substring('[执行命令] $ '.length);
        line.innerHTML = `<span class="log-time">[${time}]</span><span class="log-msg system">[执行命令]</span><code class="log-cmd">$ ${escapeHtml(cmd)}</code>`;
    } else {
        line.innerHTML = `<span class="log-time">[${time}]</span><span class="log-msg ${type}">${escapeHtml(message)}</span>`;
    }
    container.appendChild(line);
    container.scrollTop = container.scrollHeight;
}

function startLogPolling() {
    if (logPollTimer) clearInterval(logPollTimer);
    logPollTimer = setInterval(pollLogs, 1500);
}

async function pollLogs() {
    if (!currentTaskId) return;
    const logRes = await apiGet(`/api/task/logs/${currentTaskId}?offset=${logOffset}`);
    if (logRes.status === 'ok' && logRes.data.length > 0) {
        logRes.data.forEach(log => {
            let type = '';
            if (log.message.includes('[错误]') || log.message.includes('[ERROR]')) type = 'error';
            else if (log.message.includes('[WARNING]')) type = 'warning';
            else if (log.message.includes('[系统]') || log.message.includes('[+]')) type = 'system';
            addLogLine(log.time, log.message, type);
        });
        logOffset = logRes.total;
    }
    const statusRes = await apiGet('/api/task/status');
    if (statusRes.status === 'ok' && statusRes.data?.status !== 'running') {
        clearInterval(logPollTimer);
        logPollTimer = null;
        resetAttackBtn();
        const badge = $('taskBadge'), st = statusRes.data.status;
        const ok = statusRes.data.result === 'success';
        const stopped = st === 'stopped' || statusRes.data.result === 'stopped';
        if (stopped) {
            badge.className = 'task-badge'; badge.textContent = '已停止';
            addLogLine('系统', '⏹ 测试已被用户中断', 'warning');
        } else {
            badge.className = `task-badge ${ok ? 'success' : 'failed'}`;
            badge.textContent = ok ? '成功' : '失败';
            addLogLine('系统', ok ? '🎉 渗透测试成功！' : '❌ 渗透测试未成功', ok ? 'system' : 'error');
        }
        $('statusDot').style.background = 'var(--accent-green)';
        $('statusText').textContent = '就绪';
    }
}

async function stopAttack() {
    const btn = $('startAttackBtn');
    btn.disabled = true;
    btn.innerHTML = '<i class="ri-loader-4-line ri-spin"></i> 正在停止...';
    const res = await apiPost('/api/task/stop', {});
    if (res.status === 'ok') addLogLine('系统', '⏹ 正在中断测试进程...', 'warning');
    else showToast(res.message || '停止失败', 'error', '操作失败');
}

function resetAttackBtn() {
    const btn = $('startAttackBtn');
    btn.disabled = false;
    btn.innerHTML = '<i class="ri-rocket-line"></i> 启动渗透测试';
    btn.classList.remove('btn-danger');
    btn.onclick = startAttack;
}

// ==================== Docker管理 ====================
function renderEnvSkeleton(n = 6) {
    return Array.from({ length: n }, () => `
        <div class="env-item env-skeleton"><div class="env-info">
            <div class="env-title-row"><span class="skeleton-bone" style="width:8px;height:8px;border-radius:50%"></span><span class="skeleton-bone" style="width:55%;height:14px"></span></div>
            <div class="skeleton-bone" style="width:80%;height:11px;margin-top:8px"></div>
        </div><div class="env-actions"><span class="skeleton-bone" style="width:68px;height:30px;border-radius:6px"></span></div></div>`).join('');
}

function renderEnvCards(envs) {
    return envs.map(env => {
        const on = env.status === 'running', ep = encodeURIComponent(env.compose_file);
        return `<div class="env-item ${on ? 'env-running' : ''}"><div class="env-info">
            <div class="env-title-row"><span class="env-status-dot ${on ? 'running' : 'stopped'}"></span><span class="env-name">${env.name}</span></div>
            <div class="env-path">${escapeHtml(env.compose_file)}</div></div>
            <div class="env-actions"><button class="env-btn ${on ? 'stop' : 'start'}" data-action="${on ? 'stop' : 'start'}" data-compose="${ep}">
                <i class="ri-${on ? 'stop' : 'play'}-fill"></i> ${on ? '停止' : '启动'}</button></div></div>`;
    }).join('');
}

async function refreshDocker() {
    const bar = $('dockerStatusBar');
    bar.className = 'docker-status-bar';
    bar.innerHTML = '<i class="ri-loader-4-line ri-spin"></i> 正在检查Docker状态...';
    const res = await apiGet('/api/docker/status');
    const tbody = $('containerBody');
    if (res.status === 'ok' && res.data.docker_running) {
        bar.className = 'docker-status-bar ok';
        bar.innerHTML = '<i class="ri-checkbox-circle-fill"></i> Docker运行正常';
        const cs = res.data.containers;
        tbody.innerHTML = cs.length ? cs.map(c => `<tr>
            <td><code style="color:var(--accent-cyan)">${(c.ID || '').substring(0, 12)}</code></td>
            <td>${c.Image || ''}</td><td><span class="badge badge-success">${c.Status || ''}</span></td>
            <td><code>${c.Ports || ''}</code></td><td>${c.Names || ''}</td></tr>`).join('')
            : '<tr><td colspan="5" class="table-empty">暂无运行中的容器</td></tr>';
    } else {
        bar.className = 'docker-status-bar error';
        bar.innerHTML = `<i class="ri-error-warning-fill"></i> ${res.data?.message || res.message || 'Docker不可用'}`;
        tbody.innerHTML = '<tr><td colspan="5" class="table-empty">Docker未运行</td></tr>';
    }
    loadDockerEnvs();
}

async function loadDockerEnvs() {
    const grid = $('envGrid');
    grid.innerHTML = _envCache ? renderEnvCards(_envCache) : renderEnvSkeleton(6);
    const res = await apiGet('/api/docker/envs');
    if (res.status !== 'ok' || !res.data.length) {
        grid.innerHTML = '<div class="loading-spinner">未找到Docker Compose环境</div>';
        _envCache = null; return;
    }
    _envCache = res.data;
    grid.innerHTML = renderEnvCards(res.data);
}

document.addEventListener('click', e => {
    const btn = e.target.closest('[data-action][data-compose]');
    if (!btn) return;
    const path = decodeURIComponent(btn.dataset.compose);
    btn.dataset.action === 'start' ? startEnv(path) : stopEnv(path);
});

async function startEnv(composePath) {
    const t = showToast('正在启动靶机环境，镜像拉取可能较慢，请耐心等候...', 'info', '启动中', 60000);
    const res = await apiPost('/api/docker/start', { compose_file: composePath });
    dismissToast(t);
    const errTitles = { docker_daemon: 'Docker服务不可用', sandbox_limit: '沙箱环境限制', rate_limit: 'Docker Hub限流', timeout: '操作超时' };
    if (res.status === 'ok') showToast(res.message || '环境启动成功', 'success', '靶机已启动');
    else showToast(res.message || '启动失败', 'error', errTitles[res.error_type] || '启动失败');
    refreshDocker();
}

async function stopEnv(composePath) {
    if (!await showConfirm('确定要停止这个靶机环境吗？所有相关容器和卷将被移除。', '停止靶机')) return;
    const t = showToast('正在停止靶机环境...', 'info', '停止中', 60000);
    const res = await apiPost('/api/docker/stop', { compose_file: composePath });
    dismissToast(t);
    showToast(res.message || (res.status === 'ok' ? '环境已停止' : '停止失败'), res.status === 'ok' ? 'success' : 'error', res.status === 'ok' ? '靶机已停止' : '操作失败');
    refreshDocker();
}

// ==================== 测试报告 ====================
let _allResults = [], _sortDesc = true;

async function loadResults() {
    const res = await apiGet('/api/results');
    if (res.status !== 'ok' || !res.data.length) {
        _allResults = []; window._results = [];
        $('resultBody').innerHTML = '<tr><td colspan="6" class="table-empty">暂无测试记录</td></tr>';
        $('historyCountBadge').textContent = '0 条';
        loadAnalytics([], null); return;
    }
    _allResults = res.data; window._results = _allResults;
    const input = $('historySearch'); if (input) input.value = '';
    renderResultsTable(_allResults);
    const statsRes = await apiGet('/api/results/stats');
    loadAnalytics(_allResults, statsRes.status === 'ok' ? statsRes.data : null);
}

function renderResultsTable(data) {
    const sorted = [...data].sort((a, b) => {
        const ta = a.timestamp || '', tb = b.timestamp || '';
        return _sortDesc ? tb.localeCompare(ta) : ta.localeCompare(tb);
    });
    $('historyCountBadge').textContent = `${sorted.length} 条`;
    if (!sorted.length) { $('resultBody').innerHTML = '<tr><td colspan="6" class="table-empty">未找到匹配记录</td></tr>'; return; }
    $('resultBody').innerHTML = sorted.map(r => {
        const i = _allResults.indexOf(r), ok = r.flag === 'success';
        const ts = r.timestamp ? new Date(r.timestamp).toLocaleString('zh-CN', {month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'}) : '-';
        return `<tr><td><span style="color:var(--text-muted);font-size:12px;white-space:nowrap"><i class="ri-time-line" style="margin-right:3px"></i>${ts}</span></td>
            <td><code style="color:var(--accent-cyan)">${r.source_file || `test_${i}`}</code></td>
            <td>${r.model || 'N/A'}</td>
            <td><span class="badge ${ok ? 'badge-success' : 'badge-danger'}">${ok ? '✓ 成功' : '✗ 失败'}</span></td>
            <td>${r.runtime ? r.runtime.toFixed(1) + 's' : 'N/A'}</td>
            <td><button class="btn btn-sm" onclick="showResultDetail(${i})"><i class="ri-eye-line"></i></button></td></tr>`;
    }).join('');
}

function filterResults() {
    const input = $('historySearch'), clearBtn = $('historySearchClear');
    const kw = (input?.value || '').toLowerCase().trim();
    clearBtn?.classList.toggle('visible', kw.length > 0);
    if (!kw) { renderResultsTable(_allResults); return; }
    renderResultsTable(_allResults.filter(r =>
        (r.source_file || '').toLowerCase().includes(kw) ||
        (r.model || '').toLowerCase().includes(kw) ||
        (r.flag === 'success' ? '成功 success' : '失败 failed').includes(kw)));
}

function clearSearch() {
    const input = $('historySearch');
    if (input) { input.value = ''; input.focus(); }
    $('historySearchClear')?.classList.remove('visible');
    renderResultsTable(_allResults);
}

function toggleSortOrder() {
    _sortDesc = !_sortDesc;
    $('sortIcon').className = _sortDesc ? 'ri-arrow-up-s-line' : 'ri-arrow-down-s-line';
    $('sortLabel').textContent = _sortDesc ? '最新优先' : '最早优先';
    $('historySortBtn').classList.toggle('asc', !_sortDesc);
    filterResults();
}

function loadAnalytics(results, stats) {
    const total = results.length, sc = results.filter(r => r.flag === 'success').length;
    $('analyticSuccess').textContent = sc;
    $('analyticFailed').textContent = total - sc;
    $('analyticRate').textContent = (total > 0 ? Math.round(sc / total * 100) : 0) + '%';
    $('analyticAvgTime').textContent = (total > 0 ? (results.reduce((s, r) => s + (r.runtime || 0), 0) / total).toFixed(1) : 0) + 's';
    renderTypeDistChart(stats);
    renderTrendChart(results);
}

function renderTypeDistChart(stats) {
    const el = $('typeDistChart');
    if (!stats?.type_stats || !Object.keys(stats.type_stats).length) { el.innerHTML = '<div class="trend-empty">暂无类型数据</div>'; return; }
    const types = stats.type_stats, max = Math.max(...Object.values(types).map(v => v.total), 1);
    el.innerHTML = Object.entries(types).map(([name, d]) => `<div class="chart-bar-row">
        <span class="chart-bar-label" title="${name}">${name}</span>
        <div class="chart-bar-track"><div class="chart-bar-fill total" style="width:${(d.total/max*100).toFixed(0)}%"></div>
            <div class="chart-bar-fill success" style="width:${(d.success/max*100).toFixed(0)}%;position:absolute;top:0;left:0;height:100%;opacity:0.8"></div></div>
        <span class="chart-bar-value">${d.success}/${d.total}</span></div>`).join('');
}

function renderTrendChart(results) {
    const el = $('trendChart');
    if (!results.length) { el.innerHTML = '<div class="trend-empty">暂无趋势数据</div>'; return; }
    const recent = results.slice(-20), maxT = Math.max(...recent.map(r => r.runtime || 0), 1);
    el.innerHTML = recent.map((r, i) => {
        const ok = r.flag === 'success', h = Math.max(((r.runtime || 0) / maxT) * 130, 4);
        const name = (r.source_file || `#${i+1}`).split('/').pop().replace(/\.json$/i, '').slice(0, 12);
        return `<div class="trend-bar-group" title="${r.source_file || ''}\n耗时: ${r.runtime ? r.runtime.toFixed(1)+'s' : 'N/A'}\n结果: ${ok ? '成功' : '失败'}">
            <div class="trend-bar ${ok ? 'success-bar' : 'failed-bar'}" style="height:${h}px"></div>
            <span class="trend-bar-label">${name}</span></div>`;
    }).join('');
}

function showResultDetail(index) {
    const r = window._results[index];
    if (!r) return;
    const ok = r.flag === 'success';
    const ts = r.timestamp ? new Date(r.timestamp).toLocaleString('zh-CN') : '未知';
    $('modalTitle').textContent = `测试详情 - ${r.source_file || ''}`;
    let html = `<div style="margin-bottom:12px">
        <span class="badge ${ok ? 'badge-success' : 'badge-danger'}" style="font-size:13px;padding:5px 14px">${ok ? '✓ 渗透成功' : '✗ 渗透失败'}</span>
        <span class="badge badge-info" style="margin-left:8px">${r.model || 'N/A'}</span></div>
        <p style="margin-bottom:8px"><i class="ri-calendar-line" style="margin-right:4px;color:var(--accent-cyan)"></i>时间: <strong>${ts}</strong></p>
        <p style="margin-bottom:12px"><i class="ri-timer-line" style="margin-right:4px;color:var(--accent-cyan)"></i>耗时: <strong>${r.runtime ? r.runtime.toFixed(1)+'s' : 'N/A'}</strong></p>`;
    if (r.commands?.length)
        html += `<h4 style="margin:16px 0 8px;color:var(--text-primary)">执行命令</h4>
            <div style="background:var(--bg-input);padding:12px;border-radius:8px;font-family:var(--font-mono);font-size:12px;max-height:200px;overflow-y:auto">
            ${r.commands.map(c => `<div style="padding:2px 0;color:var(--accent-green)">$ ${escapeHtml(String(c))}</div>`).join('')}</div>`;
    if (r.history?.length)
        html += `<h4 style="margin:16px 0 8px;color:var(--text-primary)">执行历史</h4>
            <div style="background:var(--bg-input);padding:12px;border-radius:8px;font-family:var(--font-mono);font-size:11px;max-height:300px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;color:var(--text-secondary)">
            ${r.history.map(h => escapeHtml(String(h))).join('\n---\n')}</div>`;
    $('modalBody').innerHTML = html;
    $('modalOverlay').classList.add('active');
}

// ==================== 系统设置 ====================
async function loadConfig() {
    const res = await apiGet('/api/config');
    if (res.status !== 'ok') return;
    const c = res.data;
    $('cfgApiBase').value = c.ai?.openai_base || '';
    $('cfgApiKey').value = c.ai?.openai_key || '';
    $('cfgTemp').value = c.ai?.temperature || 0.5;
    $('cfgTempVal').textContent = c.ai?.temperature || 0.5;
    const cur = (c.test?.models || [])[0] || 'gpt4omini';
    const sel = $('cfgModel'), custom = $('cfgModelCustom');
    if (PRESET_MODELS.includes(cur)) { sel.value = cur; custom.style.display = 'none'; }
    else { sel.value = '__custom__'; custom.value = cur; custom.style.display = 'block'; }
    $('cfgSysIter').value = c.psm?.sys_iterations || 15;
    $('cfgExpIter').value = c.psm?.exp_iterations || 3;
    $('cfgQueryIter').value = c.psm?.query_iterations || 1;
    $('cfgScanIter').value = c.psm?.scan_iterations || 1;
    $('cfgTimeout').value = c.local?.command_timeout || 120;
}

function onCfgModelChange() { $('cfgModelCustom').style.display = $('cfgModel').value === '__custom__' ? 'block' : 'none'; }

async function saveConfig() {
    const modelName = $('cfgModel').value === '__custom__' ? $('cfgModelCustom').value.trim() : $('cfgModel').value;
    if (!modelName) return showToast('请输入自定义模型名称', 'warning', '参数缺失');
    const cur = await apiGet('/api/config');
    const base = cur.status === 'ok' ? cur.data : {};
    const config = {
        ai: { ...(base.ai || {}), openai_base: $('cfgApiBase').value, openai_key: $('cfgApiKey').value, temperature: parseFloat($('cfgTemp').value) },
        test: { ...(base.test || {}), models: [modelName] },
        psm: { ...(base.psm || {}), sys_iterations: +$('cfgSysIter').value, exp_iterations: +$('cfgExpIter').value, query_iterations: +$('cfgQueryIter').value, scan_iterations: +$('cfgScanIter').value },
        local: { ...(base.local || {}), command_timeout: +$('cfgTimeout').value },
        web: base.web || { host: '0.0.0.0', port: 5000, debug: false }
    };
    const res = await apiPost('/api/config', config);
    showToast(res.status === 'ok' ? '配置已保存成功' : '保存失败: ' + res.message, res.status === 'ok' ? 'success' : 'error', res.status === 'ok' ? '保存成功' : '配置保存失败');
}

async function loadSystemInfo() {
    const res = await apiGet('/api/system/info');
    if (res.status !== 'ok') { $('sysInfo').innerHTML = '<div class="loading-spinner">加载失败</div>'; return; }
    const d = res.data;
    $('sysInfo').innerHTML = [
        ['操作系统', d.platform], ['Python版本', d.python_version], ['系统架构', d.arch],
        ['Docker', `<span class="badge ${d.docker_available ? 'badge-success' : 'badge-danger'}">${d.docker_available ? '✓ 可用' : '✗ 不可用'}</span>`],
        ['Docker版本', `<span style="font-size:11px">${d.docker_version || 'N/A'}</span>`],
        ['xray扫描器', `<span class="badge ${d.xray_available ? 'badge-success' : 'badge-warning'}">${d.xray_available ? '✓ 可用' : '⚠ 未找到'}</span>`]
    ].map(([l, v]) => `<div class="sys-info-item"><span class="sys-info-label">${l}</span><span class="sys-info-value">${v}</span></div>`).join('');
}

// ==================== Toast通知 ====================
function showToast(message, type = 'success', title = '', duration = 4000) {
    let c = $('toastContainer');
    if (!c) { c = document.createElement('div'); c.id = 'toastContainer'; c.className = 'toast-container'; document.body.appendChild(c); }
    const icons = { success: 'ri-checkbox-circle-fill', error: 'ri-error-warning-fill', warning: 'ri-alert-fill', info: 'ri-information-fill' };
    const titles = { success: '操作成功', error: '操作失败', warning: '警告', info: '提示' };
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `<div class="toast-icon"><i class="${icons[type] || icons.info}"></i></div>
        <div class="toast-content"><div class="toast-title">${title || titles[type]}</div><div class="toast-message">${escapeHtml(message)}</div></div>
        <button class="toast-close" onclick="dismissToast(this.parentElement)"><i class="ri-close-line"></i></button>
        <div class="toast-progress" style="animation-duration:${duration}ms"></div>`;
    c.appendChild(toast);
    setTimeout(() => dismissToast(toast), duration);
    while (c.children.length > 5) dismissToast(c.children[0]);
    return toast;
}

function dismissToast(t) { if (!t || t.classList.contains('toast-exit')) return; t.classList.add('toast-exit'); setTimeout(() => t.remove(), 300); }

// ==================== 确认对话框 ====================
function showConfirm(message, title = '确认操作') {
    return new Promise(resolve => {
        const old = $('confirmOverlay'); if (old) old.remove();
        const ov = document.createElement('div');
        ov.id = 'confirmOverlay'; ov.className = 'confirm-overlay active';
        ov.innerHTML = `<div class="confirm-dialog">
            <div class="confirm-header"><div class="confirm-header-icon"><i class="ri-question-line"></i></div><div class="confirm-header-text">${escapeHtml(title)}</div></div>
            <div class="confirm-body">${escapeHtml(message)}</div>
            <div class="confirm-actions"><button class="confirm-btn confirm-btn-cancel" id="confirmCancel">取消</button><button class="confirm-btn confirm-btn-ok" id="confirmOk">确认</button></div></div>`;
        document.body.appendChild(ov);
        const done = r => { ov.remove(); resolve(r); };
        $('confirmOk').onclick = () => done(true);
        $('confirmCancel').onclick = () => done(false);
        ov.addEventListener('click', e => { if (e.target === ov) done(false); });
    });
}

// ==================== 初始化 ====================
document.addEventListener('DOMContentLoaded', () => { loadDashboard(); loadVulns(); });
