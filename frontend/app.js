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
            $('statRate').textContent = (d.success_rate ?? 0).toFixed(2) + '%';
            $('statAvgTime').textContent = (d.avg_runtime ?? 0) + 's';
            // Token 成本
            const ts = d.token_stats;
            if (ts) {
                $('statTokenCost').textContent = '$' + (ts.avg_cost_per_test ?? 0).toFixed(2);
                $('statTotalTokens').textContent = formatTokenCount(ts.avg_tokens_per_test ?? 0);
            }
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
        return `<div class="env-item ${on ? 'env-running' : ''}">
            <div class="env-item-header">
                <div class="env-info">
                    <div class="env-title-row"><span class="env-status-dot ${on ? 'running' : 'stopped'}"></span><span class="env-name">${env.name}</span></div>
                    <div class="env-path">${escapeHtml(env.compose_file)}</div>
                </div>
                <div class="env-menu-wrap">
                    <button class="env-menu-btn" data-menu-toggle="${ep}" onclick="toggleEnvMenu(event, '${ep}')" ${on ? '' : 'disabled'}><i class="ri-more-2-fill"></i></button>
                    <div class="env-dropdown" id="envMenu_${ep}">
                        <div class="env-dropdown-item" onclick="stopEnvFromMenu('${ep}', event)"><i class="ri-stop-circle-line"></i><span>停止环境</span></div>
                        <div class="env-dropdown-divider"></div>
                        <div class="env-dropdown-item danger" onclick="destroyEnvFromMenu('${ep}', event)"><i class="ri-delete-bin-line"></i><span>销毁环境</span></div>
                    </div>
                </div>
            </div>
            <div class="env-actions">${on ? '' : `<button class="env-btn start" data-action="start" data-compose="${ep}"><i class="ri-play-fill"></i> 启动</button>`}</div></div>`;
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
    if (btn.dataset.action === 'start') startEnv(path);
});

async function startEnv(composePath) {
    const t = showToast('正在启动靶机环境，若镜像不存在将自动拉取创建，请耐心等候...', 'info', '启动中', 120000);
    try {
        const res = await apiPost('/api/docker/start', { compose_file: composePath });
        dismissToast(t);
        const errTitles = {
            docker_daemon: 'Docker服务不可用',
            sandbox_limit: '沙箱环境限制',
            rate_limit: 'Docker Hub限流',
            timeout: '操作超时',
            pull_error: '镜像拉取失败',
            image_not_found: '镜像不存在',
            network_error: '网络异常',
            port_conflict: '端口冲突',
            disk_full: '磁盘空间不足',
        };
        if (res.status === 'ok') {
            const title = res.created ? '靶机已创建并启动' : '靶机已启动';
            showToast(res.message || '环境启动成功', 'success', title);
        } else {
            showToast(res.message || '启动失败', 'error', errTitles[res.error_type] || '启动失败');
        }
    } catch (e) {
        dismissToast(t);
        showToast('请求异常，可能是镜像拉取超时，请稍后重试', 'error', '启动失败');
    }
    refreshDocker();
}

async function stopEnv(composePath) {
    if (!await showConfirm('确定要停止这个靶机环境吗？容器将被保留，可随时重新启动。', '停止靶机')) return;
    const t = showToast('正在停止靶机环境...', 'info', '停止中', 60000);
    const res = await apiPost('/api/docker/stop', { compose_file: composePath });
    dismissToast(t);
    showToast(res.message || (res.status === 'ok' ? '环境已停止' : '停止失败'), res.status === 'ok' ? 'success' : 'error', res.status === 'ok' ? '靶机已停止' : '操作失败');
    refreshDocker();
}

// ===== 环境卡片三点菜单 =====
function toggleEnvMenu(e, ep) {
    e.stopPropagation();
    // 关闭所有其他已打开的菜单
    document.querySelectorAll('.env-dropdown.active').forEach(d => {
        if (d.id !== `envMenu_${ep}`) d.classList.remove('active');
    });
    const menu = document.getElementById(`envMenu_${ep}`);
    if (menu) menu.classList.toggle('active');
}

// 全局点击关闭下拉菜单
document.addEventListener('click', e => {
    if (!e.target.closest('.env-menu-wrap')) {
        document.querySelectorAll('.env-dropdown.active').forEach(d => d.classList.remove('active'));
    }
});

function stopEnvFromMenu(ep, e) {
    e.stopPropagation();
    document.querySelectorAll('.env-dropdown.active').forEach(d => d.classList.remove('active'));
    stopEnv(decodeURIComponent(ep));
}

async function destroyEnvFromMenu(ep, e) {
    e.stopPropagation();
    document.querySelectorAll('.env-dropdown.active').forEach(d => d.classList.remove('active'));
    const composePath = decodeURIComponent(ep);
    if (!await showConfirm('确定要彻底销毁这个靶机环境吗？\n将移除所有容器、数据卷和关联镜像，此操作不可恢复。', '销毁环境')) return;
    const t = showToast('正在销毁靶机环境，清理镜像中...', 'info', '销毁中', 120000);
    const res = await apiPost('/api/docker/destroy', { compose_file: composePath });
    dismissToast(t);
    showToast(
        res.message || (res.status === 'ok' ? '环境已销毁' : '销毁失败'),
        res.status === 'ok' ? 'success' : 'error',
        res.status === 'ok' ? '环境已销毁' : '操作失败'
    );
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
    if (!sorted.length) { $('resultBody').innerHTML = '<tr><td colspan="8" class="table-empty">未找到匹配记录</td></tr>'; return; }
    $('resultBody').innerHTML = sorted.map(r => {
        const i = _allResults.indexOf(r), ok = r.flag === 'success';
        const ts = r.timestamp ? new Date(r.timestamp).toLocaleString('zh-CN', {month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'}) : '-';
        const tu = r.token_usage || {};
        const tokenTotal = tu.total_tokens || 0;
        const tokenCost = tu.estimated_cost || 0;
        return `<tr><td><span style="color:var(--text-muted);font-size:12px;white-space:nowrap"><i class="ri-time-line" style="margin-right:3px"></i>${ts}</span></td>
            <td><code style="color:var(--accent-cyan)">${r.source_file || `test_${i}`}</code></td>
            <td>${r.model || 'N/A'}</td>
            <td><span class="badge ${ok ? 'badge-success' : 'badge-danger'}">${ok ? '✓ 成功' : '✗ 失败'}</span></td>
            <td>${r.runtime ? r.runtime.toFixed(1) + 's' : 'N/A'}</td>
            <td><span class="token-cell" title="Prompt: ${(tu.prompt_tokens||0).toLocaleString()} / Completion: ${(tu.completion_tokens||0).toLocaleString()}"><i class="ri-stack-line" style="color:#818cf8;margin-right:3px"></i>${formatTokenCount(tokenTotal)}</span></td>
            <td><span class="cost-cell ${tokenCost >= 3.0 ? 'cost-high' : tokenCost >= 2.5 ? 'cost-mid' : 'cost-low'}">$${tokenCost.toFixed(2)}</span></td>
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

/** 切换成功率分析面板的Tab */
function switchRateTab(tab) {
    switchPanelTab('rate', tab);
}

/** 通用面板Tab切换 */
function switchPanelTab(panel, tab) {
    // 映射面板前缀到Tab容器ID前缀
    const prefixMap = { rate: 'rateTab', token: 'tokenTab', tool: 'toolTab' };
    const prefix = prefixMap[panel];
    if (!prefix) return;
    // 找到父section
    const target = document.getElementById(`${prefix}-${tab}`);
    if (!target) return;
    const section = target.closest('.analytics-chart-section');
    if (!section) return;
    // 切换Tab按钮状态
    section.querySelectorAll('.rate-tab').forEach(t => {
        const tTab = t.dataset.tab;
        // 支持 "difficulty" 或 "token-difficulty" 格式
        const isActive = tTab === tab || tTab === `${panel}-${tab}`;
        t.classList.toggle('active', isActive);
    });
    // 切换Tab内容
    section.querySelectorAll('.rate-tab-content').forEach(c => c.classList.remove('active'));
    target.classList.add('active');
}

function loadAnalytics(results, stats) {
    const total = results.length, sc = results.filter(r => r.flag === 'success').length;
    $('analyticSuccess').textContent = sc;
    $('analyticFailed').textContent = total - sc;
    $('analyticRate').textContent = (total > 0 ? (sc / total * 100).toFixed(2) : '0.00') + '%';
    $('analyticAvgTime').textContent = (total > 0 ? (results.reduce((s, r) => s + (r.runtime || 0), 0) / total).toFixed(1) : 0) + 's';
    renderDifficultyRate(stats);
    renderModelRate(stats);
    renderTokenCost(stats);
    renderToolCallStats(stats);
}

function renderDifficultyRate(stats) {
    const el = $('difficultyRatePanel');
    if (!el) return;
    const ds = stats?.difficulty_stats;
    if (!ds || !Object.keys(ds).length) { el.innerHTML = '<div class="trend-empty">暂无难度数据</div>'; return; }
    const labels = { Simple: '简单', Complex: '复杂' };
    const colors = { Simple: 'var(--accent-green)', Complex: 'var(--accent-red)' };
    el.innerHTML = Object.entries(ds).map(([name, d]) => {
        const tested = d.tested || 0, success = d.success || 0;
        const rate = tested > 0 ? (success / tested * 100).toFixed(2) : '0.00';
        const pct = tested > 0 ? (success / tested * 100) : 0;
        return `<div class="diff-rate-item">
            <div class="diff-rate-header">
                <span class="diff-rate-label">${labels[name] || name}</span>
                <span class="diff-rate-value" style="color:${colors[name] || 'var(--accent-cyan)'}">${rate}%</span>
            </div>
            <div class="diff-rate-bar-track">
                <div class="diff-rate-bar-fill" style="width:${pct}%;background:${colors[name] || 'var(--accent-cyan)'}"></div>
            </div>
            <div class="diff-rate-detail">${success}/${tested} 成功 · 共 ${d.total || 0} 个漏洞</div>
        </div>`;
    }).join('');
}

function renderModelRate(stats) {
    const el = $('modelRatePanel');
    if (!el) return;
    const ms = stats?.model_stats;
    if (!ms || !Object.keys(ms).length) { el.innerHTML = '<div class="trend-empty">暂无模型数据</div>'; return; }
    const sorted = Object.entries(ms).sort((a, b) => {
        const ra = a[1].total > 0 ? a[1].success / a[1].total : 0;
        const rb = b[1].total > 0 ? b[1].success / b[1].total : 0;
        return rb - ra;
    });
    const maxTotal = Math.max(...sorted.map(([, d]) => d.total), 1);
    const medalIcons = ['🥇', '🥈', '🥉'];
    el.innerHTML = sorted.map(([name, d], idx) => {
        const rate = d.total > 0 ? (d.success / d.total * 100).toFixed(2) : '0.00';
        const pct = d.total > 0 ? (d.success / d.total * 100) : 0;
        const barW = (d.total / maxTotal * 100).toFixed(0);
        const medal = idx < 3 ? `<span class="model-medal">${medalIcons[idx]}</span>` : '';
        const rateColor = pct >= 80 ? 'var(--accent-green)' : pct >= 50 ? 'var(--accent-yellow, #f59e0b)' : 'var(--accent-red)';
        return `<div class="model-rate-item">
            <div class="model-rate-header">
                <span class="model-rate-name">${medal}${name}</span>
                <span class="model-rate-value" style="color:${rateColor}">${rate}%</span>
            </div>
            <div class="model-rate-bar-track">
                <div class="model-rate-bar-bg" style="width:${barW}%"></div>
                <div class="model-rate-bar-fill" style="width:${pct}%"></div>
            </div>
            <div class="model-rate-detail">${d.success}/${d.total} 成功</div>
        </div>`;
    }).join('');
}

/** 格式化 token 数量为可读字符串 */
function formatTokenCount(n) {
    if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
    if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
    return String(n);
}

/** 渲染 Token 成本统计面板 - 概览+按难度/按模型Tab */
function renderTokenCost(stats) {
    const overviewEl = $('tokenOverview');
    const diffEl = $('tokenDiffPanel');
    const modelEl = $('tokenModelPanel');
    if (!overviewEl || !diffEl || !modelEl) return;
    const ts = stats?.token_stats;
    if (!ts || !ts.total_tokens) {
        overviewEl.innerHTML = '';
        diffEl.innerHTML = '<div class="trend-empty">暂无 Token 数据</div>';
        modelEl.innerHTML = '<div class="trend-empty">暂无 Token 数据</div>';
        return;
    }

    // 概览指标（始终显示）
    overviewEl.innerHTML = `
        <div class="token-metric token-metric-highlight">
            <div class="token-metric-icon" style="background:rgba(245,158,11,0.15);color:#f59e0b"><i class="ri-money-dollar-circle-line"></i></div>
            <div class="token-metric-info">
                <span class="token-metric-value">$${ts.avg_cost_per_test.toFixed(2)}</span>
                <span class="token-metric-label">平均成本/次</span>
            </div>
        </div>
        <div class="token-metric">
            <div class="token-metric-icon" style="background:rgba(99,102,241,0.12);color:#818cf8"><i class="ri-stack-line"></i></div>
            <div class="token-metric-info">
                <span class="token-metric-value">${formatTokenCount(ts.avg_tokens_per_test)}</span>
                <span class="token-metric-label">平均 Tokens/次</span>
            </div>
        </div>
        <div class="token-metric">
            <div class="token-metric-icon" style="background:rgba(16,185,129,0.12);color:#10b981"><i class="ri-exchange-line"></i></div>
            <div class="token-metric-info">
                <span class="token-metric-value">${formatTokenCount(ts.total_tokens)}</span>
                <span class="token-metric-label">总 Tokens</span>
            </div>
        </div>
        <div class="token-metric">
            <div class="token-metric-icon" style="background:rgba(239,68,68,0.12);color:#ef4444"><i class="ri-file-list-3-line"></i></div>
            <div class="token-metric-info">
                <span class="token-metric-value">${ts.total_cost > 0 ? (ts.total_prompt_tokens / ts.total_tokens * 100).toFixed(0) + '%' : '0%'}</span>
                <span class="token-metric-label">Prompt 占比</span>
            </div>
        </div>`;

    // 按难度Tab内容
    const dts = ts.difficulty_token_stats;
    if (dts && Object.keys(dts).length) {
        const labels = { Simple: '简单漏洞', Complex: '复杂漏洞' };
        const icons = { Simple: 'ri-shield-check-line', Complex: 'ri-shield-cross-line' };
        const colors = { Simple: '#10b981', Complex: '#ef4444' };
        let diffHtml = '<div class="token-diff-grid">';
        Object.entries(dts).forEach(([name, d]) => {
            const avgCost = d.avg_cost || 0;
            const avgTokens = d.avg_tokens || 0;
            const color = colors[name] || '#818cf8';
            diffHtml += `<div class="token-diff-card" style="--card-color:${color}">
                <div class="token-diff-card-header">
                    <i class="${icons[name] || 'ri-shield-line'}" style="color:${color}"></i>
                    <span class="token-diff-card-label">${labels[name] || name}</span>
                </div>
                <div class="token-diff-card-cost">$${avgCost.toFixed(2)}</div>
                <div class="token-diff-card-detail">
                    <span><i class="ri-stack-line"></i> ${formatTokenCount(avgTokens)} tokens/次</span>
                    <span><i class="ri-test-tube-line"></i> ${d.count} 次测试</span>
                </div>
            </div>`;
        });
        diffHtml += '</div>';
        diffEl.innerHTML = diffHtml;
    } else {
        diffEl.innerHTML = '<div class="trend-empty">暂无难度数据</div>';
    }

    // 按模型Tab内容
    const mts = ts.model_token_stats;
    if (mts && Object.keys(mts).length) {
        const sorted = Object.entries(mts).sort((a, b) => (a[1].avg_cost || 0) - (b[1].avg_cost || 0));
        const maxAvgCost = Math.max(...sorted.map(([, d]) => d.avg_cost || 0), 0.01);
        let modelHtml = '<div class="token-model-compare-list">';
        sorted.forEach(([name, d], idx) => {
            const avgCost = d.avg_cost || 0;
            const avgTokens = d.avg_tokens || 0;
            const pct = (avgCost / maxAvgCost * 100).toFixed(0);
            const costColor = avgCost >= 3.0 ? '#ef4444' : avgCost >= 2.7 ? '#f59e0b' : '#10b981';
            const rankIcon = idx === 0 ? '<span class="token-rank-badge best">💰 最低</span>' : idx === sorted.length - 1 ? '<span class="token-rank-badge high">🔥 最高</span>' : '';
            modelHtml += `<div class="token-model-compare-row">
                <div class="token-model-compare-info">
                    <span class="token-model-compare-name">${name} ${rankIcon}</span>
                    <span class="token-model-compare-meta">${formatTokenCount(avgTokens)} tokens/次 · ${d.count} 次</span>
                </div>
                <div class="token-model-compare-bar-wrap">
                    <div class="token-model-compare-bar" style="width:${pct}%;background:${costColor}"></div>
                </div>
                <div class="token-model-compare-cost" style="color:${costColor}">$${avgCost.toFixed(2)}</div>
            </div>`;
        });
        modelHtml += '</div>';
        modelEl.innerHTML = modelHtml;
    } else {
        modelEl.innerHTML = '<div class="trend-empty">暂无模型数据</div>';
    }
}


/** 渲染工具调用次数统计面板 - 概览+按难度/按模型Tab */
function renderToolCallStats(stats) {
    const overviewEl = $('toolCallOverview');
    const diffEl = $('toolDiffPanel');
    const modelEl = $('toolModelPanel');
    if (!overviewEl || !diffEl || !modelEl) return;
    const tcs = stats?.tool_call_stats;
    if (!tcs || !tcs.total_calls) {
        overviewEl.innerHTML = '';
        diffEl.innerHTML = '<div class="trend-empty">暂无工具调用数据</div>';
        modelEl.innerHTML = '<div class="trend-empty">暂无工具调用数据</div>';
        return;
    }

    // 概览指标（始终显示）
    overviewEl.innerHTML = `
        <div class="tool-call-metric tool-call-metric-highlight">
            <div class="tool-call-metric-icon" style="background:rgba(139,92,246,0.15);color:#8b5cf6"><i class="ri-tools-line"></i></div>
            <div class="tool-call-metric-info">
                <span class="tool-call-metric-value">${tcs.avg_calls_per_test}</span>
                <span class="tool-call-metric-label">平均调用/次</span>
            </div>
        </div>
        <div class="tool-call-metric">
            <div class="tool-call-metric-icon" style="background:rgba(59,130,246,0.12);color:#3b82f6"><i class="ri-terminal-box-line"></i></div>
            <div class="tool-call-metric-info">
                <span class="tool-call-metric-value">${tcs.total_calls.toLocaleString()}</span>
                <span class="tool-call-metric-label">总调用次数</span>
            </div>
        </div>`;

    // 按难度Tab内容：工具类型分布 + 难度对比
    let diffHtml = '';

    // 工具类型分布
    const ttd = tcs.tool_type_distribution;
    if (ttd && Object.keys(ttd).length) {
        const maxCount = Math.max(...Object.values(ttd), 1);
        const toolIcons = {
            nmap: 'ri-radar-line', xray: 'ri-scan-line', curl: 'ri-link',
            sqlmap: 'ri-database-2-line', nikto: 'ri-search-eye-line',
            metasploit: 'ri-bug-line', python: 'ri-code-s-slash-line',
            shell: 'ri-terminal-line', other: 'ri-more-line'
        };
        const toolColors = {
            nmap: '#3b82f6', xray: '#06b6d4', curl: '#10b981',
            sqlmap: '#ef4444', nikto: '#f59e0b', metasploit: '#8b5cf6',
            python: '#ec4899', shell: '#64748b', other: '#94a3b8'
        };
        diffHtml += `<div class="tool-type-section">
            <div class="tool-type-title"><i class="ri-pie-chart-line" style="color:var(--accent-cyan)"></i> 工具类型分布</div>
            <div class="tool-type-list">`;
        Object.entries(ttd).forEach(([name, count]) => {
            const pct = (count / maxCount * 100).toFixed(0);
            const totalPct = (count / tcs.total_calls * 100).toFixed(1);
            const icon = toolIcons[name] || 'ri-tools-line';
            const color = toolColors[name] || '#818cf8';
            diffHtml += `<div class="tool-type-row">
                <div class="tool-type-info">
                    <span class="tool-type-icon" style="color:${color}"><i class="${icon}"></i></span>
                    <span class="tool-type-name">${name}</span>
                    <span class="tool-type-pct">${totalPct}%</span>
                </div>
                <div class="tool-type-bar-wrap">
                    <div class="tool-type-bar" style="width:${pct}%;background:${color}"></div>
                </div>
                <div class="tool-type-count">${count}</div>
            </div>`;
        });
        diffHtml += `</div></div>`;
    }

    // 难度对比
    const dts = tcs.difficulty_tool_stats;
    if (dts && Object.keys(dts).length) {
        const labels = { Simple: '简单漏洞', Complex: '复杂漏洞' };
        const colors = { Simple: '#10b981', Complex: '#ef4444' };
        const icons = { Simple: 'ri-shield-check-line', Complex: 'ri-shield-cross-line' };
        diffHtml += `<div class="tool-diff-section">
            <div class="tool-type-title"><i class="ri-bar-chart-line" style="color:var(--accent-cyan)"></i> 难度调用对比</div>
            <div class="tool-diff-grid">`;
        Object.entries(dts).forEach(([name, d]) => {
            const color = colors[name] || '#818cf8';
            diffHtml += `<div class="tool-diff-card" style="--card-color:${color}">
                <div class="tool-diff-card-header">
                    <i class="${icons[name] || 'ri-shield-line'}" style="color:${color}"></i>
                    <span class="tool-diff-card-label">${labels[name] || name}</span>
                </div>
                <div class="tool-diff-card-value">${d.avg_calls || 0}<small> 次/测试</small></div>
                <div class="tool-diff-card-detail">
                    <span><i class="ri-terminal-box-line"></i> 共 ${d.total_calls || 0} 次调用</span>
                    <span><i class="ri-test-tube-line"></i> ${d.count || 0} 次测试</span>
                </div>
            </div>`;
        });
        diffHtml += `</div></div>`;
    }

    diffEl.innerHTML = diffHtml || '<div class="trend-empty">暂无难度数据</div>';

    // 按模型Tab内容
    const mts = tcs.model_tool_stats;
    if (mts && Object.keys(mts).length) {
        const sorted = Object.entries(mts).sort((a, b) => (b[1].avg_calls || 0) - (a[1].avg_calls || 0));
        const maxAvg = Math.max(...sorted.map(([, d]) => d.avg_calls || 0), 0.1);
        let modelHtml = '<div class="tool-model-list">';
        sorted.forEach(([name, d]) => {
            const avg = d.avg_calls || 0;
            const pct = (avg / maxAvg * 100).toFixed(0);
            const barColor = avg >= maxAvg * 0.8 ? '#8b5cf6' : avg >= maxAvg * 0.5 ? '#3b82f6' : '#06b6d4';
            modelHtml += `<div class="tool-model-row">
                <div class="tool-model-info">
                    <span class="tool-model-name">${name}</span>
                    <span class="tool-model-meta">${d.total_calls} 次 · ${d.count} 测试</span>
                </div>
                <div class="tool-model-bar-wrap">
                    <div class="tool-model-bar" style="width:${pct}%;background:${barColor}"></div>
                </div>
                <div class="tool-model-avg" style="color:${barColor}">${avg}</div>
            </div>`;
        });
        modelHtml += '</div>';
        modelEl.innerHTML = modelHtml;
    } else {
        modelEl.innerHTML = '<div class="trend-empty">暂无模型数据</div>';
    }
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
    if (r.token_usage) {
        const tu = r.token_usage;
        html += `<div class="detail-token-bar" style="display:flex;gap:12px;margin-bottom:12px;flex-wrap:wrap">
            <div class="detail-token-chip" style="background:rgba(99,102,241,0.12);color:#818cf8;padding:6px 14px;border-radius:8px;font-size:12px;font-weight:600">
                <i class="ri-chat-upload-line" style="margin-right:3px"></i>Prompt: ${(tu.prompt_tokens || 0).toLocaleString()}
            </div>
            <div class="detail-token-chip" style="background:rgba(16,185,129,0.12);color:#10b981;padding:6px 14px;border-radius:8px;font-size:12px;font-weight:600">
                <i class="ri-chat-download-line" style="margin-right:3px"></i>Completion: ${(tu.completion_tokens || 0).toLocaleString()}
            </div>
            <div class="detail-token-chip" style="background:rgba(245,158,11,0.12);color:#f59e0b;padding:6px 14px;border-radius:8px;font-size:12px;font-weight:600">
                <i class="ri-coins-line" style="margin-right:3px"></i>Total: ${(tu.total_tokens || 0).toLocaleString()}
            </div>
            <div class="detail-token-chip" style="background:rgba(239,68,68,0.12);color:#ef4444;padding:6px 14px;border-radius:8px;font-size:12px;font-weight:600">
                <i class="ri-money-dollar-circle-line" style="margin-right:3px"></i>$${(tu.estimated_cost || 0).toFixed(4)}
            </div>
        </div>`; }
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
let _autoRefreshTimer = null;

function startAutoRefresh(interval = 30000) {
    if (_autoRefreshTimer) clearInterval(_autoRefreshTimer);
    _autoRefreshTimer = setInterval(() => {
        const activePage = document.querySelector('.page.active');
        if (activePage?.id === 'page-results') loadResults();
        else if (activePage?.id === 'page-dashboard') loadDashboard();
    }, interval);
}

document.addEventListener('DOMContentLoaded', () => { loadDashboard(); loadVulns(); startAutoRefresh(); });
