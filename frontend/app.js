/**
 * AutoPT 前端控制逻辑
 * 自动化渗透测试平台
 */

const API = '';  // 同域，无需前缀

// ==================== 全局状态 ====================
let allVulns = [];
let currentTaskId = null;
let logPollTimer = null;
let logOffset = 0;

// ==================== 页面导航 ====================
function switchPage(name) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    const page = document.getElementById(`page-${name}`);
    const nav = document.querySelector(`.nav-item[data-page="${name}"]`);
    if (page) page.classList.add('active');
    if (nav) nav.classList.add('active');

    const titles = {
        dashboard: '控制台', vulns: '漏洞库', attack: '渗透测试',
        docker: '靶机管理', results: '测试报告', settings: '系统设置'
    };
    document.getElementById('pageTitle').textContent = titles[name] || name;

    // 页面切换时加载数据
    if (name === 'dashboard') loadDashboard();
    if (name === 'vulns') loadVulns();
    if (name === 'attack') { /* 模型配置统一在系统设置管理 */ }
    if (name === 'docker') { refreshDocker(); loadDockerEnvs(); }
    if (name === 'results') { loadResults(); loadTaskHistory(); }
    if (name === 'settings') { loadConfig(); loadSystemInfo(); }
}

// 初始化导航事件
document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => switchPage(item.dataset.page));
});

// 侧边栏折叠
document.getElementById('menuToggle').addEventListener('click', () => {
    document.getElementById('sidebar').classList.toggle('open');
});

// ==================== API 请求封装 ====================
async function apiGet(url, retries = 2) {
    for (let i = 0; i <= retries; i++) {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 15000);
            const res = await fetch(API + url, { signal: controller.signal });
            clearTimeout(timeoutId);
            if (!res.ok) {
                const text = await res.text().catch(() => '');
                console.warn(`[API] ${url} 返回 HTTP ${res.status}: ${text.slice(0, 200)}`);
                try { return JSON.parse(text); } catch (_) {}
                return { status: 'error', message: `服务器返回 ${res.status}` };
            }
            return await res.json();
        } catch (e) {
            const errMsg = e.name === 'AbortError' ? '请求超时' : (e.message || '网络连接失败');
            console.warn(`[API] ${url} 请求失败 (${i + 1}/${retries + 1}): ${errMsg}`);
            if (i < retries) {
                await new Promise(r => setTimeout(r, 1000 * (i + 1)));
                continue;
            }
            return { status: 'error', message: errMsg };
        }
    }
}

async function apiPost(url, data) {
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 30000);
        const res = await fetch(API + url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
            signal: controller.signal
        });
        clearTimeout(timeoutId);
        if (!res.ok) {
            const text = await res.text().catch(() => '');
            console.warn(`[API] POST ${url} 返回 HTTP ${res.status}: ${text.slice(0, 200)}`);
            try { return JSON.parse(text); } catch (_) {}
            return { status: 'error', message: `服务器返回 ${res.status}` };
        }
        return await res.json();
    } catch (e) {
        const errMsg = e.name === 'AbortError' ? '请求超时' : (e.message || '网络连接失败');
        console.warn(`[API] POST ${url} 请求失败: ${errMsg}`);
        return { status: 'error', message: errMsg };
    }
}

// ==================== 控制台 ====================
async function loadDashboard() {
    try {
        const [statsRes, vulnRes] = await Promise.all([
            apiGet('/api/results/stats'),
            apiGet('/api/vulns')
        ]);

        if (statsRes.status === 'ok' && statsRes.data) {
            const d = statsRes.data;
            document.getElementById('statVulns').textContent = d.total_vulns ?? '-';
            document.getElementById('statSuccess').textContent = d.success_count ?? '-';
            document.getElementById('statFailed').textContent = d.failed_count ?? '-';
            document.getElementById('statRate').textContent = (d.success_rate ?? 0) + '%';
            document.getElementById('statAvgTime').textContent = (d.avg_runtime ?? 0) + 's';
        }

        if (vulnRes.status === 'ok' && vulnRes.data) {
            renderOwaspGrid(vulnRes.data);
        }

        // 加载当前模型配置
        const cfgRes = await apiGet('/api/config');
        if (cfgRes.status === 'ok' && cfgRes.data && cfgRes.data.test) {
            const models = cfgRes.data.test.models || [];
            document.getElementById('statModel').textContent = MODEL_DISPLAY_NAMES[models[0]] || models[0] || 'N/A';
        }
    } catch (e) {
        console.warn('[Dashboard] 加载数据异常:', e.message || e);
    }
}

function renderOwaspGrid(vulns) {
    const typeMap = {};
    vulns.forEach(v => {
        const t = v.type || 'Unknown';
        typeMap[t] = (typeMap[t] || 0) + 1;
    });

    const grid = document.getElementById('owaspGrid');
    const maxCount = Math.max(...Object.values(typeMap), 1);

    grid.innerHTML = Object.entries(typeMap).map(([name, count]) => `
        <div class="owasp-item">
            <div class="owasp-count">${count}</div>
            <div class="owasp-info">
                <div class="owasp-name">${name}</div>
                <div class="owasp-bar">
                    <div class="owasp-bar-fill" style="width:${(count / maxCount * 100).toFixed(0)}%"></div>
                </div>
            </div>
        </div>
    `).join('');
}

// ==================== 漏洞库 ====================
async function loadVulns() {
    const res = await apiGet('/api/vulns');
    if (res.status !== 'ok') return;
    allVulns = res.data;

    // 填充类型筛选器
    const types = [...new Set(allVulns.map(v => v.type))].sort();
    const sel = document.getElementById('vulnTypeFilter');
    if (sel.options.length <= 1) {
        types.forEach(t => {
            const opt = document.createElement('option');
            opt.value = t;
            opt.textContent = t;
            sel.appendChild(opt);
        });
    }

    // 填充攻击页面的漏洞选择器
    const attackSel = document.getElementById('attackVuln');
    if (attackSel.options.length <= 1) {
        allVulns.forEach(v => {
            const opt = document.createElement('option');
            opt.value = v.name;
            opt.textContent = `${v.name} (${v.difficulty})`;
            attackSel.appendChild(opt);
        });
    }

    renderVulns(allVulns);
}

function filterVulns() {
    const search = document.getElementById('vulnSearch').value.toLowerCase();
    const typeF = document.getElementById('vulnTypeFilter').value;
    const diffF = document.getElementById('vulnDiffFilter').value;

    let filtered = allVulns.filter(v => {
        const matchSearch = !search ||
            v.name.toLowerCase().includes(search) ||
            (v.description || '').toLowerCase().includes(search);
        const matchType = !typeF || v.type === typeF;
        const matchDiff = !diffF || v.difficulty === diffF;
        return matchSearch && matchType && matchDiff;
    });

    renderVulns(filtered);
}

function renderVulns(vulns) {
    const grid = document.getElementById('vulnGrid');
    if (vulns.length === 0) {
        grid.innerHTML = '<div class="loading-spinner">未找到匹配的漏洞</div>';
        return;
    }

    grid.innerHTML = vulns.map(v => `
        <div class="vuln-card" onclick="showVulnDetail('${v.name}')">
            <div class="vuln-card-header">
                <div class="vuln-name">${v.name}</div>
                <span class="vuln-difficulty ${v.difficulty.toLowerCase()}">${v.difficulty === 'Simple' ? '简单' : '复杂'}</span>
            </div>
            <div class="vuln-desc">${v.description || '暂无描述'}</div>
            <div class="vuln-footer">
                <span class="vuln-type">${v.type}</span>
                <span class="vuln-action"><i class="ri-arrow-right-s-line"></i> 详情</span>
            </div>
        </div>
    `).join('');
}

function showVulnDetail(name) {
    const v = allVulns.find(x => x.name === name);
    if (!v) return;

    document.getElementById('modalTitle').textContent = v.name;
    document.getElementById('modalBody').innerHTML = `
        <div style="margin-bottom:16px">
            <span class="badge badge-info">${v.type}</span>
            <span class="badge ${v.difficulty === 'Simple' ? 'badge-success' : 'badge-danger'}" style="margin-left:8px">
                ${v.difficulty === 'Simple' ? '简单' : '复杂'}
            </span>
        </div>
        <h4 style="margin-bottom:8px;color:var(--text-primary)">漏洞描述</h4>
        <p style="margin-bottom:16px">${v.description || '暂无描述'}</p>
        <h4 style="margin-bottom:8px;color:var(--text-primary)">攻击目标</h4>
        <p style="margin-bottom:16px;padding:12px;background:var(--bg-input);border-radius:8px;font-family:var(--font-mono);font-size:13px;color:var(--accent-cyan)">${v.target}</p>
        <div style="margin-top:20px">
            <button class="btn btn-primary" onclick="quickAttack('${v.name}')">
                <i class="ri-crosshair-2-line"></i> 直接测试此漏洞
            </button>
        </div>
    `;
    document.getElementById('modalOverlay').classList.add('active');
}

function quickAttack(name) {
    closeModal();
    switchPage('attack');
    document.getElementById('attackVuln').value = name;
}

function closeModal() {
    document.getElementById('modalOverlay').classList.remove('active');
}

// ==================== 渗透测试 ====================
async function startAttack() {
    const name = document.getElementById('attackVuln').value;
    const ip = document.getElementById('attackIP').value;

    if (!name) { showToast('请选择目标漏洞', 'warning', '参数缺失'); return; }
    if (!ip) { showToast('请输入目标IP地址', 'warning', '参数缺失'); return; }

    // 从系统配置中读取当前模型
    const cfgRes = await apiGet('/api/config');
    if (cfgRes.status !== 'ok') {
        showToast('无法读取系统配置，请先在系统设置中配置AI模型', 'error', '配置读取失败');
        return;
    }
    const model = (cfgRes.data.test?.models || [])[0] || '';
    if (!model) {
        showToast('未配置AI模型，请先在系统设置中选择模型', 'warning', '模型未配置');
        switchPage('settings');
        return;
    }

    const btn = document.getElementById('startAttackBtn');
    btn.disabled = true;
    btn.innerHTML = '<i class="ri-loader-4-line ri-spin"></i> 启动中...';

    const badge = document.getElementById('taskBadge');
    badge.className = 'task-badge running';
    badge.textContent = '运行中';

    // 清空日志
    const container = document.getElementById('logContainer');
    container.innerHTML = '';
    logOffset = 0;

    const res = await apiPost('/api/task/start', { name, ip_addr: ip, model });

    if (res.status === 'ok') {
        currentTaskId = res.data.id;
        addLogLine('系统', `任务 ${currentTaskId} 已启动`, 'system');
        addLogLine('系统', `目标: ${name} -> ${ip}`, 'system');
        addLogLine('系统', `模型: ${model}`, 'system');

        // 更新顶栏状态
        document.getElementById('statusDot').style.background = 'var(--accent-blue)';
        document.getElementById('statusText').textContent = '测试中';

        // 开始轮询日志
        startLogPolling();
    } else {
        addLogLine('错误', res.message, 'error');
        btn.disabled = false;
        btn.innerHTML = '<i class="ri-rocket-line"></i> 启动渗透测试';
        badge.className = 'task-badge';
        badge.textContent = '错误';
    }
}

function addLogLine(time, message, type = '') {
    const container = document.getElementById('logContainer');
    const line = document.createElement('div');
    line.className = 'log-line';
    line.innerHTML = `<span class="log-time">[${time}]</span><span class="log-msg ${type}">${escapeHtml(message)}</span>`;
    container.appendChild(line);
    container.scrollTop = container.scrollHeight;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function startLogPolling() {
    if (logPollTimer) clearInterval(logPollTimer);
    logPollTimer = setInterval(pollLogs, 1500);
}

async function pollLogs() {
    if (!currentTaskId) return;

    // 获取日志
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

    // 检查任务状态
    const statusRes = await apiGet('/api/task/status');
    if (statusRes.status === 'ok' && statusRes.data) {
        const task = statusRes.data;
        if (task.status !== 'running') {
            clearInterval(logPollTimer);
            logPollTimer = null;

            const btn = document.getElementById('startAttackBtn');
            btn.disabled = false;
            btn.innerHTML = '<i class="ri-rocket-line"></i> 启动渗透测试';

            const badge = document.getElementById('taskBadge');
            if (task.result === 'success') {
                badge.className = 'task-badge success';
                badge.textContent = '成功';
                addLogLine('系统', '🎉 渗透测试成功！', 'system');
            } else {
                badge.className = 'task-badge failed';
                badge.textContent = '失败';
                addLogLine('系统', '❌ 渗透测试未成功', 'error');
            }

            document.getElementById('statusDot').style.background = 'var(--accent-green)';
            document.getElementById('statusText').textContent = '就绪';
        }
    }
}

// ==================== Docker管理 ====================
async function refreshDocker() {
    const bar = document.getElementById('dockerStatusBar');
    bar.className = 'docker-status-bar';
    bar.innerHTML = '<i class="ri-loader-4-line ri-spin"></i> 正在检查Docker状态...';

    const res = await apiGet('/api/docker/status');
    const tbody = document.getElementById('containerBody');

    if (res.status === 'ok' && res.data.docker_running) {
        bar.className = 'docker-status-bar ok';
        bar.innerHTML = '<i class="ri-checkbox-circle-fill"></i> Docker运行正常';

        const containers = res.data.containers;
        if (containers.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="table-empty">暂无运行中的容器</td></tr>';
        } else {
            tbody.innerHTML = containers.map(c => `
                <tr>
                    <td><code style="color:var(--accent-cyan)">${(c.ID || '').substring(0, 12)}</code></td>
                    <td>${c.Image || ''}</td>
                    <td><span class="badge badge-success">${c.Status || ''}</span></td>
                    <td><code>${c.Ports || ''}</code></td>
                    <td>${c.Names || ''}</td>
                </tr>
            `).join('');
        }
    } else {
        bar.className = 'docker-status-bar error';
        const msg = (res.data && res.data.message) || res.message || 'Docker不可用';
        bar.innerHTML = `<i class="ri-error-warning-fill"></i> ${msg}`;
        tbody.innerHTML = '<tr><td colspan="5" class="table-empty">Docker未运行</td></tr>';
    }
}

async function loadDockerEnvs() {
    const res = await apiGet('/api/docker/envs');
    const grid = document.getElementById('envGrid');

    if (res.status !== 'ok' || !res.data.length) {
        grid.innerHTML = '<div class="loading-spinner">未找到Docker Compose环境</div>';
        return;
    }

    grid.innerHTML = res.data.map(env => `
        <div class="env-item">
            <div class="env-info">
                <div class="env-name">${env.name}</div>
                <div class="env-path">${env.compose_file}</div>
            </div>
            <div class="env-actions">
                <button class="btn btn-sm" style="font-size:12px;padding:6px 14px;background:var(--gradient-green);color:white;border:none;border-radius:6px;cursor:pointer;display:inline-flex;align-items:center;gap:5px;box-shadow:0 2px 8px rgba(16,185,129,0.25);transition:all .2s ease" onmouseover="this.style.transform='translateY(-1px)';this.style.boxShadow='0 4px 12px rgba(16,185,129,0.35)'" onmouseout="this.style.transform='';this.style.boxShadow='0 2px 8px rgba(16,185,129,0.25)'" onclick="startEnv('${env.compose_file.replace(/'/g, "\\'")}')">
                    <i class="ri-play-fill"></i> 启动
                </button>
                <button class="btn btn-sm" style="font-size:12px;padding:6px 14px;background:var(--gradient-red);color:white;border:none;border-radius:6px;cursor:pointer;display:inline-flex;align-items:center;gap:5px;box-shadow:0 2px 8px rgba(239,68,68,0.25);transition:all .2s ease" onmouseover="this.style.transform='translateY(-1px)';this.style.boxShadow='0 4px 12px rgba(239,68,68,0.35)'" onmouseout="this.style.transform='';this.style.boxShadow='0 2px 8px rgba(239,68,68,0.25)'" onclick="stopEnv('${env.compose_file.replace(/'/g, "\\'")}')">
                    <i class="ri-stop-fill"></i> 停止
                </button>
            </div>
        </div>
    `).join('');
}

async function startEnv(composePath) {
    showToast('正在启动靶机环境，镜像拉取可能较慢，请耐心等候...', 'info', '启动中', 10000);
    const res = await apiPost('/api/docker/start', { compose_file: composePath });
    if (res.status === 'ok') {
        showToast(res.message || '环境启动成功', 'success', '靶机已启动');
    } else {
        const errType = res.error_type || '';
        const titleMap = {
            docker_daemon: 'Docker服务不可用',
            sandbox_limit: '沙箱环境限制',
            rate_limit: 'Docker Hub限流',
            timeout: '操作超时',
        };
        const durationMap = {
            sandbox_limit: 12000,
            docker_daemon: 8000,
        };
        showToast(
            res.message || '启动失败',
            'error',
            titleMap[errType] || '启动失败',
            durationMap[errType] || 5000
        );
    }
    refreshDocker();
}

async function stopEnv(composePath) {
    const confirmed = await showConfirm('确定要停止这个靶机环境吗？所有相关容器和卷将被移除。', '停止靶机');
    if (!confirmed) return;
    showToast('正在停止靶机环境...', 'info', '停止中', 6000);
    const res = await apiPost('/api/docker/stop', { compose_file: composePath });
    if (res.status === 'ok') {
        showToast(res.message || '环境已停止', 'success', '靶机已停止');
    } else {
        showToast(res.message || '停止失败', 'error', '操作失败');
    }
    refreshDocker();
}

// ==================== 测试报告 ====================
async function loadResults() {
    const res = await apiGet('/api/results');
    const tbody = document.getElementById('resultBody');

    if (res.status !== 'ok' || !res.data.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="table-empty">暂无测试记录</td></tr>';
        return;
    }

    tbody.innerHTML = res.data.map((r, i) => `
        <tr>
            <td><code style="color:var(--accent-cyan)">${r.source_file || `test_${i}`}</code></td>
            <td>${r.model || 'N/A'}</td>
            <td><span class="badge ${r.flag === 'success' ? 'badge-success' : 'badge-danger'}">${r.flag === 'success' ? '✓ 成功' : '✗ 失败'}</span></td>
            <td>${r.runtime ? r.runtime.toFixed(1) + 's' : 'N/A'}</td>
            <td><button class="btn btn-sm" onclick="showResultDetail(${i})"><i class="ri-eye-line"></i></button></td>
        </tr>
    `).join('');

    // 存储结果供详情查看
    window._results = res.data;
}

function showResultDetail(index) {
    const r = window._results[index];
    if (!r) return;

    document.getElementById('modalTitle').textContent = `测试详情 - ${r.source_file || ''}`;
    let html = `
        <div style="margin-bottom:12px">
            <span class="badge ${r.flag === 'success' ? 'badge-success' : 'badge-danger'}" style="font-size:13px;padding:5px 14px">
                ${r.flag === 'success' ? '✓ 渗透成功' : '✗ 渗透失败'}
            </span>
            <span class="badge badge-info" style="margin-left:8px">${r.model || 'N/A'}</span>
        </div>
        <p style="margin-bottom:12px">耗时: <strong>${r.runtime ? r.runtime.toFixed(1) + 's' : 'N/A'}</strong></p>
    `;

    if (r.commands && r.commands.length) {
        html += `<h4 style="margin:16px 0 8px;color:var(--text-primary)">执行命令</h4>
            <div style="background:var(--bg-input);padding:12px;border-radius:8px;font-family:var(--font-mono);font-size:12px;max-height:200px;overflow-y:auto">
                ${r.commands.map(c => `<div style="padding:2px 0;color:var(--accent-green)">$ ${escapeHtml(String(c))}</div>`).join('')}
            </div>`;
    }

    if (r.history && r.history.length) {
        html += `<h4 style="margin:16px 0 8px;color:var(--text-primary)">执行历史</h4>
            <div style="background:var(--bg-input);padding:12px;border-radius:8px;font-family:var(--font-mono);font-size:11px;max-height:300px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;color:var(--text-secondary)">
                ${r.history.map(h => escapeHtml(String(h))).join('\n---\n')}
            </div>`;
    }

    document.getElementById('modalBody').innerHTML = html;
    document.getElementById('modalOverlay').classList.add('active');
}

async function loadTaskHistory() {
    const res = await apiGet('/api/task/history');
    const container = document.getElementById('taskTimeline');

    if (res.status !== 'ok' || !res.data.length) {
        container.innerHTML = '<div class="timeline-empty">暂无任务记录</div>';
        return;
    }

    container.innerHTML = res.data.reverse().map(t => `
        <div class="timeline-item">
            <div class="timeline-dot ${t.status === 'completed' ? (t.result === 'success' ? 'success' : 'failed') : t.status}"></div>
            <div class="timeline-content">
                <div class="timeline-title">${t.name} → ${t.ip_addr}</div>
                <div class="timeline-meta">
                    <span><i class="ri-robot-line"></i> ${t.model}</span>
                    <span><i class="ri-time-line"></i> ${t.runtime ? t.runtime + 's' : '进行中'}</span>
                    <span><i class="ri-calendar-line"></i> ${t.start_time ? new Date(t.start_time).toLocaleString() : ''}</span>
                </div>
            </div>
        </div>
    `).join('');
}

// ==================== 系统设置 ====================
async function loadConfig() {
    const res = await apiGet('/api/config');
    if (res.status !== 'ok') return;
    const c = res.data;

    document.getElementById('cfgApiBase').value = c.ai?.openai_base || '';
    document.getElementById('cfgApiKey').value = c.ai?.openai_key || '';
    document.getElementById('cfgTemp').value = c.ai?.temperature || 0.5;
    document.getElementById('cfgTempVal').textContent = c.ai?.temperature || 0.5;
    
    // 处理模型选择器回显（支持预设+自定义）
    const currentModel = (c.test?.models || [])[0] || 'gpt4omini';
    const cfgModelSel = document.getElementById('cfgModel');
    const cfgModelCustom = document.getElementById('cfgModelCustom');
    const presetModels = ['gpt35turbo', 'gpt4omini', 'gpt4o', 'gpt4turbo', 'qwen-plus', 'qwen-max', 'glm-4', 'deepseek-chat', 'deepseek-reasoner', 'ernie-4', 'llama31'];
    if (presetModels.includes(currentModel)) {
        cfgModelSel.value = currentModel;
        cfgModelCustom.style.display = 'none';
    } else {
        cfgModelSel.value = '__custom__';
        cfgModelCustom.value = currentModel;
        cfgModelCustom.style.display = 'block';
    }
    
    document.getElementById('cfgSysIter').value = c.psm?.sys_iterations || 15;
    document.getElementById('cfgExpIter').value = c.psm?.exp_iterations || 3;
    document.getElementById('cfgQueryIter').value = c.psm?.query_iterations || 1;
    document.getElementById('cfgScanIter').value = c.psm?.scan_iterations || 1;
    document.getElementById('cfgTimeout').value = c.local?.command_timeout || 120;
}

// ==================== 渗透测试页面模型显示 ====================
const MODEL_DISPLAY_NAMES = {
    gpt35turbo: 'GPT-3.5 Turbo',
    gpt4omini: 'GPT-4o-mini',
    gpt4o: 'GPT-4o',
    gpt4turbo: 'GPT-4-turbo',
    'qwen-plus': '通义千问 Qwen-Plus',
    'qwen-max': '通义千问 Qwen-Max',
    'glm-4': '智谱 GLM-4',
    'deepseek-chat': 'DeepSeek Chat',
    'deepseek-reasoner': 'DeepSeek Reasoner',
    'ernie-4': '文心一言 ERNIE-4',
    llama31: 'Llama 3.1 70B'
};

function onModelSelectChange() {
    // 已废弃 - 渗透测试页面不再有模型选择器
}

function onCfgModelChange() {
    const sel = document.getElementById('cfgModel');
    const custom = document.getElementById('cfgModelCustom');
    custom.style.display = sel.value === '__custom__' ? 'block' : 'none';
}

async function saveConfig() {
    const cfgModelVal = document.getElementById('cfgModel').value;
    const modelName = cfgModelVal === '__custom__'
        ? document.getElementById('cfgModelCustom').value.trim()
        : cfgModelVal;
    
    if (!modelName) {
        showToast('请输入自定义模型名称', 'warning', '参数缺失');
        return;
    }

    // 先读取当前配置，在其基础上合并修改，避免覆盖未展示在页面上的字段
    const currentRes = await apiGet('/api/config');
    const current = currentRes.status === 'ok' ? currentRes.data : {};

    const config = {
        ai: {
            ...(current.ai || {}),
            openai_base: document.getElementById('cfgApiBase').value,
            openai_key: document.getElementById('cfgApiKey').value,
            temperature: parseFloat(document.getElementById('cfgTemp').value)
        },
        test: {
            ...(current.test || {}),
            models: [modelName]
        },
        psm: {
            ...(current.psm || {}),
            sys_iterations: parseInt(document.getElementById('cfgSysIter').value),
            exp_iterations: parseInt(document.getElementById('cfgExpIter').value),
            query_iterations: parseInt(document.getElementById('cfgQueryIter').value),
            scan_iterations: parseInt(document.getElementById('cfgScanIter').value)
        },
        local: {
            ...(current.local || {}),
            command_timeout: parseInt(document.getElementById('cfgTimeout').value)
        },
        web: current.web || { host: '0.0.0.0', port: 5000, debug: false }
    };

    const res = await apiPost('/api/config', config);
    if (res.status === 'ok') {
        showToast('配置已保存成功', 'success', '保存成功');
    } else {
        showToast('保存失败: ' + res.message, 'error', '配置保存失败');
    }
}

async function loadSystemInfo() {
    const res = await apiGet('/api/system/info');
    const container = document.getElementById('sysInfo');

    if (res.status !== 'ok') {
        container.innerHTML = '<div class="loading-spinner">加载失败</div>';
        return;
    }

    const d = res.data;
    container.innerHTML = `
        <div class="sys-info-item">
            <span class="sys-info-label">操作系统</span>
            <span class="sys-info-value">${d.platform}</span>
        </div>
        <div class="sys-info-item">
            <span class="sys-info-label">Python版本</span>
            <span class="sys-info-value">${d.python_version}</span>
        </div>
        <div class="sys-info-item">
            <span class="sys-info-label">系统架构</span>
            <span class="sys-info-value">${d.arch}</span>
        </div>
        <div class="sys-info-item">
            <span class="sys-info-label">Docker</span>
            <span class="sys-info-value">
                <span class="badge ${d.docker_available ? 'badge-success' : 'badge-danger'}">
                    ${d.docker_available ? '✓ 可用' : '✗ 不可用'}
                </span>
            </span>
        </div>
        <div class="sys-info-item">
            <span class="sys-info-label">Docker版本</span>
            <span class="sys-info-value" style="font-size:11px">${d.docker_version || 'N/A'}</span>
        </div>
        <div class="sys-info-item">
            <span class="sys-info-label">xray扫描器</span>
            <span class="sys-info-value">
                <span class="badge ${d.xray_available ? 'badge-success' : 'badge-warning'}">
                    ${d.xray_available ? '✓ 可用' : '⚠ 未找到'}
                </span>
            </span>
        </div>
    `;
}

// ==================== 工具函数 ====================
function togglePassword(id) {
    const input = document.getElementById(id);
    input.type = input.type === 'password' ? 'text' : 'password';
}

// ==================== Toast通知系统 ====================
function initToastContainer() {
    if (!document.getElementById('toastContainer')) {
        const container = document.createElement('div');
        container.id = 'toastContainer';
        container.className = 'toast-container';
        document.body.appendChild(container);
    }
}

/**
 * 显示Toast通知
 * @param {string} message - 消息内容
 * @param {string} type - 类型: success | error | warning | info
 * @param {string} title - 标题（可选）
 * @param {number} duration - 显示时长ms（默认4000）
 */
function showToast(message, type = 'success', title = '', duration = 4000) {
    initToastContainer();
    const container = document.getElementById('toastContainer');

    const icons = {
        success: 'ri-checkbox-circle-fill',
        error: 'ri-error-warning-fill',
        warning: 'ri-alert-fill',
        info: 'ri-information-fill'
    };
    const defaultTitles = {
        success: '操作成功',
        error: '操作失败',
        warning: '警告',
        info: '提示'
    };

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <div class="toast-icon"><i class="${icons[type] || icons.info}"></i></div>
        <div class="toast-content">
            <div class="toast-title">${title || defaultTitles[type] || '提示'}</div>
            <div class="toast-message">${escapeHtml(message)}</div>
        </div>
        <button class="toast-close" onclick="dismissToast(this.parentElement)"><i class="ri-close-line"></i></button>
        <div class="toast-progress" style="animation-duration:${duration}ms"></div>
    `;
    container.appendChild(toast);

    // 自动移除
    setTimeout(() => dismissToast(toast), duration);

    // 限制最多显示5条
    while (container.children.length > 5) {
        dismissToast(container.children[0]);
    }
}

function dismissToast(toast) {
    if (!toast || toast.classList.contains('toast-exit')) return;
    toast.classList.add('toast-exit');
    setTimeout(() => toast.remove(), 300);
}

/**
 * 显示确认对话框（替代原生confirm）
 * @param {string} message - 确认消息
 * @param {string} title - 标题
 * @returns {Promise<boolean>}
 */
function showConfirm(message, title = '确认操作') {
    return new Promise((resolve) => {
        // 移除可能存在的旧对话框
        const old = document.getElementById('confirmOverlay');
        if (old) old.remove();

        const overlay = document.createElement('div');
        overlay.id = 'confirmOverlay';
        overlay.className = 'confirm-overlay active';
        overlay.innerHTML = `
            <div class="confirm-dialog">
                <div class="confirm-header">
                    <div class="confirm-header-icon"><i class="ri-question-line"></i></div>
                    <div class="confirm-header-text">${escapeHtml(title)}</div>
                </div>
                <div class="confirm-body">${escapeHtml(message)}</div>
                <div class="confirm-actions">
                    <button class="confirm-btn confirm-btn-cancel" id="confirmCancel">取消</button>
                    <button class="confirm-btn confirm-btn-ok" id="confirmOk">确认</button>
                </div>
            </div>
        `;
        document.body.appendChild(overlay);

        const cleanup = (result) => {
            overlay.remove();
            resolve(result);
        };

        document.getElementById('confirmOk').onclick = () => cleanup(true);
        document.getElementById('confirmCancel').onclick = () => cleanup(false);
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) cleanup(false);
        });
    });
}

// ==================== 初始化 ====================
document.addEventListener('DOMContentLoaded', () => {
    loadDashboard();
    loadVulns();
});
