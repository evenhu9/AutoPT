"""
AutoPT Web后端 - Flask API
提供RESTful接口，连接前端界面与原始渗透测试引擎
适配原始引擎（commit 23b4706）的接口
"""
import os, sys, json, time, threading, subprocess, platform, shutil
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
from utils import load_config

app = Flask(__name__, static_folder='frontend', static_url_path='')
CORS(app)

# ==================== 跨平台 Docker 环境检测 ====================
def _setup_docker_env():
    current_host = os.environ.get('DOCKER_HOST', '')
    if platform.system() == 'Windows':
        if 'unix://' in current_host:
            os.environ.pop('DOCKER_HOST', None)
    else:
        socket_path = '/var/run/docker.sock'
        if os.path.exists(socket_path):
            os.environ['DOCKER_HOST'] = f'unix://{socket_path}'
        elif not current_host.startswith('tcp://'):
            os.environ.pop('DOCKER_HOST', None)

_setup_docker_env()

# ==================== 全局状态 ====================
task_manager = {'current_task': None, 'tasks': [], 'logs': {}, 'thread': None, 'stop_event': None}
CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'src', 'config', 'config.yml')
BENCH_DATA_PATH = os.path.join(os.path.dirname(__file__), 'bench', 'data.jsonl')
RESULT_DIR = os.path.join(os.path.dirname(__file__), 'src', 'result')


def load_bench_data():
    vulns = []
    try:
        import jsonlines
        with jsonlines.open(BENCH_DATA_PATH, 'r') as reader:
            for vul in reader: vulns.append(vul)
    except Exception as e:
        print(f"[WARNING] 加载基准数据失败: {e}")
    return vulns


def load_results():
    results = []
    if not os.path.exists(RESULT_DIR): return results
    for root, dirs, files in os.walk(RESULT_DIR):
        for f in files:
            if not f.endswith('.jsonl'): continue
            filepath = os.path.join(root, f)
            try:
                import jsonlines
                with jsonlines.open(filepath, 'r') as reader:
                    for entry in reader:
                        entry['source_file'] = os.path.relpath(filepath, RESULT_DIR)
                        entry['model'] = os.path.basename(root)
                        fname = os.path.splitext(f)[0]
                        parts = fname.split('_', 1)
                        entry['vuln_name'] = parts[0] + '/' + parts[1] if len(parts) == 2 else fname
                        results.append(entry)
            except: pass
    return results


# ==================== 静态文件服务 ====================
@app.route('/')
def serve_index(): return send_from_directory('frontend', 'index.html')

@app.route('/<path:path>')
def serve_static(path): return send_from_directory('frontend', path)


# ==================== API 路由 ====================
@app.route('/api/config', methods=['GET'])
def get_config():
    try: return jsonify({'status': 'ok', 'data': load_config(CONFIG_PATH)})
    except Exception as e: return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/config', methods=['POST'])
def update_config():
    try:
        import yaml
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            yaml.dump(request.json, f, default_flow_style=False, allow_unicode=True)
        return jsonify({'status': 'ok', 'message': '配置已更新'})
    except Exception as e: return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/vulns', methods=['GET'])
def get_vulns():
    vulns = load_bench_data()
    return jsonify({'status': 'ok', 'data': vulns, 'total': len(vulns)})

@app.route('/api/results', methods=['GET'])
def get_results():
    results = load_results()
    results.sort(key=lambda r: r.get('timestamp', ''), reverse=True)
    return jsonify({'status': 'ok', 'data': results, 'total': len(results)})


def _count_by(items, key_fn, init_fn):
    """通用分组统计辅助函数"""
    result = {}
    for item in items:
        k = key_fn(item)
        if k not in result: result[k] = init_fn()
        yield item, result[k]
    return result


@app.route('/api/results/stats', methods=['GET'])
def get_stats():
    results = load_results()
    vulns = load_bench_data()
    total_tests = len(results)
    success_count = sum(1 for r in results if r.get('flag') == 'success')
    avg_runtime = sum(r.get('runtime', 0) for r in results) / total_tests if total_tests > 0 else 0

    # 构建漏洞信息映射
    vuln_info_map = {v['name']: {'difficulty': v.get('difficulty', 'Unknown'), 'type': v.get('type', 'Unknown')} for v in vulns}
    vuln_diff_map = {v['name'].replace('/', '_'): v.get('difficulty', 'Unknown') for v in vulns}

    # 按类型统计
    type_stats = {}
    for v in vulns:
        t = v.get('type', 'Unknown')
        if t not in type_stats: type_stats[t] = {'total': 0, 'tested': 0, 'success': 0}
        type_stats[t]['total'] += 1
    for r in results:
        source = r.get('source_file', '')
        for v in vulns:
            if v['name'].replace('/', '_') in source:
                ts = type_stats[v.get('type', 'Unknown')]
                ts['tested'] += 1
                if r.get('flag') == 'success': ts['success'] += 1
                break

    # 按难度统计
    difficulty_stats = {d: {'total': 0, 'tested': 0, 'success': 0} for d in ('Simple', 'Complex')}
    for v in vulns:
        d = v.get('difficulty', 'Unknown')
        if d in difficulty_stats: difficulty_stats[d]['total'] += 1

    # 初始化各维度统计容器
    model_stats, model_token_stats = {}, {}
    diff_token = {d: {'total_tokens': 0, 'total_cost': 0.0, 'count': 0} for d in ('Simple', 'Complex')}
    model_tool_stats = {}
    diff_tool = {d: {'total_calls': 0, 'count': 0} for d in ('Simple', 'Complex')}
    total_pt, total_ct, total_tt, total_cost, total_tool_calls = 0, 0, 0, 0.0, 0
    tool_type_counter = {}
    vuln_model_matrix = {}

    # 单次遍历 results 完成所有统计
    for r in results:
        model = r.get('model', 'Unknown')
        flag_ok = r.get('flag') == 'success'
        source = r.get('source_file', '')
        tu = r.get('token_usage', {})
        pt, ct, tt = tu.get('prompt_tokens', 0), tu.get('completion_tokens', 0), tu.get('total_tokens', 0)
        cost = tu.get('estimated_cost', 0)
        cmds = r.get('commands', [])
        n_calls = len(cmds)

        # 查找对应难度
        diff = None
        for vkey, d in vuln_diff_map.items():
            if vkey in source: diff = d; break

        # 难度统计
        if diff in difficulty_stats:
            difficulty_stats[diff]['tested'] += 1
            if flag_ok: difficulty_stats[diff]['success'] += 1

        # 模型统计
        if model not in model_stats: model_stats[model] = {'total': 0, 'success': 0}
        model_stats[model]['total'] += 1
        if flag_ok: model_stats[model]['success'] += 1

        # Token 统计
        total_pt += pt; total_ct += ct; total_tt += tt; total_cost += cost
        if model not in model_token_stats:
            model_token_stats[model] = {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0, 'total_cost': 0.0, 'count': 0}
        mts = model_token_stats[model]
        mts['prompt_tokens'] += pt; mts['completion_tokens'] += ct; mts['total_tokens'] += tt
        mts['total_cost'] += cost; mts['count'] += 1
        if diff in diff_token:
            diff_token[diff]['total_tokens'] += tt; diff_token[diff]['total_cost'] += cost; diff_token[diff]['count'] += 1

        # 工具调用统计
        total_tool_calls += n_calls
        if model not in model_tool_stats: model_tool_stats[model] = {'total_calls': 0, 'count': 0}
        model_tool_stats[model]['total_calls'] += n_calls; model_tool_stats[model]['count'] += 1
        if diff in diff_tool:
            diff_tool[diff]['total_calls'] += n_calls; diff_tool[diff]['count'] += 1

        # 工具类型分类
        tool_prefixes = {'execmd': 'execmd', 'playwright': 'playwright', 'serviceport': 'serviceport', 'readhtml': 'readhtml'}
        tool_keywords = {'nmap': 'nmap', 'xray': 'xray', 'curl': 'curl'}
        for cmd in cmds:
            cmd_lower = str(cmd).strip().lower()
            matched = False
            for prefix, name in tool_prefixes.items():
                if cmd_lower.startswith(prefix + ' ') or cmd_lower.startswith(prefix + ' "') or cmd_lower.startswith(prefix + " '"):
                    tool_type_counter[name] = tool_type_counter.get(name, 0) + 1; matched = True; break
            if not matched:
                for kw, name in tool_keywords.items():
                    if kw in cmd_lower:
                        tool_type_counter[name] = tool_type_counter.get(name, 0) + 1; break

        # 漏洞×模型矩阵
        vn = r.get('vuln_name', '')
        if vn not in vuln_model_matrix: vuln_model_matrix[vn] = {}
        if model not in vuln_model_matrix[vn]: vuln_model_matrix[vn][model] = {'tested': 0, 'success': 0}
        vuln_model_matrix[vn][model]['tested'] += 1
        if flag_ok: vuln_model_matrix[vn][model]['success'] += 1

    # 计算平均值的辅助函数
    def add_avg(stats_dict, total_key, count_key='count', avg_key=None, decimals=None):
        for s in stats_dict.values():
            cnt = s.get(count_key or 'count', 0)
            if avg_key:
                s[avg_key] = round(s[total_key] / cnt, decimals) if cnt > 0 else 0
            if 'total_cost' in s:
                s['total_cost'] = round(s['total_cost'], 6)

    # 模型 token 平均值
    for m in model_token_stats:
        cnt = model_token_stats[m]['count']
        if cnt > 0:
            model_token_stats[m]['avg_tokens'] = round(model_token_stats[m]['total_tokens'] / cnt)
            model_token_stats[m]['avg_cost'] = round(model_token_stats[m]['total_cost'] / cnt, 6)
        model_token_stats[m]['total_cost'] = round(model_token_stats[m]['total_cost'], 6)

    # 难度 token 平均值
    for d in diff_token:
        cnt = diff_token[d]['count']
        diff_token[d]['avg_tokens'] = round(diff_token[d]['total_tokens'] / cnt) if cnt > 0 else 0
        diff_token[d]['avg_cost'] = round(diff_token[d]['total_cost'] / cnt, 6) if cnt > 0 else 0
        diff_token[d]['total_cost'] = round(diff_token[d]['total_cost'], 6)

    # 工具调用平均值
    for m in model_tool_stats:
        cnt = model_tool_stats[m]['count']
        model_tool_stats[m]['avg_calls'] = round(model_tool_stats[m]['total_calls'] / cnt, 1) if cnt > 0 else 0
    for d in diff_tool:
        cnt = diff_tool[d]['count']
        diff_tool[d]['avg_calls'] = round(diff_tool[d]['total_calls'] / cnt, 1) if cnt > 0 else 0

    # 失败原因分类
    failure_reasons_list = ['wrong_command', 'failure_in_tools', 'security_review', 'context_limitation', 'give_up_early']
    reason_keywords = {
        'wrong_command': ['invalid', 'syntax error', 'not found', 'unrecognized', 'unknown command', 'bad request', 'malformed', '格式错误', '无效命令', '命令错误'],
        'failure_in_tools': ['工具失败', '执行失败', 'tool failed', 'tool error', 'timeout', 'connection refused', 'connection reset', '连接失败', '超时', 'timed out', 'error executing', '似乎已经修补', '未成功'],
        'security_review': ['security review', 'blocked', 'forbidden', 'access denied', '安全审查', '拦截', '禁止访问', 'waf', 'firewall', '防火墙', 'rate limit', '频率限制', 'captcha'],
        'context_limitation': ['context limit', 'token limit', 'max tokens', 'context length', '上下文限制', 'truncat', '截断', 'too long', 'exceeded'],
        'give_up_early': ['give up', 'abort', '放弃', '提前终止', '无法继续', 'cannot proceed', 'unable to', '未能', 'failed to exploit', '利用未成功', 'without confirmation', '未找到可利用'],
    }
    valid_cmd_prefixes = ('serviceport', 'readhtml', 'execmd', 'curl', 'nmap', 'xray', 'playwright', 'wget', 'python', 'nikto')

    failure_reason_stats = {}
    for r in results:
        if r.get('flag') == 'success': continue
        model = r.get('model', 'Unknown')
        if model not in failure_reason_stats:
            failure_reason_stats[model] = {'total_failed': 0, 'reasons': {k: 0 for k in failure_reasons_list}}
        failure_reason_stats[model]['total_failed'] += 1

        history_text = ' '.join(str(h) for h in r.get('history', [])).lower()
        commands = r.get('commands', [])
        commands_text = ' '.join(str(c) for c in commands).lower()
        combined = history_text + ' ' + commands_text
        reasons = set()

        for reason, kws in reason_keywords.items():
            if any(kw in (combined if reason != 'wrong_command' else history_text + ' ' + commands_text) for kw in kws):
                reasons.add(reason)
        # 检查无效命令前缀
        for cmd in commands:
            if str(cmd).strip() and not str(cmd).strip().lower().startswith(valid_cmd_prefixes):
                reasons.add('wrong_command'); break
        # 高 token 使用量暗示上下文限制
        if r.get('token_usage', {}).get('total_tokens', 0) > 8000000:
            reasons.add('context_limitation')
        # 默认分类
        if not reasons:
            reasons.add('give_up_early' if len(commands) <= 3 else 'failure_in_tools' if len(commands) > 10 else 'wrong_command')

        for reason in reasons:
            if reason in failure_reason_stats[model]['reasons']:
                failure_reason_stats[model]['reasons'][reason] += 1

    for model in failure_reason_stats:
        total = failure_reason_stats[model]['total_failed']
        failure_reason_stats[model]['reason_rates'] = {
            k: round(failure_reason_stats[model]['reasons'][k] / total * 100, 2) if total > 0 else 0
            for k in failure_reasons_list
        }

    # 漏洞通过率矩阵
    all_models = sorted(set(r.get('model', 'Unknown') for r in results))
    vuln_pass_rate_table = {'Simple': [], 'Complex': []}
    for vuln_name, info in vuln_info_map.items():
        diff = info['difficulty']
        row = {'vuln_name': vuln_name, 'type': info['type'], 'difficulty': diff, 'models': {}}
        for model in all_models:
            se = vuln_model_matrix.get(vuln_name, {}).get(model, {'tested': 0, 'success': 0})
            row['models'][model] = {
                'tested': se['tested'], 'success': se['success'],
                'pass_rate': round(se['success'] / se['tested'] * 100) if se['tested'] > 0 else None
            }
        vuln_pass_rate_table.get(diff, vuln_pass_rate_table.setdefault('Other', [])).append(row) if diff not in vuln_pass_rate_table else vuln_pass_rate_table[diff].append(row)
    for d in vuln_pass_rate_table: vuln_pass_rate_table[d].sort(key=lambda x: x['vuln_name'])

    return jsonify({'status': 'ok', 'data': {
        'total_vulns': len(vulns), 'total_tests': total_tests,
        'success_count': success_count, 'failed_count': total_tests - success_count,
        'success_rate': round(success_count / total_tests * 100, 2) if total_tests > 0 else 0,
        'avg_runtime': round(avg_runtime, 1),
        'type_stats': type_stats, 'difficulty_stats': difficulty_stats, 'model_stats': model_stats,
        'token_stats': {
            'total_prompt_tokens': total_pt, 'total_completion_tokens': total_ct,
            'total_tokens': total_tt, 'total_cost': round(total_cost, 6),
            'avg_tokens_per_test': round(total_tt / total_tests) if total_tests > 0 else 0,
            'avg_cost_per_test': round(total_cost / total_tests, 6) if total_tests > 0 else 0,
            'model_token_stats': model_token_stats, 'difficulty_token_stats': diff_token,
        },
        'tool_call_stats': {
            'total_calls': total_tool_calls,
            'avg_calls_per_test': round(total_tool_calls / total_tests, 1) if total_tests > 0 else 0,
            'model_tool_stats': model_tool_stats, 'difficulty_tool_stats': diff_tool,
            'tool_type_distribution': dict(sorted(tool_type_counter.items(), key=lambda x: x[1], reverse=True)),
        },
        'failure_reason_stats': failure_reason_stats,
        'vuln_pass_rate_table': vuln_pass_rate_table, 'all_models': all_models,
    }})


# ==================== Docker 管理 ====================
def _run_cmd(cmd, timeout=10, cwd=None):
    """统一的命令执行辅助函数"""
    try:
        return subprocess.run(cmd, capture_output=True, encoding='utf-8', timeout=timeout, cwd=cwd)
    except FileNotFoundError: return None
    except subprocess.TimeoutExpired: return None

def _check_docker_daemon():
    r = _run_cmd(['docker', 'info'], timeout=5)
    if r is None: return False, 'Docker未安装或响应超时'
    if r.returncode != 0:
        stderr = r.stderr or ''
        if 'Cannot connect' in stderr or 'Is the docker daemon running' in stderr:
            return False, 'Docker守护进程未运行。请先启动Docker服务'
        return False, f'Docker异常: {stderr[:200]}'
    return True, 'ok'

def _get_docker_compose_cmd():
    r = _run_cmd(['docker', 'compose', 'version'], timeout=5)
    if r and r.returncode == 0: return ['docker', 'compose']
    if shutil.which('docker-compose'): return ['docker-compose']
    return ['docker', 'compose']

def _get_running_containers():
    r = _run_cmd(['docker', 'ps', '--format', '{{json .}}'])
    if not r or r.returncode != 0: return []
    containers = []
    for line in r.stdout.strip().split('\n'):
        if line.strip():
            try: containers.append(json.loads(line))
            except: pass
    return containers


@app.route('/api/docker/status', methods=['GET'])
def docker_status():
    containers = _get_running_containers()
    running = len(containers) > 0 or _run_cmd(['docker', 'ps']) is not None
    r = _run_cmd(['docker', 'ps', '--format', '{{json .}}'])
    if r and r.returncode == 0:
        return jsonify({'status': 'ok', 'data': {'docker_running': True, 'containers': containers}})
    return jsonify({'status': 'ok', 'data': {'docker_running': False, 'containers': [], 'message': 'Docker未运行'}})


@app.route('/api/docker/envs', methods=['GET'])
def list_docker_envs():
    bench_dir = os.path.join(os.path.dirname(__file__), 'bench')
    running_containers = _get_running_containers()
    envs = []
    for root, dirs, files in os.walk(bench_dir):
        for f in files:
            if f not in ('docker-compose.yml', 'docker-compose.yaml'): continue
            rel_path = os.path.relpath(root, bench_dir)
            compose_file = os.path.join(root, f)
            # 检测运行状态
            project_name = os.path.basename(root).lower().replace('-', '').replace('_', '')
            status = 'stopped'
            for c in running_containers:
                cname = (c.get('Names', '') or '').lower().replace('-', '').replace('_', '')
                labels = c.get('Labels', '') or ''
                if (project_name and project_name in cname) or f'com.docker.compose.project={os.path.basename(root).lower()}' in labels:
                    status = 'running'; break
            envs.append({'path': rel_path, 'compose_file': compose_file, 'name': rel_path.replace(os.sep, '/'), 'status': status})
    return jsonify({'status': 'ok', 'data': envs})


def _docker_error_response(stderr, default_msg='操作失败'):
    """从 Docker stderr 提取有意义的错误信息"""
    err_map = {
        ('Cannot connect', 'connection refused'): ('Docker守护进程未运行', 'docker_daemon'),
        ('rate limit', 'toomanyrequests', '429'): ('Docker Hub 拉取限流，请稍后重试', 'rate_limit'),
        ('not found', 'manifest unknown'): ('镜像不存在或已下架', 'image_not_found'),
        ('timeout', 'timed out'): ('操作超时，请检查网络连接', 'network_error'),
        ('no space', 'disk'): ('磁盘空间不足', 'disk_full'),
        ('unshare', 'operation not permitted'): ('容器启动权限不足', 'sandbox_limit'),
        ('port is already allocated', 'address already in use'): ('端口冲突', 'port_conflict'),
    }
    stderr_lower = (stderr or '').lower()
    for keywords, (msg, etype) in err_map.items():
        if any(kw in stderr_lower for kw in keywords):
            return jsonify({'status': 'error', 'message': msg, 'error_type': etype})
    # 提取有效错误行
    lines = [l for l in (stderr or '').split('\n') if l.strip() and not any(x in l.lower() for x in ('pulling', 'download', 'container ', 'network ', 'volume '))]
    clean = '\n'.join(lines[-5:]) if lines else (stderr or '')[-500:]
    return jsonify({'status': 'error', 'message': f'{default_msg}：{clean}', 'error_type': 'docker_error'})


@app.route('/api/docker/start', methods=['POST'])
def start_docker_env():
    compose_path = request.json.get('compose_file', '')
    if not compose_path or not os.path.exists(compose_path):
        return jsonify({'status': 'error', 'message': '无效的compose文件路径'})
    ok, msg = _check_docker_daemon()
    if not ok: return jsonify({'status': 'error', 'message': msg, 'error_type': 'docker_daemon'})

    env_dir = os.path.dirname(compose_path)
    compose_cmd = _get_docker_compose_cmd()
    # 检查环境是否已存在
    env_exists = False
    for check_cmd in [compose_cmd + ['ps', '-a', '--format', 'json'], compose_cmd + ['images', '--format', 'json']]:
        r = _run_cmd(check_cmd, timeout=10, cwd=env_dir)
        if r and r.returncode == 0 and r.stdout.strip(): env_exists = True; break

    try:
        if not env_exists:
            pull = subprocess.run(compose_cmd + ['pull'], capture_output=True, encoding='utf-8', timeout=600, cwd=env_dir)
            if pull.returncode != 0: return _docker_error_response(pull.stderr, '镜像拉取失败')

        timeout_sec = 120 if env_exists else 300
        result = subprocess.run(compose_cmd + ['up', '-d'], capture_output=True, encoding='utf-8', timeout=timeout_sec, cwd=env_dir)
        if result.returncode == 0:
            return jsonify({'status': 'ok', 'message': '环境启动成功' if env_exists else '环境创建并启动成功', 'output': result.stdout, 'created': not env_exists})
        return _docker_error_response(result.stderr, '启动失败')
    except subprocess.TimeoutExpired:
        return jsonify({'status': 'error', 'message': '操作超时，请检查网络连接后重试', 'error_type': 'timeout'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e), 'error_type': 'unknown'})


@app.route('/api/docker/stop', methods=['POST'])
def stop_docker_env():
    return _docker_compose_action('stop', '环境已停止，容器已保留可随时重新启动', timeout=60)

@app.route('/api/docker/destroy', methods=['POST'])
def destroy_docker_env():
    return _docker_compose_action(['down', '-v', '--rmi', 'all'], '环境已彻底销毁（容器、卷及镜像已移除）', timeout=120)

def _docker_compose_action(action, success_msg, timeout=60):
    compose_path = request.json.get('compose_file', '')
    if not compose_path or not os.path.exists(compose_path):
        return jsonify({'status': 'error', 'message': '无效的compose文件路径'})
    ok, msg = _check_docker_daemon()
    if not ok: return jsonify({'status': 'error', 'message': msg, 'error_type': 'docker_daemon'})
    try:
        env_dir = os.path.dirname(compose_path)
        cmd = _get_docker_compose_cmd() + (action if isinstance(action, list) else [action])
        r = subprocess.run(cmd, capture_output=True, encoding='utf-8', timeout=timeout, cwd=env_dir)
        if r.returncode == 0: return jsonify({'status': 'ok', 'message': success_msg})
        return jsonify({'status': 'error', 'message': r.stderr or '操作失败'})
    except subprocess.TimeoutExpired:
        return jsonify({'status': 'error', 'message': '操作超时'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


# ==================== 任务管理 ====================
@app.route('/api/task/start', methods=['POST'])
def start_task():
    data = request.json
    vuln_name, ip_addr, model = data.get('name', ''), data.get('ip_addr', '127.0.0.1'), data.get('model', 'gpt4omini')
    if not vuln_name: return jsonify({'status': 'error', 'message': '请指定漏洞名称'})
    if task_manager['current_task'] and task_manager['current_task'].get('status') == 'running':
        return jsonify({'status': 'error', 'message': '已有任务正在运行'})

    task_id = f"task_{int(time.time())}"
    task = {'id': task_id, 'name': vuln_name, 'ip_addr': ip_addr, 'model': model,
            'status': 'running', 'start_time': datetime.now().isoformat(), 'end_time': None, 'result': None}
    stop_event = threading.Event()
    task_manager.update({'current_task': task, 'stop_event': stop_event})
    task_manager['tasks'].append(task)
    task_manager['logs'][task_id] = []
    thread = threading.Thread(target=_run_engine_task, args=(task, stop_event), daemon=True)
    thread.start()
    task_manager['thread'] = thread
    return jsonify({'status': 'ok', 'data': task})


def _run_engine_task(task, stop_event):
    task_id = task['id']

    def log_cb(message):
        if stop_event.is_set(): raise InterruptedError("任务被用户中断")
        task_manager['logs'][task_id].append({'time': datetime.now().strftime('%H:%M:%S'), 'message': message})

    try:
        log_cb(f"[系统] 开始任务: {task['name']} -> {task['ip_addr']}")
        log_cb(f"[系统] 使用模型: {task['model']}")
        config = load_config(CONFIG_PATH)
        config['test']['models'] = [task['model']]

        from psm import States
        from autopt import AutoPT
        log_cb("[系统] 初始化引擎...")
        states = States(task['name'], config)
        autopt = AutoPT(task['name'], config, task['ip_addr'], states, log_callback=log_cb)
        llm, res_name = autopt.llm_init(config, task['model'])
        autopt_graph = autopt.state_machine_init(llm=llm)
        os.makedirs(os.path.dirname(res_name), exist_ok=True)

        start_time = time.time()
        try:
            autopt.state_machine_run(graph=autopt_graph, name=task['name'], ip_addr=task['ip_addr'])
        except Exception as e:
            if 'string too long' in str(e) or "maximum context" in str(e):
                states.history = [str(e)]; autopt.flag = 'failed'
                log_cb(f"[错误] 上下文长度超出限制: {str(e)[:200]}")
            else: raise

        runtime = time.time() - start_time
        try: result = autopt.log(0, runtime)
        except (IndexError, KeyError): result = {'count': 0, 'flag': 'failed', 'runtime': runtime}

        import jsonlines
        if not os.path.exists(res_name):
            with open(res_name, 'w') as f: pass
        with jsonlines.open(res_name, 'a') as f: f.write(result)

        task.update({'status': 'completed', 'result': result.get('flag', 'failed'),
                     'end_time': datetime.now().isoformat(), 'runtime': round(runtime, 1)})
        flag_emoji = '🎉' if result.get('flag') == 'success' else '❌'
        log_cb(f"[系统] {flag_emoji} 任务完成: {result.get('flag', 'unknown')} | 耗时: {runtime:.1f}s")

    except InterruptedError:
        task.update({'status': 'stopped', 'result': 'stopped', 'end_time': datetime.now().isoformat()})
        task_manager['logs'][task_id].append({'time': datetime.now().strftime('%H:%M:%S'), 'message': '[系统] ⏹ 任务已被用户中断'})
    except Exception as e:
        if stop_event.is_set():
            task.update({'status': 'stopped', 'result': 'stopped', 'end_time': datetime.now().isoformat()})
            task_manager['logs'][task_id].append({'time': datetime.now().strftime('%H:%M:%S'), 'message': '[系统] ⏹ 任务已被用户中断'})
        else:
            task.update({'status': 'failed', 'result': 'error', 'end_time': datetime.now().isoformat()})
            log_cb(f"[错误] 任务执行失败: {str(e)}")


@app.route('/api/task/status', methods=['GET'])
def get_task_status():
    return jsonify({'status': 'ok', 'data': task_manager['current_task']})

@app.route('/api/task/stop', methods=['POST'])
def stop_task():
    task = task_manager['current_task']
    if not task or task.get('status') != 'running':
        return jsonify({'status': 'error', 'message': '当前没有正在运行的任务'})
    stop_event = task_manager.get('stop_event')
    if not stop_event: return jsonify({'status': 'error', 'message': '无法中断任务'})
    stop_event.set()
    thread = task_manager.get('thread')
    if thread and thread.is_alive(): thread.join(timeout=5)
    if task.get('status') == 'running':
        task.update({'status': 'stopped', 'result': 'stopped', 'end_time': datetime.now().isoformat()})
        task_manager['logs'].setdefault(task['id'], []).append(
            {'time': datetime.now().strftime('%H:%M:%S'), 'message': '[系统] ⏹ 任务已被用户强制中断'})
    return jsonify({'status': 'ok', 'message': '任务已中断'})

@app.route('/api/task/logs/<task_id>', methods=['GET'])
def get_task_logs(task_id):
    logs = task_manager['logs'].get(task_id, [])
    offset = request.args.get('offset', 0, type=int)
    return jsonify({'status': 'ok', 'data': logs[offset:], 'total': len(logs), 'offset': offset})

@app.route('/api/task/history', methods=['GET'])
def get_task_history():
    return jsonify({'status': 'ok', 'data': task_manager['tasks']})

@app.route('/api/system/info', methods=['GET'])
def system_info():
    docker_available, docker_version = False, ''
    r = _run_cmd(['docker', '--version'], timeout=5)
    if r and r.returncode == 0: docker_available = True; docker_version = r.stdout.strip()

    xray_available, xray_info = False, ''
    try:
        from terminal import InteractiveShell
        shell = InteractiveShell(timeout=10, local_mode=True)
        xray_info = 'xray路径: ' + shell.xray_path
        xray_available = os.path.exists(shell.xray_path)
        shell.close()
    except: pass

    return jsonify({'status': 'ok', 'data': {
        'platform': platform.platform(), 'python_version': platform.python_version(),
        'docker_available': docker_available, 'docker_version': docker_version,
        'xray_available': xray_available, 'xray_info': xray_info, 'arch': platform.machine(),
    }})


# ==================== 启动入口 ====================
if __name__ == '__main__':
    config = load_config(CONFIG_PATH)
    web_config = config.get('web', {})
    host, port, debug = web_config.get('host', '0.0.0.0'), web_config.get('port', 5000), web_config.get('debug', False)
    print(f"\n    ╔══════════════════════════════════════════╗\n    ║           AutoPT Web Console             ║\n    ║   基于LLM的自动化渗透测试平台            ║\n    ╠══════════════════════════════════════════╣\n    ║   访问地址: http://{host}:{port}\n    ║   操作系统: {platform.system()} {platform.machine()}\n    ╚══════════════════════════════════════════╝\n")
    app.run(host=host, port=port, debug=debug)
