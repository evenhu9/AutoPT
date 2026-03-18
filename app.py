"""
AutoPT Web后端 - Flask API
提供RESTful接口，连接前端界面与渗透测试引擎
"""
import os
import sys
import json
import time
import threading
import subprocess
import glob
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

# 确保能导入AutoPT模块
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'AutoPT'))

from AutoPT.utils import load_config

app = Flask(__name__, static_folder='frontend', static_url_path='')
CORS(app)

# 修复Docker连接: 强制使用unix socket而非tcp
# 沙箱环境中DOCKER_HOST可能被设置为tcp://localhost:2375但daemon监听在socket
os.environ['DOCKER_HOST'] = 'unix:///var/run/docker.sock'

# 全局状态
task_manager = {
    'current_task': None,
    'tasks': [],
    'logs': {},
}

CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'AutoPT', 'config', 'config.yml')
BENCH_DATA_PATH = os.path.join(os.path.dirname(__file__), 'bench', 'data.jsonl')
RESULT_DIR = os.path.join(os.path.dirname(__file__), 'AutoPT', 'result')


def load_bench_data():
    """加载基准测试数据集"""
    vulns = []
    try:
        import jsonlines
        with jsonlines.open(BENCH_DATA_PATH, 'r') as reader:
            for vul in reader:
                vulns.append(vul)
    except Exception as e:
        print(f"[WARNING] 加载基准数据失败: {e}")
    return vulns


def load_results():
    """加载历史测试结果"""
    results = []
    if not os.path.exists(RESULT_DIR):
        return results
    for root, dirs, files in os.walk(RESULT_DIR):
        for f in files:
            if f.endswith('.jsonl'):
                filepath = os.path.join(root, f)
                try:
                    import jsonlines
                    with jsonlines.open(filepath, 'r') as reader:
                        for entry in reader:
                            entry['source_file'] = os.path.relpath(filepath, RESULT_DIR)
                            entry['model'] = os.path.basename(root)
                            results.append(entry)
                except:
                    pass
    return results


# ==================== 静态文件服务 ====================

@app.route('/')
def serve_index():
    """服务前端主页"""
    return send_from_directory('frontend', 'index.html')


@app.route('/<path:path>')
def serve_static(path):
    """服务静态文件"""
    return send_from_directory('frontend', path)


# ==================== API 路由 ====================

@app.route('/api/config', methods=['GET'])
def get_config():
    """获取当前配置"""
    try:
        config = load_config(CONFIG_PATH)
        return jsonify({'status': 'ok', 'data': config})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/config', methods=['POST'])
def update_config():
    """更新配置"""
    try:
        import yaml
        data = request.json
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True)
        return jsonify({'status': 'ok', 'message': '配置已更新'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/vulns', methods=['GET'])
def get_vulns():
    """获取漏洞列表"""
    vulns = load_bench_data()
    return jsonify({'status': 'ok', 'data': vulns, 'total': len(vulns)})


@app.route('/api/results', methods=['GET'])
def get_results():
    """获取测试结果"""
    results = load_results()
    return jsonify({'status': 'ok', 'data': results, 'total': len(results)})


@app.route('/api/results/stats', methods=['GET'])
def get_stats():
    """获取统计信息"""
    results = load_results()
    vulns = load_bench_data()
    
    total_tests = len(results)
    success_count = sum(1 for r in results if r.get('flag') == 'success')
    failed_count = total_tests - success_count
    avg_runtime = sum(r.get('runtime', 0) for r in results) / total_tests if total_tests > 0 else 0
    
    # 按漏洞类型统计
    type_stats = {}
    for v in vulns:
        vtype = v.get('type', 'Unknown')
        if vtype not in type_stats:
            type_stats[vtype] = {'total': 0, 'tested': 0, 'success': 0}
        type_stats[vtype]['total'] += 1
    
    for r in results:
        source = r.get('source_file', '')
        for v in vulns:
            if v['name'].replace('/', '_') in source:
                vtype = v.get('type', 'Unknown')
                type_stats[vtype]['tested'] += 1
                if r.get('flag') == 'success':
                    type_stats[vtype]['success'] += 1
                break
    
    # 按难度统计
    difficulty_stats = {'Simple': {'total': 0, 'success': 0}, 'Complex': {'total': 0, 'success': 0}}
    for v in vulns:
        diff = v.get('difficulty', 'Unknown')
        if diff in difficulty_stats:
            difficulty_stats[diff]['total'] += 1
    
    return jsonify({
        'status': 'ok',
        'data': {
            'total_vulns': len(vulns),
            'total_tests': total_tests,
            'success_count': success_count,
            'failed_count': failed_count,
            'success_rate': round(success_count / total_tests * 100, 1) if total_tests > 0 else 0,
            'avg_runtime': round(avg_runtime, 1),
            'type_stats': type_stats,
            'difficulty_stats': difficulty_stats,
        }
    })


@app.route('/api/docker/status', methods=['GET'])
def docker_status():
    """检查Docker状态和运行中的容器"""
    try:
        # 检查Docker是否可用
        result = subprocess.run(
            ['docker', 'ps', '--format', '{{json .}}'],
            capture_output=True, encoding='utf-8', timeout=10
        )
        if result.returncode != 0:
            return jsonify({'status': 'error', 'message': 'Docker未运行或未安装', 'containers': []})
        
        containers = []
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                try:
                    containers.append(json.loads(line))
                except:
                    pass
        
        return jsonify({'status': 'ok', 'data': {'docker_running': True, 'containers': containers}})
    except FileNotFoundError:
        return jsonify({'status': 'error', 'message': 'Docker未安装', 'data': {'docker_running': False, 'containers': []}})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e), 'data': {'docker_running': False, 'containers': []}})


@app.route('/api/docker/envs', methods=['GET'])
def list_docker_envs():
    """列出可用的漏洞环境（bench目录下有docker-compose的目录）"""
    bench_dir = os.path.join(os.path.dirname(__file__), 'bench')
    envs = []
    
    for root, dirs, files in os.walk(bench_dir):
        for f in files:
            if f in ('docker-compose.yml', 'docker-compose.yaml'):
                rel_path = os.path.relpath(root, bench_dir)
                # 检查是否正在运行
                envs.append({
                    'path': rel_path,
                    'compose_file': os.path.join(root, f),
                    'name': rel_path.replace(os.sep, '/'),
                })
    
    return jsonify({'status': 'ok', 'data': envs})


def _check_docker_daemon():
    """检查Docker daemon是否可连接"""
    try:
        result = subprocess.run(
            ['docker', 'info'],
            capture_output=True, encoding='utf-8', timeout=5
        )
        if result.returncode != 0:
            stderr = result.stderr or ''
            if 'Cannot connect' in stderr or 'Is the docker daemon running' in stderr:
                return False, 'Docker守护进程未运行。请先启动Docker服务（执行 systemctl start docker 或 启动Docker Desktop）'
            return False, f'Docker异常: {stderr[:200]}'
        return True, 'ok'
    except FileNotFoundError:
        return False, 'Docker未安装。请先安装Docker: https://docs.docker.com/get-docker/'
    except subprocess.TimeoutExpired:
        return False, 'Docker响应超时，守护进程可能未正常运行'
    except Exception as e:
        return False, f'Docker检查失败: {str(e)}'


@app.route('/api/docker/start', methods=['POST'])
def start_docker_env():
    """启动Docker漏洞环境"""
    data = request.json
    compose_path = data.get('compose_file', '')
    
    if not compose_path or not os.path.exists(compose_path):
        return jsonify({'status': 'error', 'message': '无效的compose文件路径'})
    
    # 先检查Docker daemon
    daemon_ok, daemon_msg = _check_docker_daemon()
    if not daemon_ok:
        return jsonify({'status': 'error', 'message': daemon_msg, 'error_type': 'docker_daemon'})
    
    try:
        env_dir = os.path.dirname(compose_path)
        result = subprocess.run(
            ['docker', 'compose', 'up', '-d'],
            capture_output=True, encoding='utf-8', timeout=300,
            cwd=env_dir
        )
        if result.returncode == 0:
            return jsonify({'status': 'ok', 'message': '环境启动成功', 'output': result.stdout})
        else:
            error_msg = result.stderr or ''
            if 'Cannot connect' in error_msg:
                error_msg = 'Docker守护进程未运行。请先启动Docker服务'
                error_type = 'docker_daemon'
            elif 'unshare' in error_msg.lower() or 'operation not permitted' in error_msg.lower():
                error_msg = '容器启动权限不足：当前环境缺少mount namespace权限（CAP_SYS_ADMIN），这是云端沙箱的安全限制。请在您本地有完整Docker权限的机器上运行此项目。'
                error_type = 'sandbox_limit'
            elif 'toomanyrequests' in error_msg.lower() or 'rate limit' in error_msg.lower():
                error_msg = 'Docker Hub拉取限流，请稍后重试或配置镜像加速器'
                error_type = 'rate_limit'
            else:
                error_type = 'docker_error'
            return jsonify({'status': 'error', 'message': error_msg, 'error_type': error_type})
    except subprocess.TimeoutExpired:
        return jsonify({'status': 'error', 'message': '环境启动超时（300秒），可能是镜像拉取较慢，请检查网络连接', 'error_type': 'timeout'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e), 'error_type': 'unknown'})


@app.route('/api/docker/stop', methods=['POST'])
def stop_docker_env():
    """停止Docker漏洞环境"""
    data = request.json
    compose_path = data.get('compose_file', '')
    
    if not compose_path or not os.path.exists(compose_path):
        return jsonify({'status': 'error', 'message': '无效的compose文件路径'})
    
    # 先检查Docker daemon
    daemon_ok, daemon_msg = _check_docker_daemon()
    if not daemon_ok:
        return jsonify({'status': 'error', 'message': daemon_msg, 'error_type': 'docker_daemon'})
    
    try:
        env_dir = os.path.dirname(compose_path)
        result = subprocess.run(
            ['docker', 'compose', 'down', '-v'],
            capture_output=True, encoding='utf-8', timeout=60,
            cwd=env_dir
        )
        if result.returncode == 0:
            return jsonify({'status': 'ok', 'message': '环境已停止'})
        else:
            error_msg = result.stderr or '停止失败'
            if 'Cannot connect' in error_msg:
                error_msg = 'Docker守护进程未运行。请先启动Docker服务'
            return jsonify({'status': 'error', 'message': error_msg})
    except subprocess.TimeoutExpired:
        return jsonify({'status': 'error', 'message': '环境停止超时（60秒）'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/task/start', methods=['POST'])
def start_task():
    """启动渗透测试任务"""
    data = request.json
    vuln_name = data.get('name', '')
    ip_addr = data.get('ip_addr', '127.0.0.1')
    model = data.get('model', 'gpt4omini')
    
    if not vuln_name:
        return jsonify({'status': 'error', 'message': '请指定漏洞名称'})
    
    # 检查是否有正在运行的任务
    if task_manager['current_task'] and task_manager['current_task'].get('status') == 'running':
        return jsonify({'status': 'error', 'message': '已有任务正在运行'})
    
    task_id = f"task_{int(time.time())}"
    task = {
        'id': task_id,
        'name': vuln_name,
        'ip_addr': ip_addr,
        'model': model,
        'status': 'running',
        'start_time': datetime.now().isoformat(),
        'end_time': None,
        'result': None,
    }
    
    task_manager['current_task'] = task
    task_manager['tasks'].append(task)
    task_manager['logs'][task_id] = []
    
    # 在后台线程中运行
    thread = threading.Thread(target=_run_task, args=(task,), daemon=True)
    thread.start()
    
    return jsonify({'status': 'ok', 'data': task})


def _run_task(task):
    """后台执行渗透测试任务"""
    task_id = task['id']
    
    def log_callback(message):
        timestamp = datetime.now().strftime('%H:%M:%S')
        task_manager['logs'][task_id].append({
            'time': timestamp,
            'message': message
        })
    
    try:
        log_callback(f"[系统] 开始任务: {task['name']} -> {task['ip_addr']}")
        log_callback(f"[系统] 使用模型: {task['model']}")
        
        config = load_config(CONFIG_PATH)
        config['test']['models'] = [task['model']]
        
        from AutoPT.psm import States
        from AutoPT.autopt import AutoPT
        
        states = States(task['name'], config)
        autopt = AutoPT(task['name'], config, task['ip_addr'], states, log_callback=log_callback)
        
        model_name = task['model']
        llm, res_name = autopt.llm_init(config, model_name)
        autopt_graph = autopt.state_machine_init(llm=llm)
        
        os.makedirs(os.path.dirname(res_name), exist_ok=True)
        
        start_time = time.time()
        try:
            autopt.state_machine_run(graph=autopt_graph, name=task['name'], ip_addr=task['ip_addr'])
        except Exception as e:
            if 'string too long' in str(e) or "maximum context" in str(e):
                states.history = [str(e)]
                autopt.flag = 'failed'
                log_callback(f"[错误] 上下文长度超出限制: {str(e)[:200]}")
            else:
                raise e
        
        runtime = time.time() - start_time
        result = autopt.log(0, runtime)
        
        # 保存结果
        import jsonlines
        if not os.path.exists(res_name):
            with open(res_name, 'w') as f:
                pass
        with jsonlines.open(res_name, 'a') as f:
            f.write(result)
        
        task['status'] = 'completed'
        task['result'] = result['flag']
        task['end_time'] = datetime.now().isoformat()
        task['runtime'] = round(runtime, 1)
        
        log_callback(f"[系统] 任务完成: {result['flag']} | 耗时: {runtime:.1f}s")
        
    except Exception as e:
        task['status'] = 'failed'
        task['result'] = 'error'
        task['end_time'] = datetime.now().isoformat()
        log_callback(f"[错误] 任务执行失败: {str(e)}")


@app.route('/api/task/status', methods=['GET'])
def get_task_status():
    """获取当前任务状态"""
    task = task_manager['current_task']
    if not task:
        return jsonify({'status': 'ok', 'data': None})
    return jsonify({'status': 'ok', 'data': task})


@app.route('/api/task/logs/<task_id>', methods=['GET'])
def get_task_logs(task_id):
    """获取任务日志"""
    logs = task_manager['logs'].get(task_id, [])
    # 支持增量获取
    offset = request.args.get('offset', 0, type=int)
    return jsonify({
        'status': 'ok',
        'data': logs[offset:],
        'total': len(logs),
        'offset': offset
    })


@app.route('/api/task/history', methods=['GET'])
def get_task_history():
    """获取任务历史"""
    return jsonify({'status': 'ok', 'data': task_manager['tasks']})


@app.route('/api/system/info', methods=['GET'])
def system_info():
    """获取系统信息"""
    import platform
    
    # 检查Docker
    docker_available = False
    docker_version = ''
    try:
        r = subprocess.run(['docker', '--version'], capture_output=True, encoding='utf-8', timeout=5)
        if r.returncode == 0:
            docker_available = True
            docker_version = r.stdout.strip()
    except:
        pass
    
    # 检查xray
    xray_available = False
    xray_info = ''
    from AutoPT.terminal import InteractiveShell
    try:
        shell = InteractiveShell(timeout=10)
        xray_info = 'xray路径: ' + shell.xray_path
        xray_available = os.path.exists(shell.xray_path)
    except:
        pass
    
    return jsonify({
        'status': 'ok',
        'data': {
            'platform': platform.platform(),
            'python_version': platform.python_version(),
            'docker_available': docker_available,
            'docker_version': docker_version,
            'xray_available': xray_available,
            'xray_info': xray_info,
            'arch': platform.machine(),
        }
    })


if __name__ == '__main__':
    config = load_config(CONFIG_PATH)
    web_config = config.get('web', {})
    host = web_config.get('host', '0.0.0.0')
    port = web_config.get('port', 5000)
    debug = web_config.get('debug', False)
    
    print(f"""
    ╔══════════════════════════════════════════╗
    ║           AutoPT Web Console             ║
    ║   基于LLM的自动化渗透测试平台            ║
    ╠══════════════════════════════════════════╣
    ║   访问地址: http://{host}:{port}          
    ╚══════════════════════════════════════════╝
    """)
    
    app.run(host=host, port=port, debug=debug)
