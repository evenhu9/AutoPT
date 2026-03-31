"""
AutoPT Web后端 - Flask API
提供RESTful接口，连接前端界面与原始渗透测试引擎
适配原始引擎（commit 23b4706）的接口
"""
import os
import sys
import json
import time
import threading
import subprocess
import platform
import shutil
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

# 确保能导入 AutoPT 模块
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from utils import load_config

app = Flask(__name__, static_folder='frontend', static_url_path='')
CORS(app)

# ==================== 跨平台 Docker 环境检测 ====================
def _setup_docker_env():
    """
    智能设置 DOCKER_HOST 环境变量，兼容 Windows / macOS / Linux。
    Windows: Docker Desktop 默认使用 named pipe，不需要设置 DOCKER_HOST
    Linux/macOS: 优先使用 unix socket
    """
    current_host = os.environ.get('DOCKER_HOST', '')
    system = platform.system()

    if system == 'Windows':
        # Windows 上 Docker Desktop 默认使用 named pipe (npipe)
        # 如果当前设置了 unix socket（不适用于 Windows），清除它
        if 'unix://' in current_host:
            os.environ.pop('DOCKER_HOST', None)
    else:
        # Linux / macOS
        socket_path = '/var/run/docker.sock'
        if os.path.exists(socket_path):
            os.environ['DOCKER_HOST'] = f'unix://{socket_path}'
        elif current_host.startswith('tcp://'):
            pass  # 保持现有 tcp 设置
        else:
            os.environ.pop('DOCKER_HOST', None)

_setup_docker_env()

# ==================== 全局状态 ====================
task_manager = {
    'current_task': None,
    'tasks': [],
    'logs': {},
    'thread': None,       # 当前运行的后台线程
    'stop_event': None,   # 用于通知后台线程中断的 Event
}

CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'src', 'config', 'config.yml')
BENCH_DATA_PATH = os.path.join(os.path.dirname(__file__), 'bench', 'data.jsonl')
RESULT_DIR = os.path.join(os.path.dirname(__file__), 'src', 'result')


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
    return send_from_directory('frontend', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('frontend', path)


# ==================== API 路由 ====================
@app.route('/api/config', methods=['GET'])
def get_config():
    try:
        config = load_config(CONFIG_PATH)
        return jsonify({'status': 'ok', 'data': config})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/config', methods=['POST'])
def update_config():
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
    vulns = load_bench_data()
    return jsonify({'status': 'ok', 'data': vulns, 'total': len(vulns)})

@app.route('/api/results', methods=['GET'])
def get_results():
    results = load_results()
    # 按时间戳降序排列（最新的在前面），没有时间戳的排在最后
    results.sort(key=lambda r: r.get('timestamp', ''), reverse=True)
    return jsonify({'status': 'ok', 'data': results, 'total': len(results)})

@app.route('/api/results/stats', methods=['GET'])
def get_stats():
    results = load_results()
    vulns = load_bench_data()

    total_tests = len(results)
    success_count = sum(1 for r in results if r.get('flag') == 'success')
    failed_count = total_tests - success_count
    avg_runtime = sum(r.get('runtime', 0) for r in results) / total_tests if total_tests > 0 else 0

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


# ==================== Docker 管理 ====================
def _check_docker_daemon():
    """检查 Docker daemon 是否可连接"""
    try:
        result = subprocess.run(
            ['docker', 'info'],
            capture_output=True, encoding='utf-8', timeout=5
        )
        if result.returncode != 0:
            stderr = result.stderr or ''
            if 'Cannot connect' in stderr or 'Is the docker daemon running' in stderr:
                return False, 'Docker守护进程未运行。请先启动Docker服务（Windows: 启动Docker Desktop / Linux: systemctl start docker）'
            return False, f'Docker异常: {stderr[:200]}'
        return True, 'ok'
    except FileNotFoundError:
        return False, 'Docker未安装。请先安装Docker: https://docs.docker.com/get-docker/'
    except subprocess.TimeoutExpired:
        return False, 'Docker响应超时'
    except Exception as e:
        return False, f'Docker检查失败: {str(e)}'


def _get_docker_compose_cmd():
    """获取可用的 docker compose 命令，兼容 V1 和 V2"""
    try:
        result = subprocess.run(
            ['docker', 'compose', 'version'],
            capture_output=True, encoding='utf-8', timeout=5
        )
        if result.returncode == 0:
            return ['docker', 'compose']
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    if shutil.which('docker-compose'):
        return ['docker-compose']

    return ['docker', 'compose']


@app.route('/api/docker/status', methods=['GET'])
def docker_status():
    try:
        result = subprocess.run(
            ['docker', 'ps', '--format', '{{json .}}'],
            capture_output=True, encoding='utf-8', timeout=10
        )
        if result.returncode != 0:
            return jsonify({'status': 'ok', 'data': {'docker_running': False, 'containers': [], 'message': 'Docker未运行'}})

        containers = []
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                try:
                    containers.append(json.loads(line))
                except:
                    pass

        return jsonify({'status': 'ok', 'data': {'docker_running': True, 'containers': containers}})
    except FileNotFoundError:
        return jsonify({'status': 'ok', 'data': {'docker_running': False, 'containers': [], 'message': 'Docker未安装'}})
    except Exception as e:
        return jsonify({'status': 'ok', 'data': {'docker_running': False, 'containers': [], 'message': str(e)}})


@app.route('/api/docker/envs', methods=['GET'])
def list_docker_envs():
    bench_dir = os.path.join(os.path.dirname(__file__), 'bench')
    envs = []

    # 一次性获取运行中的容器（含 Labels 用于精确匹配 compose 项目）
    running_containers = []
    try:
        result = subprocess.run(
            ['docker', 'ps', '--format', '{{json .}}'],
            capture_output=True, encoding='utf-8', timeout=10
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        running_containers.append(json.loads(line))
                    except:
                        pass
    except:
        pass

    for root, dirs, files in os.walk(bench_dir):
        for f in files:
            if f in ('docker-compose.yml', 'docker-compose.yaml'):
                rel_path = os.path.relpath(root, bench_dir)
                compose_file = os.path.join(root, f)
                env_name = rel_path.replace(os.sep, '/')

                # 纯内存匹配，不再调用子进程
                status = _detect_env_status(compose_file, root, running_containers, [])

                envs.append({
                    'path': rel_path,
                    'compose_file': compose_file,
                    'name': env_name,
                    'status': status,
                })

    return jsonify({'status': 'ok', 'data': envs})


def _detect_env_status(compose_file, compose_dir, running_containers, all_containers):
    """
    检测 docker-compose 环境的运行状态（纯内存匹配，无子进程调用）。
    通过 compose 项目名 / compose 目录名匹配已运行的容器。
    返回: 'running' | 'stopped'
    """
    # docker compose 默认项目名 = 目录名（小写，去掉 - 和 _）
    dir_name = os.path.basename(compose_dir).lower()
    project_name = dir_name.replace('-', '').replace('_', '')

    for c in running_containers:
        # 匹配容器名（docker compose 容器名通常含项目名）
        container_name = (c.get('Names', '') or '').lower()
        if project_name and project_name in container_name.replace('-', '').replace('_', ''):
            return 'running'

        # 匹配 Labels 中的 com.docker.compose.project（更精确）
        labels = c.get('Labels', '') or ''
        if f'com.docker.compose.project={dir_name}' in labels:
            return 'running'

    return 'stopped'


def _check_env_exists(compose_cmd, env_dir):
    """检查 docker compose 环境的镜像/容器是否已存在"""
    try:
        # 检查是否有已创建的容器（包括停止的）
        result = subprocess.run(
            compose_cmd + ['ps', '-a', '--format', 'json'],
            capture_output=True, encoding='utf-8', timeout=10,
            cwd=env_dir
        )
        if result.returncode == 0 and result.stdout.strip():
            return True

        # 也检查 docker compose images
        result2 = subprocess.run(
            compose_cmd + ['images', '--format', 'json'],
            capture_output=True, encoding='utf-8', timeout=10,
            cwd=env_dir
        )
        if result2.returncode == 0 and result2.stdout.strip():
            return True
    except:
        pass
    return False


@app.route('/api/docker/start', methods=['POST'])
def start_docker_env():
    data = request.json
    compose_path = data.get('compose_file', '')

    if not compose_path or not os.path.exists(compose_path):
        return jsonify({'status': 'error', 'message': '无效的compose文件路径'})

    daemon_ok, daemon_msg = _check_docker_daemon()
    if not daemon_ok:
        return jsonify({'status': 'error', 'message': daemon_msg, 'error_type': 'docker_daemon'})

    try:
        env_dir = os.path.dirname(compose_path)
        compose_cmd = _get_docker_compose_cmd()

        # 检查环境是否已存在
        env_exists = _check_env_exists(compose_cmd, env_dir)
        action_msg = '环境启动成功' if env_exists else '环境创建并启动成功'

        # docker compose up -d 会自动处理创建和启动
        # 不存在时会自动 pull/build 镜像并创建容器
        # 已存在时会直接启动
        result = subprocess.run(
            compose_cmd + ['up', '-d'],
            capture_output=True, encoding='utf-8', timeout=300,
            cwd=env_dir
        )
        if result.returncode == 0:
            return jsonify({
                'status': 'ok',
                'message': action_msg,
                'output': result.stdout,
                'created': not env_exists
            })
        else:
            error_msg = result.stderr or ''
            if 'Cannot connect' in error_msg:
                error_type = 'docker_daemon'
                error_msg = 'Docker守护进程未运行'
            elif 'unshare' in error_msg.lower() or 'operation not permitted' in error_msg.lower():
                error_type = 'sandbox_limit'
                error_msg = '容器启动权限不足：当前环境可能缺少必要权限。请在有完整Docker权限的机器上运行。'
            else:
                error_type = 'docker_error'
            return jsonify({'status': 'error', 'message': error_msg, 'error_type': error_type})
    except subprocess.TimeoutExpired:
        return jsonify({'status': 'error', 'message': '环境启动超时（300秒）', 'error_type': 'timeout'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e), 'error_type': 'unknown'})


@app.route('/api/docker/stop', methods=['POST'])
def stop_docker_env():
    data = request.json
    compose_path = data.get('compose_file', '')

    if not compose_path or not os.path.exists(compose_path):
        return jsonify({'status': 'error', 'message': '无效的compose文件路径'})

    daemon_ok, daemon_msg = _check_docker_daemon()
    if not daemon_ok:
        return jsonify({'status': 'error', 'message': daemon_msg, 'error_type': 'docker_daemon'})

    try:
        env_dir = os.path.dirname(compose_path)
        compose_cmd = _get_docker_compose_cmd()
        result = subprocess.run(
            compose_cmd + ['stop'],
            capture_output=True, encoding='utf-8', timeout=60,
            cwd=env_dir
        )
        if result.returncode == 0:
            return jsonify({'status': 'ok', 'message': '环境已停止，容器已保留可随时重新启动'})
        else:
            return jsonify({'status': 'error', 'message': result.stderr or '停止失败'})
    except subprocess.TimeoutExpired:
        return jsonify({'status': 'error', 'message': '环境停止超时'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/docker/destroy', methods=['POST'])
def destroy_docker_env():
    """销毁环境：停止容器、移除容器和卷、删除镜像"""
    data = request.json
    compose_path = data.get('compose_file', '')

    if not compose_path or not os.path.exists(compose_path):
        return jsonify({'status': 'error', 'message': '无效的compose文件路径'})

    daemon_ok, daemon_msg = _check_docker_daemon()
    if not daemon_ok:
        return jsonify({'status': 'error', 'message': daemon_msg, 'error_type': 'docker_daemon'})

    try:
        env_dir = os.path.dirname(compose_path)
        compose_cmd = _get_docker_compose_cmd()
        # down -v --rmi all: 停止容器、移除容器、移除卷、删除关联镜像
        result = subprocess.run(
            compose_cmd + ['down', '-v', '--rmi', 'all'],
            capture_output=True, encoding='utf-8', timeout=120,
            cwd=env_dir
        )
        if result.returncode == 0:
            return jsonify({'status': 'ok', 'message': '环境已彻底销毁（容器、卷及镜像已移除）'})
        else:
            return jsonify({'status': 'error', 'message': result.stderr or '销毁失败'})
    except subprocess.TimeoutExpired:
        return jsonify({'status': 'error', 'message': '环境销毁超时'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})
@app.route('/api/task/start', methods=['POST'])
def start_task():
    """启动渗透测试任务 - 直接在进程内调用引擎"""
    data = request.json
    vuln_name = data.get('name', '')
    ip_addr = data.get('ip_addr', '127.0.0.1')
    model = data.get('model', 'gpt4omini')

    if not vuln_name:
        return jsonify({'status': 'error', 'message': '请指定漏洞名称'})

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

    stop_event = threading.Event()
    task_manager['current_task'] = task
    task_manager['tasks'].append(task)
    task_manager['logs'][task_id] = []
    task_manager['stop_event'] = stop_event

    # 在后台线程中运行引擎
    thread = threading.Thread(target=_run_engine_task, args=(task, stop_event), daemon=True)
    thread.start()
    task_manager['thread'] = thread

    return jsonify({'status': 'ok', 'data': task})


def _run_engine_task(task, stop_event):
    """
    后台执行渗透测试任务。
    直接在进程内调用 AutoPT 引擎（原始版本接口）。
    通过 log_callback 实时传递日志到前端。
    stop_event: threading.Event，外部调用 set() 可中断任务。
    """
    task_id = task['id']

    def log_callback(message):
        """日志回调 - 实时传递到前端，同时检查中断信号"""
        if stop_event.is_set():
            raise InterruptedError("任务被用户中断")
        timestamp = datetime.now().strftime('%H:%M:%S')
        task_manager['logs'][task_id].append({
            'time': timestamp,
            'message': message
        })

    try:
        log_callback(f"[系统] 开始任务: {task['name']} -> {task['ip_addr']}")
        log_callback(f"[系统] 使用模型: {task['model']}")

        # 加载配置
        config = load_config(CONFIG_PATH)
        config['test']['models'] = [task['model']]

        # 导入原始引擎模块
        from psm import States
        from autopt import AutoPT

        # 初始化状态机和引擎（与原始 main.py 逻辑一致）
        log_callback("[系统] 初始化引擎...")
        states = States(task['name'], config)
        autopt = AutoPT(
            task['name'], config, task['ip_addr'], states,
            log_callback=log_callback
        )

        # LLM 初始化
        model_name = task['model']
        llm, res_name = autopt.llm_init(config, model_name)

        # 状态机初始化
        autopt_graph = autopt.state_machine_init(llm=llm)

        # 确保结果目录存在
        os.makedirs(os.path.dirname(res_name), exist_ok=True)

        # 执行渗透测试（与原始 main.py 完全一致的流程）
        start_time = time.time()
        try:
            autopt.state_machine_run(
                graph=autopt_graph,
                name=task['name'],
                ip_addr=task['ip_addr']
            )
        except Exception as e:
            if 'string too long' in str(e) or "maximum context" in str(e):
                states.history = [str(e)]
                autopt.flag = 'failed'
                log_callback(f"[错误] 上下文长度超出限制: {str(e)[:200]}")
            else:
                raise e

        runtime = time.time() - start_time
        
        # 安全调用 log (处理空历史记录的情况)
        try:
            result = autopt.log(0, runtime)
        except (IndexError, KeyError):
            result = {'count': 0, 'flag': 'failed', 'runtime': runtime}

        # 保存结果到 jsonl 文件（与原始 main.py 一致）
        import jsonlines
        if not os.path.exists(res_name):
            with open(res_name, 'w') as f:
                pass
        with jsonlines.open(res_name, 'a') as f:
            f.write(result)

        task['status'] = 'completed'
        task['result'] = result.get('flag', 'failed')
        task['end_time'] = datetime.now().isoformat()
        task['runtime'] = round(runtime, 1)

        flag_emoji = '🎉' if result.get('flag') == 'success' else '❌'
        log_callback(f"[系统] {flag_emoji} 任务完成: {result.get('flag', 'unknown')} | 耗时: {runtime:.1f}s")

    except InterruptedError:
        task['status'] = 'stopped'
        task['result'] = 'stopped'
        task['end_time'] = datetime.now().isoformat()
        timestamp = datetime.now().strftime('%H:%M:%S')
        task_manager['logs'][task_id].append({
            'time': timestamp,
            'message': '[系统] ⏹ 任务已被用户中断'
        })
    except Exception as e:
        task['status'] = 'failed'
        task['result'] = 'error'
        task['end_time'] = datetime.now().isoformat()
        # 如果是因为 stop_event 导致的异常，统一标记为 stopped
        if stop_event.is_set():
            task['status'] = 'stopped'
            task['result'] = 'stopped'
            timestamp = datetime.now().strftime('%H:%M:%S')
            task_manager['logs'][task_id].append({
                'time': timestamp,
                'message': '[系统] ⏹ 任务已被用户中断'
            })
        else:
            log_callback(f"[错误] 任务执行失败: {str(e)}")


@app.route('/api/task/status', methods=['GET'])
def get_task_status():
    task = task_manager['current_task']
    if not task:
        return jsonify({'status': 'ok', 'data': None})
    return jsonify({'status': 'ok', 'data': task})


@app.route('/api/task/stop', methods=['POST'])
def stop_task():
    """中断当前正在运行的渗透测试任务"""
    task = task_manager['current_task']
    if not task or task.get('status') != 'running':
        return jsonify({'status': 'error', 'message': '当前没有正在运行的任务'})

    stop_event = task_manager.get('stop_event')
    if stop_event:
        stop_event.set()
        # 等待线程结束（最多5秒）
        thread = task_manager.get('thread')
        if thread and thread.is_alive():
            thread.join(timeout=5)
        # 如果线程仍在运行，强制更新状态
        if task.get('status') == 'running':
            task['status'] = 'stopped'
            task['result'] = 'stopped'
            task['end_time'] = datetime.now().isoformat()
            task_id = task['id']
            timestamp = datetime.now().strftime('%H:%M:%S')
            task_manager['logs'].setdefault(task_id, []).append({
                'time': timestamp,
                'message': '[系统] ⏹ 任务已被用户强制中断'
            })
        return jsonify({'status': 'ok', 'message': '任务已中断'})
    return jsonify({'status': 'error', 'message': '无法中断任务'})


@app.route('/api/task/logs/<task_id>', methods=['GET'])
def get_task_logs(task_id):
    logs = task_manager['logs'].get(task_id, [])
    offset = request.args.get('offset', 0, type=int)
    return jsonify({
        'status': 'ok',
        'data': logs[offset:],
        'total': len(logs),
        'offset': offset
    })


@app.route('/api/task/history', methods=['GET'])
def get_task_history():
    return jsonify({'status': 'ok', 'data': task_manager['tasks']})


@app.route('/api/system/info', methods=['GET'])
def system_info():
    """获取系统信息"""
    # 检查 Docker
    docker_available = False
    docker_version = ''
    try:
        r = subprocess.run(['docker', '--version'], capture_output=True, encoding='utf-8', timeout=5)
        if r.returncode == 0:
            docker_available = True
            docker_version = r.stdout.strip()
    except:
        pass

    # 检查 xray
    xray_available = False
    xray_info = ''
    try:
        from terminal import InteractiveShell
        shell = InteractiveShell(timeout=10, local_mode=True)
        xray_info = 'xray路径: ' + shell.xray_path
        xray_available = os.path.exists(shell.xray_path)
        shell.close()
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


# ==================== 启动入口 ====================
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
    ║   操作系统: {platform.system()} {platform.machine()}
    ╚══════════════════════════════════════════╝
    """)

    app.run(host=host, port=port, debug=debug)
