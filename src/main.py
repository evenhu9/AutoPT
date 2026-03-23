"""
AutoPT 本地调试入口
用于在命令行中直接运行渗透测试引擎，方便本地开发调试。

使用方法：
  cd src
  python main.py --name "elasticsearch/CVE-2015-1427" --ip_addr "127.0.0.1"
"""
import argparse
import os
import sys
import time
import jsonlines

from utils import load_config, print_AutoRT
from psm import States
from autopt import AutoPT


def argument_parser():
    parser = argparse.ArgumentParser(
        description='AutoPT - 基于LLM的自动化渗透测试工具（本地调试模式）'
    )
    parser.add_argument(
        '--name',
        type=str,
        required=True,
        help='漏洞名称，如 elasticsearch/CVE-2015-1427'
    )
    parser.add_argument(
        '--ip_addr',
        type=str,
        required=True,
        help='目标机器的IP地址'
    )
    parser.add_argument(
        '--model',
        type=str,
        default=None,
        help='指定模型名称，默认使用配置文件中的模型列表'
    )
    parser.add_argument(
        '--config',
        type=str,
        default='config/config.yml',
        help='配置文件路径（默认: config/config.yml）'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='启用详细日志输出'
    )
    args = parser.parse_args()
    return args


def log_callback(message):
    """本地调试日志回调 - 直接打印到控制台"""
    from datetime import datetime
    timestamp = datetime.now().strftime('%H:%M:%S')
    print(f"[{timestamp}] {message}")


def main():
    print_AutoRT()
    args = argument_parser()
    pname = str(args.name)
    ip_addr = str(args.ip_addr)
    config_file_path = args.config
    config = load_config(config_file_path)

    # 如果指定了模型，覆盖配置文件中的模型列表
    if args.model:
        config['test']['models'] = [args.model]

    models = config['test']['models']
    states = States(pname, config)
    autopt = AutoPT(pname, config, ip_addr, states, log_callback=log_callback)

    for model_name in models:
        print(f"\n{'='*60}")
        print(f"  模型: {model_name} | 漏洞: {pname} | 目标: {ip_addr}")
        print(f"{'='*60}\n")

        llm, res_name = autopt.llm_init(config, model_name)
        autort_graph = autopt.state_machine_init(llm=llm)

        # 确保结果输出目录存在
        os.makedirs(os.path.dirname(res_name), exist_ok=True)
        if not os.path.exists(res_name):
            with open(res_name, 'w') as f:
                pass

        with jsonlines.open(res_name, 'a') as f:
            start_time = time.time()
            try:
                autopt.state_machine_run(
                    graph=autort_graph,
                    name=pname,
                    ip_addr=ip_addr
                )
            except Exception as e:
                if 'string too long' in str(e) or "maximum context" in str(e):
                    states.history = [str(e)]
                    autopt.flag = 'failed'
                    print(f"\n[错误] 上下文长度超出限制: {str(e)[:200]}")
                else:
                    raise e

            runtime = time.time() - start_time

            try:
                log_entry = autopt.log(0, runtime)
            except (IndexError, KeyError):
                log_entry = {'count': 0, 'flag': 'failed', 'runtime': runtime}

            f.write(log_entry)

            # 输出结果摘要
            flag = log_entry.get('flag', 'unknown')
            flag_emoji = '✅' if flag == 'success' else '❌'
            print(f"\n{'='*60}")
            print(f"  {flag_emoji} 结果: {flag} | 耗时: {runtime:.1f}s")
            print(f"  结果已保存至: {res_name}")
            print(f"{'='*60}\n")

            states.refresh()


if __name__ == '__main__':
    main()
