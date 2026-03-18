"""
本地交互式Shell - 去掉SSH依赖，直接在本地执行命令
适用于 Windows 攻击机 + 本地 Docker 靶机的架构
"""
import subprocess
import time
import re
import os
import platform
import shutil


class InteractiveShell:
    """
    本地命令执行器，替代原有的SSH远程执行方式。
    所有命令直接在本地机器上通过subprocess执行。
    """

    def __init__(self, timeout=120, xray_path=None):
        """
        初始化本地Shell。
        
        @param timeout: 命令执行超时时间（秒）
        @param xray_path: xray可执行文件路径，为None时自动检测
        """
        self.timeout = timeout
        self.is_windows = platform.system() == 'Windows'
        
        # 自动检测xray路径
        if xray_path:
            self.xray_path = xray_path
        else:
            self.xray_path = self._detect_xray_path()
        
        # 验证基本环境
        try:
            result = self.execute_command("echo AutoPT_READY")
            if "AutoPT_READY" not in result:
                raise Exception("Shell环境验证失败")
        except Exception as e:
            raise Exception(f"初始化本地Shell失败: {e}")

    def _detect_xray_path(self) -> str:
        """自动检测xray可执行文件路径"""
        # 搜索路径列表
        search_paths = []
        
        base_dir = os.path.dirname(os.path.abspath(__file__))
        
        if self.is_windows:
            candidates = [
                os.path.join(base_dir, '..', 'xray', 'xray_windows_amd64.exe'),
                os.path.join(base_dir, 'xray', 'xray_windows_amd64.exe'),
                os.path.join(base_dir, '..', 'xray', 'xray.exe'),
            ]
        else:
            candidates = [
                os.path.join(base_dir, '..', 'xray', 'xray_linux_amd64'),
                os.path.join(base_dir, 'xray', 'xray_linux_amd64'),
                os.path.join(base_dir, '..', 'xray', 'xray'),
            ]
        
        for path in candidates:
            abs_path = os.path.abspath(path)
            if os.path.exists(abs_path):
                return abs_path
        
        # 尝试在PATH中查找
        xray_in_path = shutil.which('xray')
        if xray_in_path:
            return xray_in_path
        
        return "xray"  # 回退，让subprocess自行查找

    def execute_command(self, command: str) -> str:
        """
        在本地机器上执行命令。
        
        @param command: 要执行的命令
        @return: 命令输出结果
        """
        # 清理命令
        command = command.strip()
        if command.startswith("`") and command.endswith("`"):
            command = command[1:-1]
        if command.count('\n') > 0:
            lines = command.splitlines()
            command = ' '.join(line.strip() for line in lines if line.strip())
        
        # 屏蔽不支持的命令
        blocked_commands = {
            'nano ': "nano编辑器在自动化环境中不受支持，请使用echo或tee命令写入文件",
            'searchsploit ': "searchsploit在当前环境中不可用",
            'man ': "man命令在当前环境中不可用，请直接使用 --help 参数",
            'vim ': "vim编辑器在自动化环境中不受支持",
            'vi ': "vi编辑器在自动化环境中不受支持",
        }
        
        for blocked, msg in blocked_commands.items():
            if blocked in command:
                return msg
        
        # xray命令特殊处理
        if "xray" in command:
            return self._execute_xray(command)
        
        # curl 命令添加 -s 标志以禁用进度条
        if "curl" in command and " -s" not in command:
            command = command.replace("curl ", "curl -s ", 1)
        
        # 本地执行命令
        return self._execute_local(command)

    def _execute_local(self, command: str) -> str:
        """通过subprocess在本地执行命令"""
        try:
            if self.is_windows:
                # Windows下使用cmd
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    timeout=self.timeout,
                    encoding='utf-8',
                    errors='replace',
                    cwd=os.path.expanduser('~')
                )
            else:
                # Linux/Mac下使用bash
                result = subprocess.run(
                    ['/bin/bash', '-c', command],
                    capture_output=True,
                    timeout=self.timeout,
                    encoding='utf-8',
                    errors='replace',
                    cwd=os.path.expanduser('~')
                )
            
            output = (result.stdout or "")
            if result.stderr:
                # 过滤掉一些常见的无关stderr信息
                stderr = result.stderr.strip()
                if stderr and not stderr.startswith('WARNING'):
                    output += "\n" + stderr
            
            return self.omit(command, output.strip()) if output.strip() else "[命令执行完成，无输出]"
            
        except subprocess.TimeoutExpired:
            return f"[ERROR] 命令执行超时（{self.timeout}秒）: {command}"
        except Exception as e:
            return f"[ERROR] 命令执行失败: {str(e)}"

    def _execute_xray(self, command: str) -> str:
        """执行xray扫描命令"""
        try:
            # 解析命令参数
            parts = command.split()
            if parts[0] == 'xray':
                parts.pop(0)
            
            # 构建完整命令
            full_command = [self.xray_path] + parts
            
            # 确定xray工作目录
            xray_dir = os.path.dirname(self.xray_path) if os.path.exists(self.xray_path) else '.'
            
            result = subprocess.run(
                full_command,
                capture_output=True,
                timeout=self.timeout,
                cwd=xray_dir,
                encoding='utf-8',
                errors='replace'
            )
            
            output = (result.stdout or "")
            if result.stderr:
                output += "\n" + result.stderr
            
            if result.returncode != 0 and not output.strip():
                output = f"[ERROR] xray命令退出码: {result.returncode}"
            
            return output.strip() if output else "[INFO] xray命令执行完成，无输出"
            
        except subprocess.TimeoutExpired:
            return f"[ERROR] xray命令超时（{self.timeout}秒）"
        except FileNotFoundError:
            return f"[ERROR] 找不到xray可执行文件: {self.xray_path}\n请确保xray已正确安装并配置路径"
        except Exception as e:
            return f"[ERROR] xray执行失败: {str(e)}"

    def omit(self, command: str, output: str) -> str:
        """对特定命令的输出进行截断"""
        if "make" in command:
            return "\n".join(output.split("\n")[-30:])
        elif "configure" in command:
            return "\n".join(output.split("\n")[-20:])
        elif "cmake" in command:
            return "\n".join(output.split("\n")[-20:])
        else:
            return output

    def close(self):
        """兼容原有接口"""
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def parse_vuln(text: str) -> list:
    """解析xray扫描结果中的漏洞信息"""
    vulns = []
    color_codes = r'\x1b\[([0-?]*[ -/]*[@-~])'
    raw_text = re.sub(color_codes, '', text)
    lines = raw_text.splitlines()
    vuln_info = None
    for line in lines:
        if line.startswith('[Vuln: '):
            vuln_info = {}
            vuln_match = re.search(r'\[Vuln: (.*?)\]', line)
            if vuln_match:
                vuln_info['vuln'] = vuln_match.group(1)
        elif vuln_info:
            match = re.search(r'(\w+)\s+"(.*?)"', line)
            if match:
                vuln_info[match.group(1).lower()] = match.group(2)
            elif line.startswith('Payload'):
                match = re.search(r'Payload\s+"(.*?)"', line)
                if match:
                    vuln_info['payload'] = match.group(1)
            elif line.startswith('Links'):
                match = re.search(r'Links\s+\[(.*?)\]', line)
                if match:
                    links = match.group(1).split(', ')
                    vuln_info['links'] = [link.strip('"') for link in links]
            elif line.startswith('level'):
                match = re.search(r'level\s+"(.*?)"\s*', line)
                if match:
                    vuln_info['level'] = match.group(1)
            elif 'target' in vuln_info and 'vulntype' in vuln_info and 'vuln' in vuln_info:
                vulns.append(vuln_info)
                vuln_info = None
    return vulns


if __name__ == '__main__':
    # 本地测试
    print("=" * 60)
    print("AutoPT 本地Shell测试")
    print("=" * 60)
    with InteractiveShell() as shell:
        print("[*] 测试基本命令:")
        print(shell.execute_command("whoami"))
        print()
        print("[*] 测试Docker:")
        print(shell.execute_command("docker --version"))
        print()
        print("[*] 测试curl:")
        print(shell.execute_command("curl -s --max-time 5 http://localhost:8080 || echo '目标不可达'"))
