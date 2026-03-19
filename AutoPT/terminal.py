"""
本地交互式Shell - 替代原始SSH连接
在 Windows 上通过 subprocess 本地执行命令，兼容 macOS/Linux
保持与原始 InteractiveShell 相同的接口
"""
import subprocess
import time
import re
import os
import platform
import shutil


class InteractiveShell:
    """
    本地命令执行器，替代原有的 paramiko SSH 远程执行方式。
    保持与原始版本完全相同的接口：
      - __init__(hostname, port, username, password, timeout)
      - execute_command(command) -> str
      - close()
    所有命令直接在本地机器上通过 subprocess 执行。
    """

    def __init__(self, hostname='127.0.0.1', port=22, username='', password='', timeout=120):
        """
        初始化本地Shell。
        保留原始参数签名以兼容，但实际不使用SSH参数。

        @param hostname: 兼容参数（不使用）
        @param port: 兼容参数（不使用）
        @param username: 兼容参数（不使用）
        @param password: 兼容参数（不使用）
        @param timeout: 命令执行超时时间（秒）
        """
        self.timeout = timeout
        self.system = platform.system()  # 'Windows', 'Darwin', 'Linux'
        self.is_windows = self.system == 'Windows'
        self.is_macos = self.system == 'Darwin'

        # 自动检测xray路径
        self.xray_path = self._detect_xray_path()

        # 验证基本环境
        try:
            result = self.execute_command("echo AutoPT_READY")
            if "AutoPT_READY" not in result:
                raise Exception("Shell环境验证失败")
        except Exception as e:
            raise Exception(f"初始化本地Shell失败: {e}")

    def _detect_xray_path(self) -> str:
        """自动检测xray可执行文件路径，支持 Windows / macOS / Linux"""
        base_dir = os.path.dirname(os.path.abspath(__file__))

        if self.is_windows:
            candidates = [
                os.path.join(base_dir, '..', 'xray', 'xray_windows_amd64.exe'),
                os.path.join(base_dir, 'xray', 'xray_windows_amd64.exe'),
                os.path.join(base_dir, '..', 'xray', 'xray.exe'),
            ]
        elif self.is_macos:
            arch = platform.machine()  # 'x86_64' or 'arm64'
            if arch == 'arm64':
                candidates = [
                    os.path.join(base_dir, '..', 'xray', 'xray_darwin_arm64'),
                    os.path.join(base_dir, 'xray', 'xray_darwin_arm64'),
                    os.path.join(base_dir, '..', 'xray', 'xray_darwin_amd64'),
                ]
            else:
                candidates = [
                    os.path.join(base_dir, '..', 'xray', 'xray_darwin_amd64'),
                    os.path.join(base_dir, 'xray', 'xray_darwin_amd64'),
                ]
        else:
            # Linux
            candidates = [
                os.path.join(base_dir, '..', 'xray', 'xray_linux_amd64'),
                os.path.join(base_dir, 'xray', 'xray_linux_amd64'),
                os.path.join(base_dir, '..', 'xray', 'xray'),
            ]

        for path in candidates:
            abs_path = os.path.abspath(path)
            if os.path.exists(abs_path):
                return abs_path

        # 尝试在 PATH 中查找
        xray_name = 'xray.exe' if self.is_windows else 'xray'
        xray_in_path = shutil.which(xray_name)
        if xray_in_path:
            return xray_in_path

        return "xray"  # 回退

    def execute_command(self, command: str) -> str:
        """
        在本地机器上执行命令。
        保持与原始 SSH 版本相同的接口。

        @param command: 要执行的命令
        @return: 命令输出结果
        """
        # 清理命令（与原始版本逻辑一致）
        command = command.strip()
        if command.startswith("`") and command.endswith("`"):
            command = command[1:-1]
        if command.count('\n') > 0:
            lines = command.splitlines()
            command = ' '.join(line.strip() for line in lines if line.strip())

        # 屏蔽不支持的命令（与原始版本一致）
        if 'nano ' in command:
            return "nano is not supported in this environment"
        if 'searchsploit ' in command:
            return "searchsploit is not supported in this environment"
        if 'man ' in command:
            return "man is not supported in this environment"
        if 'vim ' in command:
            return "vim is not supported in this environment"
        if 'vi ' in command:
            return "vi is not supported in this environment"

        # xray 命令特殊处理（原始版本就在本地执行xray）
        if "xray" in command:
            return self._execute_xray_local(command)

        # curl 命令添加 -s 标志以禁用进度条
        if "curl" in command and " -s" not in command:
            command = command.replace("curl ", "curl -s ", 1)

        # 本地执行命令（替代原始版本的SSH执行）
        return self._execute_local(command)

    def _execute_local(self, command: str) -> str:
        """通过 subprocess 在本地执行命令"""
        try:
            if self.is_windows:
                # Windows 下使用 cmd，设置 UTF-8 代码页
                result = subprocess.run(
                    f'chcp 65001 >nul 2>&1 & {command}',
                    shell=True,
                    capture_output=True,
                    timeout=self.timeout,
                    encoding='utf-8',
                    errors='replace',
                    cwd=os.path.expanduser('~')
                )
            else:
                # Linux/Mac 下使用 bash
                shell_path = self._detect_shell()
                result = subprocess.run(
                    [shell_path, '-c', command],
                    capture_output=True,
                    timeout=self.timeout,
                    encoding='utf-8',
                    errors='replace',
                    cwd=os.path.expanduser('~')
                )

            output = (result.stdout or "")
            if result.stderr:
                stderr = result.stderr.strip()
                if stderr and not stderr.startswith('WARNING'):
                    output += "\n" + stderr

            return self.omit(command, output.strip()) if output.strip() else "[命令执行完成，无输出]"

        except subprocess.TimeoutExpired:
            return f"Command execution timeout! ({self.timeout}s)"
        except Exception as e:
            return f"[ERROR] 命令执行失败: {str(e)}"

    def _execute_xray_local(self, command: str) -> str:
        """
        在本地执行 xray 扫描命令。
        与原始版本的 _execute_xray_local 逻辑一致。
        """
        try:
            # 解析命令参数
            parts = command.split()
            if parts[0] == 'xray':
                parts.pop(0)

            # 构建完整命令
            full_command = [self.xray_path] + parts

            # 确定 xray 工作目录
            xray_dir = os.path.dirname(self.xray_path) if os.path.exists(self.xray_path) else '.'

            # Windows 下需要特殊处理
            extra_kwargs = {}
            if self.is_windows:
                if hasattr(subprocess, 'CREATE_NO_WINDOW'):
                    extra_kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW

            result = subprocess.run(
                full_command,
                capture_output=True,
                timeout=self.timeout,
                cwd=xray_dir,
                encoding='utf-8',
                errors='replace',
                **extra_kwargs
            )

            output = (result.stdout or "")
            if result.stderr:
                output += "\n" + result.stderr

            if result.returncode != 0 and not output.strip():
                output = f"[ERROR] xray command exited with code {result.returncode}"

            return output.strip() if output else "[INFO] xray command completed with no output"

        except subprocess.TimeoutExpired:
            return f"[ERROR] xray command timeout after {self.timeout} seconds"
        except FileNotFoundError:
            return f"[ERROR] 找不到xray可执行文件: {self.xray_path}"
        except Exception as e:
            return f"[ERROR] Failed to execute xray: {str(e)}"

    def omit(self, command, output) -> str:
        """对特定命令的输出进行截断（与原始版本一致）"""
        if "make" in command:
            return "\n".join(output.split("\n")[-30:])
        elif "configure" in command:
            return "\n".join(output.split("\n")[-20:])
        elif "cmake" in command:
            return "\n".join(output.split("\n")[-20:])
        else:
            return output

    def _detect_shell(self) -> str:
        """检测可用的 shell 路径"""
        env_shell = os.environ.get('SHELL')
        if env_shell and os.path.exists(env_shell):
            return env_shell
        for candidate in ['/bin/bash', '/bin/zsh', '/bin/sh']:
            if os.path.exists(candidate):
                return candidate
        return '/bin/sh'

    def close(self):
        """兼容原始接口"""
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# 漏洞解析函数（与原始版本完全一致）
def parse_vuln(text):
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
    print("=" * 60)
    print("AutoPT 本地Shell测试")
    print("=" * 60)
    with InteractiveShell() as shell:
        print("[*] 测试基本命令:")
        print(shell.execute_command("whoami"))
        print()
        print("[*] 测试curl:")
        print(shell.execute_command("curl -s --max-time 5 http://localhost:8080 || echo '目标不可达'"))
