import paramiko
import time
import re
import subprocess
import os

class InteractiveShell:
    def __init__(self, hostname=None, port=22, username=None, password=None, timeout=30, local_mode=None):
        """
        交互式Shell，支持两种模式：
        - SSH远程模式: 提供 hostname/username/password 时使用 Paramiko SSH 连接
        - 本地模式: 不提供 SSH 参数时，在本机直接执行命令（subprocess）
        
        local_mode: 显式指定 True/False，None 时自动检测
        """
        self.timeout = timeout
        self.local_mode = local_mode
        self.client = None
        self.session = None
        
        # 自动检测模式：如果没有提供 SSH 凭据，使用本地模式
        if self.local_mode is None:
            self.local_mode = (hostname is None or username is None or password is None)
        
        if not self.local_mode:
            # SSH 远程模式
            try:
                self.client = paramiko.SSHClient()
                self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self.client.connect(hostname, username=username, password=password, port=port)
                self.session = self.client.invoke_shell()
                # Wait for shell to be ready
                time.sleep(1)
                # Clear initial output
                while self.session.recv_ready():
                    self.session.recv(1024)
                # Test connection
                try:
                    self.execute_command("pwd")
                except Exception as e:
                    self.close()
                    raise Exception(f"Failed to initialize shell: {e}")
            except Exception as e:
                print(f"[WARNING] SSH 连接失败 ({hostname}:{port}): {e}，回退到本地模式")
                self.local_mode = True
                self.client = None
                self.session = None
        
        # 确定 xray 可执行文件路径
        self.xray_path = self._find_xray_path()

    def _find_xray_path(self) -> str:
        """查找 xray 可执行文件路径"""
        # 按优先级搜索
        candidates = [
            os.path.join(os.path.dirname(__file__), '..', 'xray', 'xray_linux_amd64'),
            os.path.join(os.path.dirname(__file__), '..', 'xray', 'xray_windows_amd64.exe'),
            os.path.join(os.path.dirname(__file__), '..', 'xray', 'xray_darwin_amd64'),
        ]
        for c in candidates:
            p = os.path.abspath(c)
            if os.path.exists(p):
                return p
        # 尝试 which
        import shutil
        xray = shutil.which('xray')
        if xray:
            return xray
        return os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'xray', 'xray_linux_amd64'))

    def execute_command(self, command:str):
        """
        Execute a command in a interactive shell.
        In local mode, uses subprocess; in SSH mode, uses paramiko session.
        """
        # clean the command
        command = command.strip()
        if command.startswith("`") and command.endswith("`"):
            command = command[1:-1]
        if command.count('\n') > 0:
            command = command.splitlines() # pyright: ignore[reportAssignmentType]
            command = ''.join(command[1:-1])
        if 'nano ' in command:
            return "nano is not supported in this environment"
        if 'searchsploit ' in command:
            return "searchsploit is not supported in this environment"
        if 'man ' in command:
            return "man is not supported in this environment"

        # xray 命令始终在本地执行
        if "xray" in command:
            return self._execute_xray_local(command)
        
        # curl 命令添加 -s 标志以禁用进度条
        if "curl" in command and " -s" not in command:
            command = command.replace("curl ", "curl -s ", 1)
        
        # 根据模式执行
        if self.local_mode:
            return self._execute_local(command)
        else:
            return self._execute_ssh(command)

    def _execute_local(self, command: str) -> str:
        """本地模式：使用 subprocess 执行命令"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                timeout=self.timeout,
                encoding='utf-8',
                errors='replace',
                cwd='/root' if os.path.exists('/root') else os.path.expanduser('~')
            )
            output = (result.stdout or "")
            if result.stderr:
                output += "\n" + result.stderr
            
            if not output.strip():
                if result.returncode != 0:
                    output = f"Command exited with code {result.returncode}"
                else:
                    output = "(no output)"
            
            return self.omit(command, output)
        except subprocess.TimeoutExpired:
            return f"Command execution timeout after {self.timeout} seconds!"
        except Exception as e:
            return f"Error executing command: {str(e)}"

    def _execute_ssh(self, command: str) -> str:
        """SSH远程模式：使用 paramiko session 执行命令"""
        if self.session is None:
            raise Exception("No session available.")

        self.session.send((command + '\n').encode('utf-8'))

        start_time = time.time()
        output = ""
        # 使用正则表达式匹配提示符，格式为 *@*
        prompt_pattern = re.compile(r'\w+@\w+')
        
        while True:
            if time.time() - start_time > self.timeout: # execution timeout
                self.session.send(b'\x03')
                timeout_output = output
                timeout_time = time.time()
                
                # Try to receive remaining output after Ctrl+C
                while True:
                    if time.time() - timeout_time > 3:  # Wait up to 3 more seconds
                        timeout_output += "\nCommand execution timeout!"
                        return self.omit(command, timeout_output)
                    
                    # Check if we see any prompt pattern using regex
                    if prompt_pattern.search(timeout_output):
                        timeout_output += "\nCommand execution timeout!"
                        return self.omit(command, timeout_output)
                    
                    if self.session.recv_ready():
                        try:
                            timeout_output += self.session.recv(1024).decode('utf-8', 'ignore')
                        except:
                            pass
                    else:
                        time.sleep(0.1)
            
            # Check for any command prompt using regex as return condition
            if prompt_pattern.search(output) and command not in output.split('\n')[-1]:
                return self.omit(command, output)
            
            # read outputs
            if self.session.recv_ready():
                while self.session.recv_ready():
                    try:
                        output += self.session.recv(1024).decode('utf-8','ignore')
                    except:
                        pass
                time.sleep(0.1)  # add a delay after receiving output
            else:
                time.sleep(0.1)
        

    def omit(self, command, output)->str:
        '''
        omit the command from the output for special commands
        '''
        if "make" in command:
            return "\n".join(output.split("\n")[-30:])
        elif "configure" in command:
            return "\n".join(output.split("\n")[-20:])
        elif "cmake" in command:
            return "\n".join(output.split("\n")[-20:])
        else:
            return output

    def _execute_xray_local(self, command: str) -> str:
        """
        Execute xray command locally.
        Uses self.xray_path found during initialization.
        """
        try:
            xray_exe = self.xray_path
            xray_dir = os.path.dirname(xray_exe)
            
            # 解析命令参数
            # 例如: "xray ws --url http://target.com" -> ["ws", "--url", "http://target.com"]
            parts = command.split()
            if parts[0] == 'xray':
                parts.pop(0)  # 移除 'xray'
            
            # 构建完整命令
            full_command = [xray_exe] + parts
            
            # 直接执行，指定 UTF-8 编码处理 xray 的 Unicode 输出
            result = subprocess.run(
                full_command,
                capture_output=True,
                timeout=self.timeout,
                cwd=xray_dir if os.path.isdir(xray_dir) else None,
                encoding='utf-8',
                errors='replace'
            )
            
            # 合并 stdout 和 stderr
            output = (result.stdout or "")
            if result.stderr:
                output += "\n" + result.stderr
            
            if result.returncode != 0:
                if not output.strip():
                    output = f"[ERROR] xray command exited with code {result.returncode}"
            
            return output.strip() if output else "[INFO] xray command completed with no output"
            
        except subprocess.TimeoutExpired:
            return f"[ERROR] xray command timeout after {self.timeout} seconds"
        except FileNotFoundError:
            return f"[ERROR] xray not found at {self.xray_path}. Please install xray first."
        except Exception as e:
            return f"[ERROR] Failed to execute xray: {str(e)}"

    def close(self):
        if self.client:
            self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

import re

def parse_vuln(text):
    vulns = []
    color_codes = r'\x1b\[([0-?]*[ -/]*[@-~])'
    raw_text = re.sub(color_codes, '', text)
    lines = raw_text.splitlines()
    # lines = text.splitlines()
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
    # DEMO
    with InteractiveShell() as shell:
        print("="*60)
        print(shell.execute_command("pwd"))

        scan_res = shell.execute_command('xray ws --url 192.168.160.1:8081')
        print(scan_res)
        # color_codes = r'\x1b\[([0-?]*[ -/]*[@-~])'
        # scan_res = re.sub(color_codes, '', scan_res)
        vuln_dict = parse_vuln(scan_res)

        print(vuln_dict)
        result = [item for item in vuln_dict if 'level' in item]

        print(result)

