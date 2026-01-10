import paramiko
import time
import re
import subprocess
import os

class InteractiveShell:
    def __init__(self, hostname='172.17.0.1', port=22, username='hyw', password='260259', timeout=30):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(hostname, username=username, password=password, port=port)
        self.session = self.client.invoke_shell()
        self.timeout = timeout
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

    def execute_command(self, command:str):
        """
        Execute a command in a interactive kali docker shell on the local machine.
        Initially, we are in the /root/ directory.

        @param cmd: The command to execute.
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

        # xray 命令在宿主机上执行
        if "xray" in command:
            return self._execute_xray_local(command)
        
        # curl 命令添加 -s 标志以禁用进度条
        if "curl" in command and " -s" not in command:
            # 检查是否已有其他标志，在URL前添加 -s
            command = command.replace("curl ", "curl -s ", 1)
        
        # 其他命令通过 SSH 在远程执行
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
        Execute xray command on the local Windows host machine.
        xray is located at: c:\\Users\\86138\\Desktop\\毕设\\AutoPT\\xray\\xray_windows_amd64.exe
        """
        try:
            # 获取 xray 可执行文件的路径
            xray_dir = os.path.join(os.path.dirname(__file__), '..', 'xray')
            xray_exe = os.path.abspath(os.path.join(xray_dir, 'xray_windows_amd64.exe'))
            
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
                cwd=xray_dir,
                encoding='utf-8',
                errors='replace'  # 替换无法解码的字符而不是抛出异常
            )
            
            # 合并 stdout 和 stderr
            output = (result.stdout or "")
            if result.stderr:
                output += "\n" + result.stderr
            
            # 如果命令执行失败但有输出，返回输出；否则返回错误信息
            if result.returncode != 0:
                if not output.strip():
                    output = f"[ERROR] xray command exited with code {result.returncode}"
            
            return output.strip() if output else "[INFO] xray command completed with no output"
            
        except subprocess.TimeoutExpired:
            return f"[ERROR] xray command timeout after {self.timeout} seconds"
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

