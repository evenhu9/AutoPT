from terminal import InteractiveShell

try:
    print("[*] 测试 SSH 连接...")
    with InteractiveShell() as shell:
        result = shell.execute_command('pwd')
        print(f"[+] 连接成功!")
        print(f"[+] 命令输出: {result}")
except Exception as e:
    print(f"[ERROR] 连接失败: {e}")