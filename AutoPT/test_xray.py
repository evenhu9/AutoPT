from terminal import InteractiveShell

try:
    print("[*] 测试 xray 工具...")
    with InteractiveShell() as shell:
        # 检查 xray 是否在 PATH 中
        result1 = shell.execute_command('which xray')
        print(f"[*] which xray: {result1}")
        
        # 检查 xray 文件
        result2 = shell.execute_command('ls -la ~/xray* 2>/dev/null || echo "未找到 xray 文件"')
        print(f"[*] ls xray: {result2}")
        
        # 检查 xray 目录
        result3 = shell.execute_command('find ~ -name "xray*" -type f 2>/dev/null | head -5')
        print(f"[*] find xray: {result3}")
        
        # 检查当前目录
        result4 = shell.execute_command('pwd && ls -la')
        print(f"[*] 当前目录: {result4}")
        
except Exception as e:
    print(f"[ERROR] 测试失败: {e}")
