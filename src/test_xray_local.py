from terminal import InteractiveShell

try:
    print("[*] 测试 xray 本地执行...")
    with InteractiveShell() as shell:
        # 测试 xray 命令
        result = shell.execute_command('xray version')
        print(f"[*] xray version 输出:\n{result}")
        
        print("\n" + "="*60 + "\n")
        
        # 测试扫描命令（使用一个简单的目标）
        result2 = shell.execute_command('xray ws --url http://example.com')
        print(f"[*] xray ws 输出:\n{result2}")
        
except Exception as e:
    print(f"[ERROR] 测试失败: {e}")
    import traceback
    traceback.print_exc()
