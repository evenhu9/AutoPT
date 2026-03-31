@echo off
chcp 65001 >nul

:: 多线程漏洞测试启动脚本 (Windows版本)
:: 用法: run_vuln_tests.bat <target> [threads] [timeout]

setlocal enabledelayedexpansion

:: 参数处理
set TARGET=%1
set THREADS=%2
set TIMEOUT=%3

:: 设置默认值
if "%THREADS%"=="" set THREADS=5
if "%TIMEOUT%"=="" set TIMEOUT=30

:: 生成输出文件名
for /f "tokens=2 delims=:" %%a in ('echo %TIME%') do set TIMESTAMP=%%a
set TIMESTAMP=%DATE:~0,4%%DATE:~5,2%%DATE:~8,2%_%TIME:~0,2%%TIME:~3,2%%TIME:~6,2%
set TIMESTAMP=%TIMESTAMP: =0%
set OUTPUT=vulnerability_results_%TIMESTAMP%.json

if "%TARGET%"=="" (
    echo 用法: %0 ^<目标地址^> [线程数] [超时时间]
    echo 示例:
    echo   %0 127.0.0.1:8080
    echo   %0 192.168.1.100:8848 10 60
    goto :end
)

echo ================================
echo     多线程漏洞测试 - Windows版本
echo ================================
echo 目标: %TARGET%
echo 线程数: %THREADS%
echo 超时时间: %TIMEOUT%秒
echo 输出文件: %OUTPUT%
echo.

:: 检查Python是否可用
where python >nul 2>&1
if errorlevel 1 (
    where python3 >nul 2>&1
    if errorlevel 1 (
        echo 错误: 未找到 Python，请先安装Python
        goto :end
    )
)

:: 检查测试用例文件是否存在
if not exist "test_cases.txt" (
    echo 警告: 未找到 test_cases.txt，使用默认测试用例
    set TEST_CASES=
) else (
    echo 使用 test_cases.txt 中的测试用例
    set TEST_CASES=-f test_cases.txt
)

:: 执行测试
echo 开始执行漏洞测试...
echo.

python vulnerability_tester.py -t "%TARGET%" %TEST_CASES% -w %THREADS% --timeout %TIMEOUT% -o "%OUTPUT%"

:: 检查执行结果
if !errorlevel! equ 0 (
    echo.
    echo ================================
    echo           测试完成
    echo ================================
    echo 结果已保存到: %OUTPUT%
    echo.
    echo 可以使用以下命令查看结果:
    echo   type %OUTPUT%
    echo   或者使用 JSON 查看工具
) else (
    echo.
    echo ================================
    echo       测试执行出错
    echo ================================
)

:end
pause