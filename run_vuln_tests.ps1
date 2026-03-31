# 多线程漏洞测试启动脚本 (PowerShell版本)
# 用法: .\run_vuln_tests.ps1 <target> [threads] [timeout]

param(
    [Parameter(Mandatory=$true, HelpMessage="目标地址，格式: host:port 或 http://host:port")]
    [string]$Target,
    
    [Parameter(HelpMessage="并发线程数，默认: 5")]
    [int]$Threads = 5,
    
    [Parameter(HelpMessage="超时时间(秒)，默认: 30")]
    [int]$Timeout = 30
)

# 设置输出编码为UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# 生成输出文件名
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$OutputFile = "vulnerability_results_$Timestamp.json"

Write-Host "================================" -ForegroundColor Green
Write-Host "   多线程漏洞测试 - PowerShell版本" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green
Write-Host "目标: $Target"
Write-Host "线程数: $Threads"
Write-Host "超时时间: ${Timeout}秒"
Write-Host "输出文件: $OutputFile"
Write-Host ""

# 检查Python是否可用
$pythonExe = $null
if (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonExe = "python"
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    $pythonExe = "python3"
} else {
    Write-Host "错误: 未找到 Python，请先安装Python" -ForegroundColor Red
    exit 1
}

# 检查测试用例文件是否存在
$testCasesParam = ""
if (Test-Path "test_cases.txt") {
    Write-Host "使用 test_cases.txt 中的测试用例" -ForegroundColor Yellow
    $testCasesParam = "-f test_cases.txt"
} else {
    Write-Host "警告: 未找到 test_cases.txt，使用默认测试用例" -ForegroundColor Yellow
}

# 执行测试
Write-Host "开始执行漏洞测试..." -ForegroundColor Cyan
Write-Host ""

$arguments = @(
    "vulnerability_tester.py",
    "-t", $Target,
    $testCasesParam,
    "-w", $Threads,
    "--timeout", $Timeout,
    "-o", $OutputFile
)

& $pythonExe $arguments

# 检查执行结果
if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "================================" -ForegroundColor Green
    Write-Host "          测试完成" -ForegroundColor Green
    Write-Host "================================" -ForegroundColor Green
    Write-Host "结果已保存到: $OutputFile" -ForegroundColor Green
    Write-Host ""
    Write-Host "可以使用以下命令查看结果:" -ForegroundColor Yellow
    Write-Host "  Get-Content $OutputFile | ConvertFrom-Json"
    Write-Host "  或者使用 JSON 查看工具"
    
    # 显示简要统计
    $result = Get-Content $OutputFile | ConvertFrom-Json
    Write-Host ""
    Write-Host "测试统计:" -ForegroundColor Cyan
    Write-Host "  总测试数: $($result.total_tests)"
    Write-Host "  成功: $($result.successful)"
    Write-Host "  失败: $($result.failed)"
    Write-Host "  超时: $($result.timeout)"
    Write-Host "  错误: $($result.errors)"
} else {
    Write-Host ""
    Write-Host "================================" -ForegroundColor Red
    Write-Host "      测试执行出错" -ForegroundColor Red
    Write-Host "================================" -ForegroundColor Red
    exit 1
}