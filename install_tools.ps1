# ============================================================================
# install_tools.ps1 - AutoPT 渗透测试工具一键安装脚本 (Windows 版)
# ============================================================================

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

function Write-Info    { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-Success { param($msg) Write-Host "[OK]   $msg" -ForegroundColor Green }
function Write-Warn    { param($msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err     { param($msg) Write-Host "[ERR]  $msg" -ForegroundColor Red }

$ARCH = if ([Environment]::Is64BitOperatingSystem) { "win64" } else { "win32" }
$OS_VERSION = [System.Environment]::OSVersion.VersionString

Write-Info "检测到系统: Windows ($ARCH)"
Write-Info "系统版本: $OS_VERSION"
Write-Host ""

$INSTALLED = [System.Collections.ArrayList]::new()
$SKIPPED   = [System.Collections.ArrayList]::new()
$FAILED    = [System.Collections.ArrayList]::new()

function Test-CommandExists {
    param($Command)
    $null -ne (Get-Command $Command -ErrorAction SilentlyContinue)
}

function Test-Chocolatey {
    Test-CommandExists "choco"
}

function Test-Winget {
    Test-CommandExists "winget"
}

function Install-Chocolatey {
    if (Test-Chocolatey) {
        Write-Info "Chocolatey 已安装"
        return $true
    }
    Write-Info "正在安装 Chocolatey 包管理器..."
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        Write-Success "Chocolatey 安装完成"
        return $true
    }
    catch {
        Write-Err "Chocolatey 安装失败: $_"
        return $false
    }
}

function Install-Nmap {
    Write-Info "安装 nmap（全端口扫描与服务识别）..."
    if (Test-CommandExists "nmap") {
        $ver = & nmap --version 2>&1 | Select-Object -First 1
        Write-Success "nmap 已安装: $ver"
        [void]$SKIPPED.Add("nmap")
        return
    }
    if (Test-Winget) {
        Write-Info "尝试通过 winget 安装 nmap..."
        try {
            & winget install --id Insecure.Nmap --accept-package-agreements --accept-source-agreements --silent
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
            if (Test-CommandExists "nmap") {
                Write-Success "nmap 通过 winget 安装完成"
                [void]$INSTALLED.Add("nmap")
                return
            }
        }
        catch {
            Write-Warn "winget 安装 nmap 失败，尝试其他方式..."
        }
    }
    if (Install-Chocolatey) {
        try {
            & choco install nmap -y --no-progress
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
            if (Test-CommandExists "nmap") {
                Write-Success "nmap 通过 Chocolatey 安装完成"
                [void]$INSTALLED.Add("nmap")
                return
            }
        }
        catch {
            Write-Warn "Chocolatey 安装 nmap 失败"
        }
    }
    Write-Err "nmap 自动安装失败，请手动安装："
    Write-Err "  下载地址: https://nmap.org/download.html#windows"
    Write-Err "  下载 nmap-*-setup.exe 并运行安装（安装时勾选 Npcap）"
    Write-Err "  安装后将 nmap 目录添加到系统 PATH 环境变量"
    [void]$FAILED.Add("nmap")
}

function Install-Curl {
    Write-Info "检查 curl..."
    if (Test-CommandExists "curl.exe") {
        $ver = & curl.exe --version 2>&1 | Select-Object -First 1
        Write-Success "curl 已安装: $ver"
        [void]$SKIPPED.Add("curl")
        return
    }
    $curlPath = Join-Path $env:SystemRoot "System32\curl.exe"
    if (Test-Path $curlPath) {
        Write-Success "curl 已存在: $curlPath"
        [void]$SKIPPED.Add("curl")
        return
    }
    Write-Warn "curl 未找到。Windows 10 1803+ 应自带 curl.exe"
    Write-Warn "如需手动安装: https://curl.se/windows/"
    [void]$FAILED.Add("curl")
}

function Install-Xray {
    $SCRIPT_DIR = Split-Path -Parent $MyInvocation.ScriptName
    if (-not $SCRIPT_DIR) { $SCRIPT_DIR = $PSScriptRoot }
    if (-not $SCRIPT_DIR) { $SCRIPT_DIR = Get-Location }
    $XRAY_DIR = Join-Path $SCRIPT_DIR "xray"
    $XRAY_BIN = Join-Path $XRAY_DIR "xray_windows_amd64.exe"
    Write-Info "安装 xray（Web 漏洞扫描器）..."
    if (Test-Path $XRAY_BIN) {
        Write-Success "xray 已存在: $XRAY_BIN"
        [void]$SKIPPED.Add("xray")
        return
    }
    if (Test-CommandExists "xray") {
        $xrayLoc = (Get-Command xray).Source
        Write-Success "xray 已安装在系统 PATH 中: $xrayLoc"
        [void]$SKIPPED.Add("xray")
        return
    }
    if (-not (Test-Path $XRAY_DIR)) {
        New-Item -ItemType Directory -Path $XRAY_DIR -Force | Out-Null
    }
    Write-Info "获取 xray 最新版本..."
    $XRAY_VERSION = $null
    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/chaitin/xray/releases/latest" -UseBasicParsing
        $XRAY_VERSION = $release.tag_name
    }
    catch {
        Write-Warn "无法获取 xray 最新版本号"
    }
    if (-not $XRAY_VERSION) {
        Write-Warn "请手动下载 xray："
        Write-Warn "  下载地址: https://github.com/chaitin/xray/releases"
        Write-Warn "  下载 xray_windows_amd64.exe.zip 并解压到: $XRAY_DIR\"
        [void]$FAILED.Add("xray")
        return
    }
    Write-Info "下载 xray $XRAY_VERSION (windows/amd64)..."
    $DOWNLOAD_URL = "https://github.com/chaitin/xray/releases/download/$XRAY_VERSION/xray_windows_amd64.exe.zip"
    $TMP_ZIP = Join-Path $env:TEMP "xray_download.zip"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $DOWNLOAD_URL -OutFile $TMP_ZIP -UseBasicParsing
        Expand-Archive -Path $TMP_ZIP -DestinationPath $XRAY_DIR -Force
        Remove-Item $TMP_ZIP -Force -ErrorAction SilentlyContinue
        if ((Test-Path $XRAY_BIN) -or (Get-ChildItem "$XRAY_DIR\xray*" -ErrorAction SilentlyContinue)) {
            Write-Success "xray $XRAY_VERSION 安装完成: $XRAY_DIR\"
            [void]$INSTALLED.Add("xray")
        }
        else {
            Write-Err "xray 解压后未找到可执行文件，请检查 $XRAY_DIR\"
            [void]$FAILED.Add("xray")
        }
    }
    catch {
        Write-Err "xray 下载失败: $_"
        Write-Err "请手动下载:"
        Write-Err "  $DOWNLOAD_URL"
        Write-Err "  解压后放入 $XRAY_DIR\"
        Remove-Item $TMP_ZIP -Force -ErrorAction SilentlyContinue
        [void]$FAILED.Add("xray")
    }
}

function Install-Docker {
    Write-Info "检查 Docker..."
    if (Test-CommandExists "docker") {
        $ver = & docker --version 2>&1
        Write-Success "Docker 已安装: $ver"
        [void]$SKIPPED.Add("docker")
        return
    }
    Write-Warn "Docker 未安装。请手动安装 Docker Desktop for Windows："
    Write-Warn "  下载地址: https://www.docker.com/products/docker-desktop/"
    Write-Warn "  安装后需要启用 WSL 2 或 Hyper-V 后端"
    Write-Warn "  安装完成后重启电脑"
    [void]$FAILED.Add("docker")
}

Write-Host "============================================================"
Write-Host "  AutoPT 渗透测试工具安装脚本 (Windows)"
Write-Host "============================================================"
Write-Host ""

Install-Nmap
Write-Host ""
Install-Curl
Write-Host ""
Install-Xray
Write-Host ""
Install-Docker

Write-Host ""
Write-Host "============================================================"
Write-Host "  安装汇总"
Write-Host "============================================================"

if ($INSTALLED.Count -gt 0) {
    Write-Success "新安装: $($INSTALLED -join ', ')"
}
if ($SKIPPED.Count -gt 0) {
    Write-Info "已存在（跳过）: $($SKIPPED -join ', ')"
}
if ($FAILED.Count -gt 0) {
    Write-Err "安装失败: $($FAILED -join ', ')"
    Write-Host ""
    Write-Warn "对于安装失败的工具，请参考以下手动安装方式："
    foreach ($tool in $FAILED) {
        switch ($tool) {
            "nmap"   { Write-Warn "  nmap:   https://nmap.org/download.html#windows (安装时勾选 Npcap)" }
            "xray"   { Write-Warn "  xray:   https://github.com/chaitin/xray/releases (下载 windows_amd64 版本)" }
            "curl"   { Write-Warn "  curl:   Windows 10 1803+ 自带，或从 https://curl.se/windows/ 下载" }
            "docker" { Write-Warn "  docker: https://www.docker.com/products/docker-desktop/" }
        }
    }
}

Write-Host ""

Write-Info "工具可用性验证："

if (Test-CommandExists "nmap") {
    $nmapPath = (Get-Command nmap).Source
    Write-Success "  nmap: $nmapPath"
}
else {
    Write-Err "  nmap: 未找到"
}

if (Test-CommandExists "ncat") {
    $ncatPath = (Get-Command ncat).Source
    Write-Success "  ncat (netcat): $ncatPath"
}
else {
    Write-Warn "  ncat: 未找到（安装 nmap 时会自带 ncat）"
}

if (Test-CommandExists "curl.exe") {
    $curlPath = (Get-Command curl.exe).Source
    Write-Success "  curl: $curlPath"
}
else {
    Write-Err "  curl: 未找到"
}

if (Test-CommandExists "docker") {
    $dockerPath = (Get-Command docker).Source
    Write-Success "  docker: $dockerPath"
}
else {
    Write-Err "  docker: 未找到"
}

$SCRIPT_DIR_V = $PSScriptRoot
if (-not $SCRIPT_DIR_V) {
    try { $SCRIPT_DIR_V = Split-Path -Parent $MyInvocation.ScriptName } catch {}
}
$XRAY_CHECK = Join-Path $SCRIPT_DIR_V "xray\xray_windows_amd64.exe"

if ((Test-Path $XRAY_CHECK) -or (Test-CommandExists "xray")) {
    $xrayLoc = if (Test-Path $XRAY_CHECK) { $XRAY_CHECK } else { (Get-Command xray).Source }
    Write-Success "  xray: $xrayLoc"
}
else {
    Write-Err "  xray: 未找到"
}

Write-Host ""
Write-Info "安装完成！如果所有工具均已就绪，可以启动 AutoPT："
Write-Info "  python app.py"
Write-Host ""
