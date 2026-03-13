"""
服务知识库加载模块
从 config/services.yml 动态加载服务信息，供 prompt 使用

改动说明（相对 optimize-prompts 分支）：
- 新增 dynamic_discover_port(ip, service_name)
  优先级：masscan 全端口扫描 → httpx 探活 → 返回第一个匹配的 HTTP 端口
  在 get_service_info 查不到服务时作为兜底，彻底摆脱非标端口依赖
"""

import os
import re
import subprocess
import yaml
from typing import Optional

_KNOWLEDGE_CACHE = None
_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config", "services.yml")


def load_services() -> dict:
    """加载服务知识库"""
    global _KNOWLEDGE_CACHE
    if _KNOWLEDGE_CACHE is None:
        with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
            _KNOWLEDGE_CACHE = yaml.safe_load(f)
    return _KNOWLEDGE_CACHE


def get_service_port(service_name: str) -> int:
    """根据服务名获取端口"""
    kb = load_services()
    name = service_name.lower().strip()

    if name in kb["services"]:
        return kb["services"][name]["port"]

    for svc, info in kb["services"].items():
        if name in info.get("aliases", []):
            return info["port"]

    return kb["default"]["port"]


def get_service_info(service_name: str) -> Optional[dict]:
    """获取服务完整信息"""
    kb = load_services()
    name = service_name.lower().strip()

    if name in kb["services"]:
        return kb["services"][name]

    for svc, info in kb["services"].items():
        if name in info.get("aliases", []):
            return info

    return None


# ---------------------------------------------------------------------------
# 动态端口发现：masscan + httpx
# 仅在 get_service_info 返回 None（YAML 里查不到服务）时触发
# ---------------------------------------------------------------------------

def _run(cmd: str, timeout: int = 30) -> str:
    """执行 shell 命令，返回 stdout+stderr，超时或报错返回空串。"""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return (result.stdout + result.stderr).strip()
    except Exception:
        return ""


def _masscan_open_ports(ip: str, rate: int = 1000, timeout: int = 30) -> list:
    """
    用 masscan 扫描全端口，返回开放端口列表（int）。
    需要 root 权限运行 masscan。
    """
    out = _run(f"masscan {ip} -p 1-65535 --rate={rate} --wait 2 -oG -", timeout=timeout)
    ports = []
    # masscan -oG 输出格式：Host: 1.2.3.4 ()  Ports: 8080/open/tcp//http//
    for match in re.finditer(r'Ports:\s*([\d,/a-z ]+)', out, re.IGNORECASE):
        for port_match in re.finditer(r'(\d+)/open', match.group(1)):
            ports.append(int(port_match.group(1)))
    return sorted(set(ports))


def _httpx_probe(ip: str, ports: list, timeout: int = 20) -> list:
    """
    用 httpx 对给定端口探活，返回可访问的 URL 列表。
    格式：["http://1.2.3.4:8080", "https://1.2.3.4:8443", ...]
    """
    if not ports:
        return []

    # 构造 targets 文件内容：ip:port 每行一个
    targets = "\n".join(f"{ip}:{p}" for p in ports)
    # 用 echo 管道传给 httpx，-silent 只输出成功的 URL
    cmd = f"echo '{targets}' | httpx -silent -no-fallback -timeout 5"
    out = _run(cmd, timeout=timeout)
    urls = [line.strip() for line in out.splitlines() if line.strip().startswith("http")]
    return urls


def dynamic_discover_port(ip: str, service_name: str) -> Optional[int]:
    """
    动态发现端口，流程：
      1. masscan 扫全端口，获取开放端口列表
      2. httpx 探活，找出 HTTP/HTTPS 服务
      3. 优先返回与 service_name 默认端口最接近的端口；
         若找不到则返回第一个可访问端口

    返回端口号（int），找不到返回 None。
    """
    print(f"[Recon] YAML miss for '{service_name}', starting dynamic discovery on {ip}...")

    # Step 1: masscan
    open_ports = _masscan_open_ports(ip)
    if not open_ports:
        print(f"[Recon] masscan found no open ports on {ip}, falling back to default 80")
        return None

    print(f"[Recon] masscan open ports: {open_ports}")

    # Step 2: httpx 探活
    http_urls = _httpx_probe(ip, open_ports)
    if not http_urls:
        print(f"[Recon] httpx found no HTTP services, returning first open port: {open_ports[0]}")
        return open_ports[0]

    print(f"[Recon] httpx live URLs: {http_urls}")

    # Step 3: 从 URL 里解析端口
    http_ports = []
    for url in http_urls:
        m = re.search(r':(\d+)(?:/|$)', url)
        if m:
            http_ports.append(int(m.group(1)))
        elif url.startswith("https://"):
            http_ports.append(443)
        else:
            http_ports.append(80)

    # 优先返回非 80/443 的端口（更可能是目标服务）
    non_default = [p for p in http_ports if p not in (80, 443)]
    if non_default:
        return non_default[0]

    return http_ports[0] if http_ports else None


# ---------------------------------------------------------------------------
# 以下函数保持不变
# ---------------------------------------------------------------------------

def generate_port_mapping_text() -> str:
    kb = load_services()
    lines = []
    for name, info in kb["services"].items():
        lines.append(f"   - {name.capitalize()} → port {info['port']}")
    return "\n".join(lines)


def generate_scan_port_table() -> str:
    kb = load_services()
    lines = []
    for name, info in kb["services"].items():
        port = info["port"]
        lines.append(f"   - {name.capitalize()} → port {port}: xray ws --url http://{{target}}:{port}")
    lines.append(f"   - Default (unknown) → port 80: xray ws --url http://{{target}}")
    return "\n".join(lines)


def generate_exploit_recon_table() -> str:
    kb = load_services()
    lines = []
    for name, info in kb["services"].items():
        port = info["port"]
        probe = info.get("probe_cmd", f"curl http://{{target}}:{port}")
        lines.append(f"- {name.capitalize()}: Port {port} → {probe}")
    return "\n".join(lines)


def generate_service_hints() -> str:
    kb = load_services()
    lines = []
    for name, info in kb["services"].items():
        port = info["port"]
        hints = info.get("exploit_hints", "")
        lines.append(f"- {name.capitalize()}: Port {port}, {hints}")
    return "\n".join(lines)


def generate_cve_patterns() -> str:
    kb = load_services()
    lines = []
    for name, info in kb["services"].items():
        patterns = ", ".join(info.get("cve_patterns", []))
        if patterns:
            lines.append(f"- {name.capitalize()}: {patterns}")
    return "\n".join(lines)
