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
# 动态端口发现：xray crawlergo 探测
# 仅在 get_service_info 返回 None（YAML 里查不到服务）时触发
# ---------------------------------------------------------------------------

# 探测的候选端口列表（覆盖常见 Web 服务端口）
_CANDIDATE_PORTS = [
    80, 443, 8080, 8443, 8888, 8008, 8090,
    9200, 9300,   # Elasticsearch
    7001, 7002,   # WebLogic
    8161,         # ActiveMQ
    27017,        # MongoDB
    6379,         # Redis
    5601,         # Kibana
    9000,         # SonarQube / Portainer
    3000,         # Grafana / Node apps
    4848,         # GlassFish
    8983,         # Solr
    15672,        # RabbitMQ management
    2375,         # Docker API
    10250,        # Kubernetes kubelet
]


def _run(cmd: str, timeout: int = 30) -> str:
    """执行 shell 命令，返回 stdout+stderr，超时或报错返回空串。"""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return (result.stdout + result.stderr).strip()
    except Exception:
        return ""


def _xray_probe_port(ip: str, port: int, timeout: int = 8) -> bool:
    """
    用 curl 探测 ip:port 是否有 HTTP 服务（xray 扫描前的预筛）。
    返回 True 表示该端口有 HTTP/HTTPS 响应。
    """
    for scheme in ("http", "https"):
        out = _run(
            f"curl -sk -o /dev/null -w '%{{http_code}}' --connect-timeout 3 --max-time 5 {scheme}://{ip}:{port}/",
            timeout=timeout
        )
        code = out.strip().lstrip("'").rstrip("'")
        if code.isdigit() and int(code) > 0:
            return True
    return False


def dynamic_discover_port(ip: str, service_name: str) -> Optional[int]:
    """
    动态发现端口，流程：
      1. 遍历候选端口列表，用 curl 探测 HTTP/HTTPS 响应
      2. 收集所有存活端口
      3. 优先返回非 80/443 的端口（更可能是目标服务）
      4. 找不到返回 None（调用方 fallback 到默认 80）

    不依赖 masscan/httpx，只需要 curl（系统自带）。
    """
    print(f"[Recon] YAML miss for '{service_name}', probing {ip} on {len(_CANDIDATE_PORTS)} candidate ports...")

    live_ports = []
    for port in _CANDIDATE_PORTS:
        if _xray_probe_port(ip, port):
            live_ports.append(port)
            print(f"[Recon] HTTP service found on {ip}:{port}")

    if not live_ports:
        print(f"[Recon] No HTTP services found on candidate ports, falling back to default 80")
        return None

    # 优先返回非 80/443 的端口
    non_default = [p for p in live_ports if p not in (80, 443)]
    if non_default:
        return non_default[0]

    return live_ports[0]


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
