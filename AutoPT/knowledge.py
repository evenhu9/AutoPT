"""
服务知识库加载模块
从 config/services.yml 动态加载服务信息，供 prompt 使用
"""

import os
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
    
    # 直接匹配
    if name in kb["services"]:
        return kb["services"][name]["port"]
    
    # 别名匹配
    for svc, info in kb["services"].items():
        if name in info.get("aliases", []):
            return info["port"]
    
    # 默认端口
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


def generate_port_mapping_text() -> str:
    """生成端口映射文本（用于 prompt）"""
    kb = load_services()
    lines = []
    for name, info in kb["services"].items():
        lines.append(f"   - {name.capitalize()} → port {info['port']}")
    return "\n".join(lines)


def generate_scan_port_table() -> str:
    """生成 scan 阶段的端口映射表"""
    kb = load_services()
    lines = []
    for name, info in kb["services"].items():
        port = info["port"]
        lines.append(f"   - {name.capitalize()} → port {port}: xray ws --url http://{{target}}:{port}")
    lines.append(f"   - Default (unknown) → port 80: xray ws --url http://{{target}}")
    return "\n".join(lines)


def generate_exploit_recon_table() -> str:
    """生成 exploit 阶段的侦察表"""
    kb = load_services()
    lines = []
    for name, info in kb["services"].items():
        port = info["port"]
        probe = info.get("probe_cmd", f"curl http://{{target}}:{port}")
        lines.append(f"- {name.capitalize()}: Port {port} → {probe}")
    return "\n".join(lines)


def generate_service_hints() -> str:
    """生成服务识别提示（用于 inquire）"""
    kb = load_services()
    lines = []
    for name, info in kb["services"].items():
        port = info["port"]
        hints = info.get("exploit_hints", "")
        lines.append(f"- {name.capitalize()}: Port {port}, {hints}")
    return "\n".join(lines)


def generate_cve_patterns() -> str:
    """生成 CVE 模式表"""
    kb = load_services()
    lines = []
    for name, info in kb["services"].items():
        patterns = ", ".join(info.get("cve_patterns", []))
        if patterns:
            lines.append(f"- {name.capitalize()}: {patterns}")
    return "\n".join(lines)


def get_cve_payload(service_name: str, cve_id: str, target_ip: str) -> Optional[str]:
    """获取 CVE 特定的利用 payload，并替换目标 IP"""
    kb = load_services()
    name = service_name.lower().strip()
    cve_id = cve_id.upper().strip()
    
    # 直接匹配
    if name in kb["services"]:
        info = kb["services"][name]
    else:
        # 别名匹配
        info = None
        for svc, svc_info in kb["services"].items():
            if name in svc_info.get("aliases", []):
                info = svc_info
                break
    
    if info and "cve_payloads" in info:
        payload = info["cve_payloads"].get(cve_id)
        if payload:
            return payload.strip().replace("{target}", target_ip)
    
    return None
