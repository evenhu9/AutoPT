"""
服务知识库加载模块
从 config/services.yml 动态加载服务信息，供 prompt 使用

改动说明：
- 端口发现逻辑已合并到 scan agent 的提示词中，由 LLM 直接通过 EXECMD 执行 nmap
- 本模块仅保留 services.yml 加载和 CVE 模式生成功能（用于 exploit prompt 中的服务模式提示）
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


def get_service_info(service_name: str) -> Optional[dict]:
    """获取服务完整信息（仅用于 CVE 模式等辅助信息）"""
    kb = load_services()
    name = service_name.lower().strip()

    if name in kb["services"]:
        return kb["services"][name]

    for svc, info in kb["services"].items():
        if name in info.get("aliases", []):
            return info

    return None


def generate_cve_patterns() -> str:
    kb = load_services()
    lines = []
    for name, info in kb["services"].items():
        patterns = ", ".join(info.get("cve_patterns", []))
        if patterns:
            lines.append(f"- {name.capitalize()}: {patterns}")
    return "\n".join(lines)