from terminal import InteractiveShell
from langchain.agents import create_react_agent, Tool, AgentExecutor
from langchain_community.agent_toolkits import PlayWrightBrowserToolkit
from langchain_community.tools.playwright.utils import (
    create_async_playwright_browser,
    create_sync_playwright_browser
)

from utils import cat_html
from knowledge import get_service_info, dynamic_discover_port
from browser_ext_tools import get_browser_ext_tools

# 保存最近一次探测到的 IP，供动态发现使用
# 由 States.problem 格式化后从外部注入（见下方说明）
_current_target_ip: str = ""

def set_target_ip(ip: str):
    """由 autopt.py 在 state_machine_run 时调用，注入靶机 IP 供动态发现使用。"""
    global _current_target_ip
    _current_target_ip = ip.strip()


def lookup_service_port(service_name: str) -> str:
    """
    查询服务对应的端口号。
    优先级：
      1. services.yml 静态查询（快，无网络开销）
      2. masscan + httpx 动态发现（YAML miss 时兜底）
      3. 默认 80
    """
    service_name = service_name.strip().lower()
    info = get_service_info(service_name)

    if info:
        # YAML 命中，直接返回
        return str(info["port"])

    # YAML miss → 动态发现
    if _current_target_ip:
        port = dynamic_discover_port(_current_target_ip, service_name)
        if port:
            return str(port)

    # 最终兜底
    return "80"


def new_terminal_tool(tools: list = None, log_callback=None) -> list:
    if tools is None:
        tools = []
    s = InteractiveShell(timeout=120)
    if log_callback:
        s.log_callback = log_callback
    tools.append(Tool(
        name="EXECMD",
        description="Execute the command in an interactive shell on your local machine (on Ubuntu 22.04 as root user, the input must be a single line without any quotes). Initially, we are in the /root/ directory.",
        func=s.execute_command
    ))
    return tools


def service_lookup_tool(tools: list = None) -> list:
    if tools is None:
        tools = []
    tools.append(Tool(
        name="ServicePort",
        description="Look up the default port for a service. Input: service name (e.g., elasticsearch, mongodb, redis). Output: port number only.",
        func=lookup_service_port
    ))
    return tools


def cat_html_tool(tools: list = None) -> list:
    if tools is None:
        tools = []
    tools.append(Tool(
        name="ReadHTML",
        description="Fetch content from URL. For GitHub vulhub links, automatically extracts PoC code blocks from README. Input: URL only (no quotes).",
        func=cat_html
    ))
    return tools


def playwright_tool(tools: list = None) -> list:
    if tools is None:
        tools = []
    sync_browser = create_sync_playwright_browser()
    toolkit = PlayWrightBrowserToolkit.from_browser(sync_browser=sync_browser)
    tools += toolkit.get_tools()
    # 注入自定义浏览器扩展工具（fill_element、select_option、wait_for_selector）
    # 共享同一个 sync_browser 实例，确保与 Toolkit 工具操作同一个浏览器上下文
    tools += get_browser_ext_tools(sync_browser=sync_browser)
    return tools