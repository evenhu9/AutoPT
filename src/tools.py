"""
tools.py - Agent 工具集

改动说明：
- Scan Agent 直接通过 EXECMD 执行 nmap 进行端口发现，无需单独的端口扫描工具
- 端口发现逻辑完全由 scan agent 的提示词驱动，保持架构简洁
"""

from terminal import InteractiveShell
from langchain.agents import create_react_agent, Tool, AgentExecutor
from langchain_community.agent_toolkits import PlayWrightBrowserToolkit
from langchain_community.tools.playwright.utils import (
    create_async_playwright_browser,
    create_sync_playwright_browser
)

from utils import cat_html
from browser_ext_tools import get_browser_ext_tools


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