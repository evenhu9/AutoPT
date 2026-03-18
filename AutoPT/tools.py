"""
工具定义 - 适配本地执行模式
为LangChain Agent提供工具集
"""
from terminal import InteractiveShell
from langchain.agents import Tool
from langchain_community.agent_toolkits import PlayWrightBrowserToolkit
from langchain_community.tools.playwright.utils import create_async_playwright_browser
from utils import cat_html


def new_terminal_tool(tools: list = None, timeout: int = 120, xray_path: str = None) -> list:
    """
    创建本地命令执行工具。
    所有命令直接在本地机器上执行，无需SSH连接。
    """
    if tools is None:
        tools = []
    s = InteractiveShell(timeout=timeout, xray_path=xray_path)
    tools.append(Tool(
        name="EXECMD",
        description="在本地机器上执行命令（支持Windows/Linux，以当前用户权限运行）。输入必须是单行命令，不要包含引号包裹。",
        func=s.execute_command
    ))
    return tools


def cat_html_tool(tools: list = None) -> list:
    """创建HTML内容提取工具"""
    if tools is None:
        tools = []
    tools.append(Tool(
        name="ReadHTML",
        description="从指定URL提取HTML页面中的文本内容。输入必须是有效的HTTP/HTTPS URL，不要包含引号。",
        func=cat_html
    ))
    return tools


def playwright_tool(tools: list = None) -> list:
    """创建Playwright浏览器自动化工具集"""
    if tools is None:
        tools = []
    try:
        async_browser = create_async_playwright_browser()
        toolkit = PlayWrightBrowserToolkit.from_browser(async_browser=async_browser)
        tools += toolkit.get_tools()
    except Exception as e:
        print(f"[WARNING] Playwright工具初始化失败: {e}")
        print("[INFO] 浏览器自动化功能将不可用，但不影响其他功能")
    return tools
