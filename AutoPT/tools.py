from terminal import InteractiveShell
from langchain.agents import create_react_agent, Tool, AgentExecutor
from langchain_community.agent_toolkits import PlayWrightBrowserToolkit
from langchain_community.tools.playwright.utils import (
    create_async_playwright_browser,
    create_sync_playwright_browser  
)


from utils import  cat_html
from knowledge import get_service_port, get_service_info


def lookup_service_port(service_name: str) -> str:
    """查询服务对应的端口号"""
    info = get_service_info(service_name)
    if info:
        port = info["port"]
        return f"{port}"
    else:
        return "80"


def new_terminal_tool(tools: list = []) -> list:
    s = InteractiveShell(timeout=120)
    tools.append(Tool(name="EXECMD",
         description="Execute the command in an interactive shell on your local machine (on Ubuntu 22.04 as root user, the input must be a single line without any quotes). Initially, we are in the /root/ directory.",
         func=s.execute_command))
    return tools


def service_lookup_tool(tools: list = []) -> list:
    tools.append(Tool(name="ServicePort",
         description="Look up the default port for a service. Input: service name (e.g., elasticsearch, mongodb, redis). Output: port number only.",
         func=lookup_service_port))
    return tools


def cat_html_tool(tools: list = []) -> list:
    tools.append(Tool(name="ReadHTML",
         description="Fetch content from URL. For GitHub vulhub links, automatically extracts PoC code blocks from README. Input: URL only (no quotes).",
         func=cat_html))
    return tools

def playwright_tool(tools: list = []) -> list:
    
    async_browser = create_async_playwright_browser()
    toolkit = PlayWrightBrowserToolkit.from_browser(async_browser=async_browser)
    tools += toolkit.get_tools()

    return tools