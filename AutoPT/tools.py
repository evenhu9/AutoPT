from terminal import InteractiveShell
from langchain.agents import create_react_agent, Tool, AgentExecutor
from langchain_community.agent_toolkits import PlayWrightBrowserToolkit
from langchain_community.tools.playwright.utils import (
    create_async_playwright_browser,
    create_sync_playwright_browser  
)


from utils import  cat_html
from knowledge import get_service_port, get_service_info, get_cve_payload


def lookup_service_port(service_name: str) -> str:
    """查询服务对应的端口号"""
    info = get_service_info(service_name)
    if info:
        port = info["port"]
        hints = info.get("exploit_hints", "")
        return f"{port}"
    else:
        return "80"


def lookup_cve_payload(query: str) -> str:
    """查询 CVE 利用 payload，输入格式: service CVE-ID target_ip"""
    parts = query.split()
    if len(parts) < 3:
        return "Error: Input format should be 'service CVE-ID target_ip', e.g., 'elasticsearch CVE-2015-1427 192.168.111.11'"
    
    service = parts[0]
    cve_id = parts[1]
    target_ip = parts[2]
    
    payload = get_cve_payload(service, cve_id, target_ip)
    if payload:
        return payload
    else:
        return f"No payload found for {service} {cve_id}. Try manual exploitation."


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


def cve_payload_tool(tools: list = []) -> list:
    tools.append(Tool(name="CVEPayload",
         description="Get the exploit payload for a specific CVE. Input format: 'service CVE-ID target_ip' (e.g., 'elasticsearch CVE-2015-1427 192.168.111.11'). Output: ready-to-execute curl command.",
         func=lookup_cve_payload))
    return tools

def cat_html_tool(tools: list = []) -> list:
    tools.append(Tool(name="ReadHTML",
         description="Extracts paragraph elements from the HTML content of the specified URL. Do not enter any quotation marks or enclosed characters.",
         func=cat_html))
    return tools

def playwright_tool(tools: list = []) -> list:
    
    async_browser = create_async_playwright_browser()
    toolkit = PlayWrightBrowserToolkit.from_browser(async_browser=async_browser)
    tools += toolkit.get_tools()

    return tools