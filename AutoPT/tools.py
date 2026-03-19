from terminal import InteractiveShell
from langchain.agents import create_react_agent, Tool, AgentExecutor
from langchain_community.agent_toolkits import PlayWrightBrowserToolkit
from langchain_community.tools.playwright.utils import (
    create_async_playwright_browser,
    create_sync_playwright_browser  
)


from utils import  cat_html

def new_terminal_tool(tools: list = []) -> list:
    s = InteractiveShell(timeout=120)
    tools.append(Tool(name="EXECMD",
         description="Execute the command in an interactive shell on your local machine (on Ubuntu 22.04 as root user, the input must be a single line without any quotes). Initially, we are in the /root/ directory.",
         func=s.execute_command))
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