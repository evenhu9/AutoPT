import re
import requests
from bs4 import BeautifulSoup

import functools
import time
from termcolor import colored
import yaml

def retry(max_retries=3, retry_delay=2):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            for i in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    print(f"发生异常：{e}")
                    if i < max_retries - 1:
                        print(f"等待 {retry_delay} 秒后重试...")
                        time.sleep(retry_delay)
                    else:
                        print("所有重试失败")
                        raise
        return wrapper
    return decorator

def cat_html(url: str) -> str:
    # 去掉引号
    url = re.sub(r'^["\']|["\']$', '', url).strip()
    
    # 检查 URL 是否有效
    if not url or '{' in url or '}' in url or 'Replace with' in url:
        return "Error: Invalid URL provided. Please provide a valid HTTP/HTTPS URL, not a placeholder."
    
    # 确保 URL 有协议头
    if not url.startswith(('http://', 'https://')):
        return "Error: URL must start with http:// or https://"
    
    try:
        # 获取 HTML 内容
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # 确保请求成功
        
        # 解析 HTML
        html_content = response.text
        soup = BeautifulSoup(html_content, "html.parser")
        
        # 提取页面上的所有文本内容
        body_content = soup.find('body')
        if body_content:
            text_content = body_content.get_text(separator="\n", strip=True)
        else:
            text_content = "No body content found"
        
        return text_content
    except requests.exceptions.RequestException as e:
        return f"Error fetching URL: {str(e)}"

    
def load_config(config_path):
    with open(config_path, 'r', encoding='utf-8') as config_stream:
        return yaml.safe_load(config_stream)

def print_AutoRT():
    ascii_art = """
     _              _             ____    _____ 
    / \     _   _  | |_    ___   |  _ \  |_   _|
   / _ \   | | | | | __|  / _ \  | |_) |   | |  
  / ___ \  | |_| | | |_  | (_) | |  __/    | |  
 /_/   \_\  \__,_|  \__|  \___/  |_|       |_|  
    """
    color = 'red'  # Set the color to red

    for line in ascii_art.splitlines():
        print(colored(line, color))