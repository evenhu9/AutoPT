import re
import requests
import json
from urllib.parse import unquote
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
    # 规范化并尝试提取第一个可用 URL，避免模型把说明文字拼到 Action Input
    url = re.sub(r'^["\']|["\']$', '', url).strip()
    url = unquote(url)

    # 如果输入包含说明文字，先提取第一个 URL 片段
    url_match = re.search(r'https?://[^\s\]\)\"\']+', url, re.IGNORECASE)
    if url_match:
        url = url_match.group(0).rstrip('.,;')
    
    lower_url = url.lower()

    # 检查 URL 是否有效（含占位符/模板化文本）
    placeholder_tokens = [
        'replace with actual url',
        'insert url here',
        'placeholder',
        'since i cannot access',
        'please provide a valid url',
        'xray scan results if available',
    ]
    if not url or '{' in url or '}' in url or any(token in lower_url for token in placeholder_tokens):
        return "Error: Invalid URL provided. Please provide a valid HTTP/HTTPS URL, not a placeholder."
    
    # 确保 URL 有协议头
    if not url.startswith(('http://', 'https://')):
        return "Error: URL must start with http:// or https://"
    
    # GitHub URL 特殊处理：转换为 raw.githubusercontent.com 获取 README.md
    github_tree_match = re.match(r'https?://github\.com/([^/]+)/([^/]+)/tree/([^/]+)/(.+)', url)
    github_blob_match = re.match(r'https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)', url)
    
    if github_tree_match:
        # GitHub 目录页面，尝试获取 README.md
        owner, repo, branch, path = github_tree_match.groups()
        raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}/README.md"
        # 也尝试 README.zh-cn.md（vulhub 有中文版）
        alt_urls = [
            raw_url,
            f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}/README.zh-cn.md",
        ]
        for try_url in alt_urls:
            try:
                response = requests.get(try_url, timeout=15)
                if response.status_code == 200:
                    return _extract_poc_from_readme(response.text)
            except:
                continue
        return f"Error: Could not fetch README from GitHub path {path}"
    
    if github_blob_match:
        # GitHub 文件页面，转换为 raw URL
        owner, repo, branch, path = github_blob_match.groups()
        url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
    
    try:
        # 获取内容
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, timeout=15, headers=headers)
        response.raise_for_status()

        content_type = (response.headers.get('Content-Type') or '').lower()
        text = response.text or ""

        # JSON API response (e.g., Elasticsearch 9200 root endpoint)
        if 'application/json' in content_type or text.strip().startswith('{'):
            try:
                obj = response.json()
                if isinstance(obj, dict):
                    summary = {
                        'status': response.status_code,
                        'name': obj.get('name'),
                        'cluster_name': obj.get('cluster_name'),
                        'version': (obj.get('version') or {}).get('number') if isinstance(obj.get('version'), dict) else None,
                        'tagline': obj.get('tagline'),
                    }
                    return json.dumps(summary, ensure_ascii=False)
            except Exception:
                pass

        # Markdown 文件（如 GitHub raw README）
        if url.endswith('.md') or 'text/plain' in content_type:
            return _extract_poc_from_readme(text)

        # Non-HTML response fallback
        if 'text/html' not in content_type and '<html' not in text[:200].lower():
            return text[:2000] if text else f"HTTP {response.status_code} with empty body"
        
        # 解析 HTML
        html_content = text
        soup = BeautifulSoup(html_content, "html.parser")
        
        body_content = soup.find('body')
        if body_content:
            text_content = body_content.get_text(separator="\n", strip=True)
        else:
            text_content = f"HTTP {response.status_code}, non-body response"
        
        return text_content[:3000]
    except requests.exceptions.RequestException as e:
        return f"Error fetching URL: {str(e)}"


def _extract_poc_from_readme(text: str) -> str:
    """从 README 中提取 PoC 相关内容"""
    lines = text.split('\n')
    result = []
    in_code_block = False
    code_blocks = []
    current_block = []
    
    for line in lines:
        # 检测代码块
        if line.strip().startswith('```'):
            if in_code_block:
                # 结束代码块
                code_blocks.append('\n'.join(current_block))
                current_block = []
            in_code_block = not in_code_block
            continue
        
        if in_code_block:
            current_block.append(line)
        else:
            # 保留标题和关键描述
            lower_line = line.lower()
            if any(kw in lower_line for kw in ['poc', 'exploit', 'payload', 'curl', 'http', 'vulnerability', '漏洞', '利用', '复现']):
                result.append(line)
    
    # 组合输出：关键描述 + 所有代码块
    output = '\n'.join(result[:10])  # 最多10行描述
    if code_blocks:
        output += '\n\n=== CODE BLOCKS (PoC) ===\n'
        for i, block in enumerate(code_blocks[:5], 1):  # 最多5个代码块
            output += f"\n--- Block {i} ---\n{block}\n"
    
    return output if output.strip() else text[:2000]

    
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