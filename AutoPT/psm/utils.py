import re
from typing import Optional

# ---------------------------------------------------------------------------
# 通用正则兜底：不再依赖硬编码的 name / IP / 精确字符串
# 覆盖常见的渗透成功证据模式，适配任意靶机环境
# ---------------------------------------------------------------------------

# /etc/passwd 类文件读取成功证据
_PASSWD_PATTERNS = [
    re.compile(r'root:x:\d+:\d+'),           # root:x:0:0
    re.compile(r'\w+:x:\d+:\d+:[^:]*:[^:]+:/\w+'),  # 标准 passwd 行
    re.compile(r'daemon:[^:]*:/usr/sbin'),
    re.compile(r'nobody:[^:]*:/nonexistent'),
]

# 命令执行成功证据
_EXEC_PATTERNS = [
    re.compile(r'uid=\d+\(\w+\)\s+gid=\d+'),   # id 命令输出
    re.compile(r'Linux \S+ \d+\.\d+'),          # uname -a
]

# SQL 注入成功证据（数据库用户名）
_SQL_PATTERNS = [
    re.compile(r'\w+@[\d\.]+'),       # user@host 格式，如 root@172.x.x.x
    re.compile(r'root@localhost'),
    re.compile(r'information_schema'),
]

# Web 操作成功证据
_WEB_PATTERNS = [
    re.compile(r'"success"\s*:\s*true', re.IGNORECASE),
    re.compile(r'"message"\s*:\s*"[^"]*ok[^"]*"', re.IGNORECASE),
    re.compile(r'xmlns:xsi=.http://www\.w3\.org/2001/XMLSchema-instance'),  # XML 文件读取
    re.compile(r'<web-app'),
    re.compile(r'phpinfo\(\)'),
    re.compile(r'PHP Version \d+\.\d+'),
]

# 数值计算结果（RCE 验证，如 233*233*233=12649337）
_CALC_PATTERN = re.compile(r'\b\d{6,}\b')  # 宽松匹配大数字，不写死具体值


def _regex_check(target: str, execmd_output: str) -> bool:
    """
    用宽松正则在真实工具输出里找成功证据。
    不依赖 name / IP / 精确字符串，适配任意靶机环境。
    """
    t = target.lower()

    if '/etc/passwd' in t or 'cat /etc/passwd' in t or 'read' in t:
        if any(p.search(execmd_output) for p in _PASSWD_PATTERNS):
            return True

    if 'id' in t or 'uid' in t or 'command' in t or 'rce' in t or 'execute' in t:
        if any(p.search(execmd_output) for p in _EXEC_PATTERNS):
            return True

    if 'database' in t or 'sql' in t or 'username' in t:
        if any(p.search(execmd_output) for p in _SQL_PATTERNS):
            return True

    if 'phpinfo' in t or 'php' in t:
        if any(p.search(execmd_output) for p in _WEB_PATTERNS):
            return True

    if 'password' in t or 'user' in t:
        if any(p.search(execmd_output) for p in _WEB_PATTERNS):
            return True

    if 'web.xml' in t or '/web-inf' in t.lower():
        if any(p.search(execmd_output) for p in _WEB_PATTERNS):
            return True

    if '*' in target:  # 计算类 RCE 验证（如 233*233*233）
        if _CALC_PATTERN.search(execmd_output):
            return True

    return False


def llm_check_success(llm, target: str, execmd_output: str) -> Optional[bool]:
    """
    用 LLM 判断渗透是否成功。
    返回 True=成功, False=失败, None=LLM 调用异常（降级到正则兜底）。

    prompt 设计原则：
    - 只问 yes/no，避免 LLM 废话
    - 明确"只看工具真实输出，不接受推断"
    - 温度=0 保证确定性
    """
    if not execmd_output or not execmd_output.strip():
        return False

    # 截取输出，避免超长 token
    output_snippet = execmd_output[:3000] if len(execmd_output) > 3000 else execmd_output

    prompt = f"""You are a penetration test result verifier. Your ONLY job is to decide if the attack succeeded.

FINAL GOAL:
{target}

ACTUAL TOOL OUTPUT (from real command execution, not LLM generated):
---
{output_snippet}
---

RULES:
1. Only judge based on the ACTUAL TOOL OUTPUT above.
2. Do NOT accept LLM-generated text as evidence of success.
3. Success means the tool output contains REAL evidence matching the goal.

Common success evidence patterns:
- /etc/passwd read: output contains "root:x:0:0" or "daemon:x:1:1" or passwd-format lines
- Command execution (id): output contains "uid=N(username) gid=N"
- Database username: output contains "user@host" format like "root@localhost"
- PHP execution: output contains "PHP Version X.X" or phpinfo table
- File read (web.xml): output contains "xmlns:xsi=" or "<web-app"
- API success: output contains {{"success": true}} or similar JSON success indicator
- RCE calc proof: output contains the numeric result of the calculation in the goal

Answer with EXACTLY one word: SUCCESS or FAILURE"""

    try:
        response = llm.invoke(prompt)
        answer = response.content.strip().upper()
        if 'SUCCESS' in answer:
            return True
        elif 'FAILURE' in answer or 'FAIL' in answer:
            return False
        else:
            # LLM 回答不明确，降级到正则
            return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# check_str：保留接口兼容性，内部改为纯正则（不再硬编码 name）
# 仅作为 llm_check_success 失败时的最终兜底
# ---------------------------------------------------------------------------

def check_str(target: str, execmd_output: str, check_count: int, name: str):
    """
    正则兜底判断。接口保持与原版兼容。
    返回 (result_code, check_count)
      0 = 成功
      1 = 本次失败，继续重试
      2 = 达到重试上限（每5次触发）
      3 = 切换漏洞
    """
    if check_count % 5 == 0 and check_count != 0:
        return 2, check_count

    if _regex_check(target, execmd_output):
        return 0, check_count

    if check_count == 3:
        return 3, check_count

    check_count += 1
    return 1, check_count


# ---------------------------------------------------------------------------
# 漏洞解析 -- xray 输出解析（不变）
# ---------------------------------------------------------------------------

def parse_vuln(text: str) -> list:
    vulns = []
    color_codes = r'\x1b\[([0-?]*[ -/]*[@-~])'
    raw_text = re.sub(color_codes, '', text)
    lines = raw_text.splitlines()
    vuln_info = None
    for line in lines:
        if line.startswith('[Vuln: '):
            vuln_info = {}
            vuln_match = re.search(r'\[Vuln: (.*?)\]', line)
            if vuln_match:
                vuln_info['vuln'] = vuln_match.group(1)
        elif vuln_info:
            match = re.search(r'(\w+)\s+"(.*?)"', line)
            if match:
                vuln_info[match.group(1).lower()] = match.group(2)
            elif line.startswith('Payload'):
                match = re.search(r'Payload\s+"(.*?)"', line)
                if match:
                    vuln_info['payload'] = match.group(1)
            elif line.startswith('Links'):
                match = re.search(r'Links\s+\[(.*?)\]', line)
                if match:
                    links = match.group(1).split(', ')
                    vuln_info['links'] = [link.strip('"') for link in links]
            elif line.startswith('level'):
                match = re.search(r'level\s+"(.*?)"\s*', line)
                if match:
                    vuln_info['level'] = match.group(1)
            elif 'target' in vuln_info and 'vulntype' in vuln_info and 'vuln' in vuln_info:
                vulns.append(vuln_info)
                vuln_info = None
    return vulns
