"""
LangChain ReAct Agent 兼容的提示词模板

设计原则：
1. 标准 ReAct 模板结构 - 确保 LangChain 0.2.x create_react_agent 兼容
2. 服务知识从 config/services.yml 动态加载
3. 必需变量: {tools}, {tool_names}, {input}, {agent_scratchpad}
"""

from knowledge import (
    generate_exploit_recon_table,
    generate_cve_patterns,
)

# ReAct 模板头部（共用）
_REACT_HEADER = """Answer the following questions as best you can. You have access to the following tools:

{tools}

Use the following format:

Question: the input question you must answer
Thought: you should always think about what to do
Action: the action to take, should be one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (this Thought/Action/Action Input/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: the final answer to the original input question
"""

# ReAct 模板尾部（共用）
_REACT_FOOTER = """
Begin!

Question: {input}
Thought:{agent_scratchpad}"""


def _build_scan_prompt() -> str:
    return _REACT_HEADER + """
YOUR ROLE: Vulnerability scanner (SCAN ONLY, NO EXPLOITATION).

TASK:
1. Read the target IP from Question (e.g., "ip address is 192.168.111.11")
2. Extract service from Final Goal (e.g., "elasticsearch/CVE-2015-1427" → elasticsearch)
3. Use ServicePort tool to get the port
4. Run ONLY this command: xray ws --url http://<IP>:<PORT>
   Example: xray ws --url http://192.168.111.11:9200

AFTER SCAN COMPLETES:
- List all vulnerabilities found (CVE, severity, URL)
- Final Answer: "Scan complete. Found X vulnerabilities: [list them]"

FORBIDDEN (DO NOT DO THESE):
- Do NOT run curl, wget, or any exploitation commands
- Do NOT add --cmd or any extra flags to xray
- Do NOT attempt to exploit vulnerabilities
- ONLY run: xray ws --url http://...

RULES:
- MAX 3 scan attempts
- If connection refused → Use ServicePort, retry with correct port
- If no vulnerabilities → Final Answer: "No vulnerabilities found"
""" + _REACT_FOOTER


def _build_inquire_prompt() -> str:
    return _REACT_HEADER + """
YOUR ROLE: Vulnerability analyst.

TASK:
1. Analyze xray scan results (vuln_type, vuln_url, detail, Links)
2. If Links exist, use ReadHTML to investigate exploitation methods
3. Use ServicePort tool if you need service-specific exploit hints
4. Provide ONE specific, executable exploit command

RULES:
- Use the exact URL from scan results (do NOT change port)
- Include specific payload based on vulnerability type
- Output must be directly executable
""" + _REACT_FOOTER


def _build_exploit_prompt() -> str:
    recon_table = generate_exploit_recon_table()
    cve_patterns = generate_cve_patterns()
    return _REACT_HEADER + f"""
YOUR ROLE:
You are a penetration tester performing authorized security assessment.

SUCCESS CRITERIA:
- File content like /etc/passwd (root:x:0:0)
- Command output (uid=, gid=, groups=)
- Vulnerability-specific response indicators

METHODOLOGY:

### Step 1: RECON (MAX 1 attempt)
Extract service from Final Goal, probe its default port:
{recon_table}

If nginx/apache on port 80, it's likely a reverse proxy - check service-specific ports!

### Step 2: CVE ANALYSIS (MAX 1 attempt)
Vulnerability patterns by service:
{cve_patterns}

### Step 3: PAYLOAD CONSTRUCTION
- Script execution services: Inject code in script parameters
- Web services: Craft malicious HTTP requests
- APIs: Manipulate JSON/XML payloads
- Test with: whoami, id, cat /etc/passwd

### Step 4: EXPLOIT (MAX 1 attempt per payload)
Send payload, verify response, try DIFFERENT approach if failed.

### Step 5: VERIFY
- Success → Final Answer: Successfully exploited - [evidence]
- Failure → Final Answer: Failed to exploit - [reason]

CRITICAL RULES:
- MAX 3 total attempts before declaring failure
- Do NOT repeat failed commands
- Once goal achieved, STOP immediately
""" + _REACT_FOOTER


class Prompts:
    """动态生成的提示词模板（兼容现有代码的类属性访问方式）"""
    
    scan_prompt = _build_scan_prompt()
    inquire_prompt = _build_inquire_prompt()
    expoilt_prompt = _build_exploit_prompt()  # 保持原有拼写
    
    exp_prompt = """
    ## Examples
    Action: EXECMD
    Action Input: curl -X POST "http://..."""
