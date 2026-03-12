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
1. Extract service name and CVE ID from the vulnerability info (e.g., "elasticsearch", "CVE-2015-1427")
2. Extract target IP from the vuln_url (e.g., "http://192.168.111.11:9200" → "192.168.111.11")
3. Use CVEPayload tool to get the exploit command: Input format is "service CVE-ID target_ip"
   Example: CVEPayload elasticsearch CVE-2015-1427 192.168.111.11
4. If CVEPayload returns no result, use ReadHTML on Links to investigate

OUTPUT:
- Provide the exact exploit command from CVEPayload
- If no CVEPayload available, provide a manually crafted command based on research

RULES:
- Always try CVEPayload tool FIRST before ReadHTML
- Output must be directly executable (no placeholders)
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

### Step 1: GET EXPLOIT COMMAND (REQUIRED FIRST STEP)
Use CVEPayload tool to get the exact exploit command:
- Input format: "service CVE-ID target_ip"
- Example: CVEPayload elasticsearch CVE-2015-1427 192.168.111.11
- Extract service/CVE from Final Goal, IP from previous scan results

### Step 2: EXECUTE PAYLOAD
Run the command returned by CVEPayload using EXECMD tool.

### Step 3: VERIFY RESULT
- If output contains expected content (e.g., root:x:0:0) → Success
- If failed → Try modifying the payload slightly, MAX 3 attempts

### Step 4: FINAL ANSWER
- Success → Final Answer: Successfully exploited - [evidence]
- Failure → Final Answer: Failed to exploit - [reason]

FALLBACK (only if CVEPayload returns no result):
Service-specific patterns:
{cve_patterns}

CRITICAL RULES:
- ALWAYS use CVEPayload tool FIRST to get exploit command
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
