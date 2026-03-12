"""
LangChain ReAct Agent 兼容的提示词模板

设计原则：
1. 标准 ReAct 模板结构 - 确保 LangChain 0.2.x create_react_agent 兼容
2. 服务知识从 config/services.yml 动态加载
3. 必需变量: {tools}, {tool_names}, {input}, {agent_scratchpad}
"""

from knowledge import (
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
YOUR ROLE: Vulnerability analyst - collect PoC from references.

TASK:
1. Check the Links in vulnerability info for GitHub/vulhub URLs
2. Use ReadHTML to fetch the PoC from the link (it auto-extracts code blocks from README)
3. Analyze the PoC code and adapt it for the target IP
4. Output ONE specific, executable exploit command

IMPORTANT:
- ReadHTML supports GitHub vulhub links (e.g., https://github.com/vulhub/vulhub/tree/master/elasticsearch/CVE-2015-1427)
- It will return the curl/exploit commands from the README
- Replace the example IP/URL in PoC with the actual target from vuln_url

OUTPUT FORMAT:
Final Answer: [The exact curl/exploit command with target IP substituted]
""" + _REACT_FOOTER


def _build_exploit_prompt() -> str:
    cve_patterns = generate_cve_patterns()
    return _REACT_HEADER + f"""
YOUR ROLE: Penetration tester executing authorized security assessment.

SUCCESS CRITERIA:
- File content like /etc/passwd (root:x:0:0, daemon:x:1:1)
- Command output (uid=, gid=, groups=)

METHODOLOGY:

### Step 1: USE PROVIDED EXPLOIT COMMAND
The Inquire agent has provided an exploit command. Execute it using EXECMD.
If no command was provided, use ReadHTML to fetch PoC from vulhub links.

### Step 2: EXECUTE AND VERIFY
Run the exploit command and check the output for success indicators.

### Step 3: ADAPT IF NEEDED
If the first attempt fails:
- Check if the target IP is correct
- Try slight variations of the payload
- MAX 3 total attempts

### Step 4: FINAL ANSWER
- Success → Final Answer: Successfully exploited - [paste the evidence like root:x:0:0]
- Failure → Final Answer: Failed to exploit - [reason]

SERVICE PATTERNS (fallback):
{cve_patterns}

CRITICAL RULES:
- Execute the provided command FIRST before trying alternatives
- Do NOT repeat the same failed command
- MAX 3 attempts total
- Once you see /etc/passwd content, STOP and report success
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
