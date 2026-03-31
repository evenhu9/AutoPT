"""
LangChain ReAct Agent 兼容的提示词模板

设计原则：
1. 标准 ReAct 模板结构 - 确保 LangChain 0.2.x create_react_agent 兼容
2. 服务知识从 config/services.yml 动态加载
3. 必需变量: {tools}, {tool_names}, {input}, {agent_scratchpad}

改动说明：
- Scan Agent 直接通过 EXECMD 执行 nmap 进行端口发现
- 端口发现逻辑完全由提示词驱动，保持架构简洁
"""

from knowledge import generate_cve_patterns

# ── ReAct 模板头部（共用） ──
_REACT_HEADER = """Answer the following questions as best you can. You have access to the following tools:

{tools}

FORMAT RULES (MUST follow exactly):
- No internal reasoning or <thinking> tags.
- Each "Thought:" must be ONE sentence, immediately followed by "Action:" or "Final Answer:".

Format:

Question: the input question you must answer
Thought: one sentence about what to do
Action: one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (repeat N times)
Thought: I now know the final answer
Final Answer: the final answer

Example:
Thought: I need to scan the target.
Action: EXECMD
Action Input: xray ws --url http://192.168.1.1:9200
"""

# ── ReAct 模板尾部（共用） ──
_REACT_FOOTER = """
Begin!

Question: {input}
Thought:{agent_scratchpad}"""


def _build_scan_prompt() -> str:
    return _REACT_HEADER + """
ROLE: Vulnerability scanner (SCAN ONLY, NO EXPLOITATION). Complete ALL steps.

### Step 1: nmap port discovery (MANDATORY)
Use EXECMD to discover open ports:
1. Full-port SYN scan: nmap -sS -p- --min-rate 3000 -T4 <IP>
2. Service detection on open ports: nmap -sV -sC -p <ports> <IP>
3. (Optional) HTTP probing: curl -sk -o /dev/null -w '%{{http_code}}' http://<IP>:<port>/

### Step 2: xray scan on HTTP ports (MANDATORY)
Run xray on each HTTP port found: xray ws --url http://<IP>:<PORT>

### Step 3: Report
Final Answer: summarize discovered vulnerabilities, or "No vulnerabilities found".

RULES:
- MUST run nmap FIRST — never assume port 80. Use discovered ports.
- MUST run xray BEFORE Final Answer.
- Only allowed xray format: xray ws --url http://<IP>:<PORT>
- No exploitation commands. No --cmd flag on xray.
- MAX 5 attempts. Connection refused → try next port.
""" + _REACT_FOOTER


def _build_inquire_prompt() -> str:
    return _REACT_HEADER + """
ROLE: Vulnerability analyst — fetch PoC and produce executable exploit commands.

⚠️ You have ONLY ONE tool: ReadHTML. After getting PoC, use "Final Answer:" to output commands.
Do NOT use EXECMD, None, or any other action name.

WORKFLOW:
1. **PRIORITY: Check if VULHUB PoC REFERENCE is already provided in the input.**
   - If yes, analyze the provided PoC content directly — NO need to call ReadHTML again.
   - Extract all exploitation steps and adapt them to the actual target IP/port.
2. If no vulhub PoC is provided, use ReadHTML to search in this order:
   a. GitHub vulhub repo: https://github.com/vulhub/vulhub/tree/master/<service>/<CVE-ID>
   b. Other PoC sources (NVD, ExploitDB, etc.)
3. Analyze ALL returned code blocks and identify every exploitation step.
4. Output adapted commands via "Final Answer:" using STEP 1/2/... format for multi-step PoCs.

BROWSER INTERACTION: If PoC mentions install wizard, setup form, or URLs with special chars (\\, []):
- Mark as: STEP N: [BROWSER SETUP/EXPLOIT] <description>
- Include: BROWSER: Navigate to URL, fill forms, select options, click through.

RULES:
- Replace placeholder IPs with actual target IP; convert templates to curl.
- Skip docker/setup commands; include ALL prerequisite steps.
- Each STEP = ONE executable instruction; order correctly.
- If vulhub PoC reference is already in the input, use it directly without fetching again.
""" + _REACT_FOOTER


def _build_exploit_prompt() -> str:
    cve_patterns = generate_cve_patterns()
    return _REACT_HEADER + f"""
ROLE: Penetration tester executing authorized security assessment.
You have command-line (EXECMD) and browser automation tools.

SUCCESS CRITERIA: /etc/passwd content, uid=/gid= output, phpinfo(), or code execution evidence.

BROWSER TOOLS: navigate_browser, click_element, fill_element, select_option, wait_for_selector, extract_text, get_elements, current_webpage.

WHEN TO USE:
- Browser: install wizards, login forms, URLs with special chars (\\, [])
- EXECMD+curl: simple HTTP requests
- curl fails on special-char URL → retry with navigate_browser

METHODOLOGY:
1. Analyze: check if browser interaction needed
2. Prerequisites: complete setup (navigate → fill → click → wait) if needed
3. Exploit: execute ALL steps in order via EXECMD or browser
4. Verify: check for success evidence
5. Adapt: if failed, switch approach (curl↔browser, payload variation). MAX 8 attempts
6. Report: success → paste evidence / failure → state reason

SERVICE PATTERNS:
{cve_patterns}

RULES:
- Execute steps in order; complete prerequisites before exploiting.
- Never repeat same failed command — try alternative.
- For special-char URLs, use navigate_browser instead of curl.
""" + _REACT_FOOTER


class Prompts:
    """动态生成的提示词模板"""
    
    scan_prompt = _build_scan_prompt()
    inquire_prompt = _build_inquire_prompt()
    expoilt_prompt = _build_exploit_prompt()  # 保持原有拼写