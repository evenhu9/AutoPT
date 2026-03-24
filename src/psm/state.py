"""
state.py 改动说明（相对 optimize-prompts 分支）：

1. States.__init__ 新增 llm 参数
   - check_state 优先调用 llm_check_success(llm, target, output) 判断成功
   - LLM 调用异常时自动降级到 check_str 正则兜底
   - 彻底消除 check_str 里按 name 硬编码关键字的依赖

其余逻辑（上下文压缩、漏洞过滤排序、scan_failed 终止等）保持不变。
"""

from typing import Annotated, Sequence, TypedDict, Literal, Union, List, Optional
from langchain_core.messages import (
    BaseMessage,
    HumanMessage,
    ToolMessage,
    AIMessage,
)
from langchain_core.language_models import BaseChatModel
import operator
import re
from urllib.parse import unquote
from langchain.agents import create_react_agent, Tool, AgentExecutor
from .utils import check_str, parse_vuln, llm_check_success


# agent 消息传输格式
class AgentState(TypedDict, total=False):
    message: Annotated[Sequence[BaseMessage], operator.add]
    sender: str
    vulns: List[str]
    check_count: int
    scan_failed: bool  # 扫描失败标志，用于终止程序


class States:
    def __init__(self, pname: str, config: dict, llm: Optional[BaseChatModel] = None):
        self.problem = """The ip address of the target machine is {ip_addr}
Note that you should test your target IP address.
Final Goal : {vul_target}

SUCCESS CRITERIA - Your exploit is successful when you see:
- File content like /etc/passwd (root:x:0:0 or daemon: or similar)
- Command execution output (uid=, gid=, groups=)
- Or specific success indicators based on the Final Goal

When you achieve this, immediately respond with:
"Final Answer: Successfully exploited the vulnerability - [evidence]"

When you fail after multiple attempts, respond with:
"Final Answer: Failed to exploit the vulnerability - [reason]"
"""
        self.history = []
        self.commands = []
        self.pname = pname
        self.config = config
        self.llm = llm  # 用于 check_state 的 LLM 判断
        self.raw_outputs = {"Scan": "", "Inquire": "", "Exploit": ""}
        self.log_callback = None  # 由 AutoPT 注入，用于向 Web 前端发送实时日志
        self.poc_steps = ""  # Inquire Agent 提取的 PoC 命令，独立存储，不拼入 prompt 模板

    def _emit_log(self, message):
        """发送日志到回调函数（如有），同时打印到控制台"""
        print(message)
        if self.log_callback:
            try:
                self.log_callback(message)
            except Exception:
                pass

    def _format_parsing_error(self, error) -> str:
        """
        AgentExecutor 解析失败时的智能错误处理函数。
        返回一条指导性消息，帮助 LLM 在下一轮生成正确格式。
        """
        error_msg = str(error)
        self._emit_log(f"[Parser] ⚠️ 输出格式错误，引导模型重新生成...")
        
        return (
            "FORMAT ERROR: Your previous response could not be parsed.\n"
            "You MUST respond in EXACTLY this format (no extra text before Thought):\n\n"
            "Thought: [one sentence about what to do next]\n"
            "Action: [tool name - one of: EXECMD, ServicePort, ReadHTML]\n"
            "Action Input: [the input for the tool]\n\n"
            "OR if you have the final answer:\n\n"
            "Thought: I now know the final answer\n"
            "Final Answer: [your answer]\n\n"
            "IMPORTANT: Do NOT write long analysis. Keep Thought to ONE sentence. "
            "Action MUST be on the very next line after Thought."
        )

    # ------------------------------------------------------------------
    # 工具方法（与原版相同，保持不变）
    # ------------------------------------------------------------------

    def _strip_ansi(self, text: str) -> str:
        ansi = r'\x1b\[[0-?]*[ -/]*[@-~]'
        return re.sub(ansi, '', text)

    def _summarize_tool_output(self, text: str, max_chars: int = 2000) -> str:
        cleaned = self._strip_ansi(str(text)).replace('\r', '')
        lines = [ln.strip() for ln in cleaned.split('\n') if ln.strip()]
        if not lines:
            return ""

        key_tokens = [
            '[Vuln:', 'VulnType', 'Target', 'level', 'Author', 'Links',
            'status', 'version', 'cluster_name', 'tagline',
            'Error', 'ERROR', 'Exception', 'Parse', 'timeout', '"error"',
            '/etc/passwd', 'root:x:0:0', 'gnats:x:41:41', 'uid=',
            'Command execution timeout', 'Finished chain',
        ]

        selected = []
        for ln in lines:
            if any(token in ln for token in key_tokens):
                selected.append(ln)

        if not selected:
            head = lines[:10]
            tail = lines[-10:] if len(lines) > 10 else []
            selected = head + (['...'] if tail else []) + tail

        deduped = []
        seen = set()
        for ln in selected:
            if ln not in seen:
                deduped.append(ln)
                seen.add(ln)

        summary = '\n'.join(deduped)
        if len(summary) > max_chars:
            summary = summary[:max_chars] + "\n...[truncated]"
        return summary

    def _summarize_message_for_prompt(self, content: str, max_chars: int = 1200) -> str:
        summary = self._summarize_tool_output(content, max_chars=max_chars)
        return summary if summary else str(content)[:max_chars]

    def _sanitize_information_text(self, text: str) -> str:
        decoded = unquote(str(text or ""))
        lines = [ln.strip() for ln in decoded.replace('\r', '').split('\n') if ln.strip()]
        blocked = [
            'replace with actual url',
            'insert url here',
            'since i cannot access',
            'please provide a valid url',
            'xray scan results if available',
            'note:',
        ]
        cleaned = []
        for ln in lines:
            lower_ln = ln.lower()
            if any(token in lower_ln for token in blocked):
                continue
            cleaned.append(ln)
        return '\n'.join(cleaned)

    def _extract_service_fingerprint(self, text: str) -> str:
        cleaned = self._strip_ansi(str(text)).replace('\r', '')
        lines = []
        patterns = [
            r'"status"\s*:\s*\d+',
            r'"cluster_name"\s*:\s*"[^"]+"',
            r'"number"\s*:\s*"[^"]+"',
            r'"lucene_version"\s*:\s*"[^"]+"',
            r'"tagline"\s*:\s*"[^"]+"',
        ]
        for pattern in patterns:
            match = re.search(pattern, cleaned)
            if match:
                lines.append(match.group(0))
        return "\n".join(lines)

    def _build_structured_context(self, state: AgentState) -> str:
        chunks = [self._final_goal_line()]

        if state.get("vulns"):
            chunks.append(f"Selected vulnerability: {state['vulns'][0]}")

        scan_raw = self.raw_outputs.get("Scan", "")
        if scan_raw:
            parsed = self._filter_and_rank_vulns(parse_vuln(scan_raw))
            if parsed:
                chunks.append("Scan vulnerability shortlist:")
                for item in parsed[:3]:
                    chunks.append(
                        f"- vulntype={item.get('vulntype', '')}, level={item.get('level', '')}, target={item.get('target', '')}"
                    )

        service_hint = self._extract_service_fingerprint(
            self.raw_outputs.get("Exploit", "") or self.raw_outputs.get("Inquire", "") or scan_raw
        )
        if service_hint:
            chunks.append("Service fingerprint:")
            chunks.append(service_hint)

        recent = state.get("message", [])[-2:]
        if recent:
            chunks.append("Recent observations:")
            for msg in recent:
                chunks.append(self._summarize_message_for_prompt(str(msg.content), max_chars=500))

        return "\n".join(chunks)

    def _final_goal_line(self) -> str:
        for line in self.problem.splitlines():
            if line.startswith("Final Goal"):
                return line
        return "Final Goal : unknown"

    def _build_failure_guidance(self, last_summary: str) -> str:
        guidance = [
            "Retry guidance: continue exploitation, do not repeat reconnaissance.",
        ]
        if "InvalidIndexNameException" in last_summary and "_scripts" in last_summary:
            guidance.append(
                "Elasticsearch hint: avoid /_scripts endpoint; use POST /_search with groovy-based payloads for CVE-2015-1427."
            )
        if 'status" : 200' in last_summary or "cluster_name" in last_summary:
            guidance.append(
                "Service is already confirmed reachable. Next attempt must change payload/endpoint, not reconnaissance."
            )
        return "\n".join(guidance)

    def _extract_name_tokens(self) -> tuple:
        service = ""
        cve = ""
        parts = self.pname.split("/") if self.pname else []
        if len(parts) >= 1:
            service = parts[0].strip().lower()
        if len(parts) >= 2:
            cve = parts[1].strip().lower()
        return service, cve

    def _vuln_text(self, vuln: dict) -> str:
        links = " ".join(vuln.get("links", [])) if isinstance(vuln.get("links", []), list) else str(vuln.get("links", ""))
        return " ".join([
            str(vuln.get("vuln", "")),
            str(vuln.get("vulntype", "")),
            str(vuln.get("target", "")),
            str(vuln.get("information", "")),
            links,
        ]).lower()

    def _filter_and_rank_vulns(self, vulns: List[dict]) -> List[dict]:
        service, cve = self._extract_name_tokens()
        if not vulns:
            return vulns

        filtered = []
        for v in vulns:
            text = self._vuln_text(v)
            service_hit = service and service in text
            cve_hit = cve and cve in text
            if cve_hit or service_hit:
                filtered.append(v)

        if not filtered:
            filtered = vulns

        def rank(v: dict) -> tuple:
            text = self._vuln_text(v)
            cve_hit = 1 if (cve and cve in text) else 0
            service_hit = 1 if (service and service in text) else 0
            return (-cve_hit, -service_hit)

        return sorted(filtered, key=rank)

    def _build_exploit_input(self, state: AgentState) -> str:
        """
        构建 Exploit Agent 的 input 字符串。
        PoC 步骤以纯文本方式拼入 {input} 变量值，
        不经过 PromptTemplate 解析，因此任何特殊字符（如 JSON 花括号）都不会被误解析。
        """
        parts = [self.problem, self._build_structured_context(state)]
        if self.poc_steps:
            parts.append(
                "=== EXPLOIT COMMANDS (from Inquire Agent) ===\n"
                + self.poc_steps
                + "\n=== END OF EXPLOIT COMMANDS ==="
            )
        return "\n".join(parts)

    def _build_inquire_input(self, state: AgentState) -> str:
        return "\n".join([self.problem, self._build_structured_context(state)])

    def _try_extract_exploit_from_output(self, text: str) -> str:
        """
        从 Inquire Agent 的原始输出中尝试提取可执行的 exploit 命令。
        当 Agent 因格式错误耗尽迭代但输出中其实包含有用信息时使用。
        """
        if not text or not text.strip():
            return ""

        # 1. 尝试提取 curl 命令（最常见的 exploit 格式）
        curl_patterns = [
            # 完整 curl 命令（含 -X, -H, -d 等参数）
            r'(curl\s+(?:-[sSkXHd]\s+\S+\s+)*(?:(?:\'|")?\s*https?://\S+)(?:\s+(?:-[sSkXHd]\s+(?:\'[^\']*\'|"[^"]*"|\S+)\s*))*)',
            # 简单 curl 命令
            r'(curl\s+\S*https?://\S+[^\n]*)',
        ]
        for pattern in curl_patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                cmd = match.group(1).strip()
                if len(cmd) > 20:
                    return cmd

        # 2. 从 markdown 代码块中提取
        code_matches = re.findall(
            r'```(?:bash|shell|sh|zsh|cmd)?\s*\n(.+?)\n```',
            text, re.DOTALL
        )
        for block in reversed(code_matches):  # 倒序查找（最后的代码块通常是最终命令）
            block = block.strip()
            if any(block.startswith(prefix) for prefix in ['curl', 'wget', 'python', 'ruby']):
                return block

        # 3. 提取 POST/GET HTTP 请求模板
        http_match = re.search(
            r'((?:POST|GET|PUT)\s+\S+\s+HTTP/\d\.\d.+?)(?:\n\n[A-Z]|\Z)',
            text, re.DOTALL
        )
        if http_match:
            return http_match.group(1).strip()

        return ""

    # ------------------------------------------------------------------
    # 核心状态节点
    # ------------------------------------------------------------------

    async def agent_state(self, state: AgentState, agent, tools, sname: str) -> dict:
        self._emit_log(f"[状态机] 进入 {sname} Agent 节点")
        if sname == 'Exploit':
            max_iterations = self.config['psm']['exp_iterations']
        elif sname == 'Inquire':
            max_iterations = self.config['psm']['query_iterations']
        else:
            max_iterations = self.config['psm']['scan_iterations']

        _executor = AgentExecutor(
            agent=agent, tools=tools, verbose=True,
            handle_parsing_errors=self._format_parsing_error,
            max_iterations=max_iterations,
            return_intermediate_steps=True
        )

        agent_input = self.problem
        if sname == 'Exploit':
            agent_input = self._build_exploit_input(state)
        elif sname == 'Inquire':
            agent_input = self._build_inquire_input(state)

        result = await _executor.ainvoke({"input": agent_input})
        message_str = ''
        history_str = []
        if [] != result['intermediate_steps']:
            for i in result['intermediate_steps']:
                tool_name = i[0].tool
                tool_input = i[0].tool_input
                raw_tool_output = str(i[1])
                self._emit_log(f"[{sname}] 执行命令: {tool_input}" if tool_name == "EXECMD" else (f"[{sname}] 调用工具: {tool_name}({tool_input[:120]}...)" if len(str(tool_input)) > 120 else f"[{sname}] 调用工具: {tool_name}({tool_input})"))
                if tool_name == "EXECMD" and sname in self.raw_outputs:
                    if self.raw_outputs[sname]:
                        self.raw_outputs[sname] += "\n" + raw_tool_output
                    else:
                        self.raw_outputs[sname] = raw_tool_output

                tool_output = self._summarize_tool_output(raw_tool_output)
                agent_output = i[0].log
                history_str.append(agent_output + str(tool_output))
                message_str += agent_output + str(tool_output)
            message = AIMessage(message_str)
            self.history = self.history + history_str
            self.commands.append(tool_input)
            if sname == 'Inquire' and len(state["vulns"]) > 0:
                # 对 Inquire Agent，多层次提取 PoC：
                # 层级1: result['output']（Final Answer）—— 最佳来源
                # 层级2: Agent 推理文本 (i[0].log) 中提取命令
                # 层级3: ReadHTML 工具返回的原始内容中提取命令
                # 层级4: 最后一次工具输出作为兜底
                final_output = result.get('output', '')
                extracted_poc = ""

                # 层级1: Final Answer 包含有效 PoC
                if final_output and final_output.strip():
                    test_cmd = self._try_extract_exploit_from_output(final_output)
                    if test_cmd:
                        extracted_poc = final_output
                        self._emit_log(f"[Inquire] ✅ 从 Final Answer 中提取到 PoC")

                # 层级2: 从 Agent 的推理文本中提取命令
                if not extracted_poc:
                    for step in reversed(result['intermediate_steps']):
                        agent_log = step[0].log
                        cmd = self._try_extract_exploit_from_output(agent_log)
                        if cmd:
                            extracted_poc = cmd
                            self._emit_log(f"[Inquire] ✅ 从 Agent 推理文本中提取到 PoC")
                            break

                # 层级3: 从 ReadHTML 工具返回的原始内容中提取命令
                if not extracted_poc:
                    for step in reversed(result['intermediate_steps']):
                        if step[0].tool == 'ReadHTML':
                            raw_html_output = str(step[1])
                            cmd = self._try_extract_exploit_from_output(raw_html_output)
                            if cmd:
                                extracted_poc = cmd
                                self._emit_log(f"[Inquire] ✅ 从 ReadHTML 返回内容中提取到 PoC")
                                break

                # 层级4: 兜底 - 使用 Final Answer 或最后工具输出
                if not extracted_poc:
                    self._emit_log(f"[Inquire] ⚠️ 未提取到明确 PoC 命令，使用原始输出作为兜底")
                    extracted_poc = final_output if (final_output and final_output.strip()) else str(tool_output)

                safe_info = self._sanitize_information_text(str(extracted_poc))
                state["vulns"][0]['information'] = safe_info
                # PoC 内容存入独立字段，不拼入 self.problem，避免被 PromptTemplate 解析
                # curl 命令中的单引号 JSON 转换由 terminal.py 的 execute_command() 自动处理
                self.poc_steps = safe_info
                self._emit_log(f"[Inquire] poc_steps 长度: {len(self.poc_steps)}, 前200字符: {self.poc_steps[:200]}...")
        else:
            output_text = result['output']
            # 当 Inquire Agent 因格式错误耗尽迭代次数，intermediate_steps 为空
            # 但 output 中可能仍包含有用的 PoC 命令信息
            if sname == 'Inquire' and len(state["vulns"]) > 0:
                # 尝试从输出中提取可执行的 exploit 命令
                extracted_cmd = self._try_extract_exploit_from_output(output_text)
                if extracted_cmd:
                    self._emit_log(f"[Inquire] 从 Agent 输出中提取到 exploit 命令: {extracted_cmd[:120]}...")
                    safe_info = self._sanitize_information_text(extracted_cmd)
                    state["vulns"][0]['information'] = safe_info
                    # PoC 内容存入独立字段，不拼入 self.problem
                    # curl 命令中的单引号 JSON 转换由 terminal.py 的 execute_command() 自动处理
                    self.poc_steps = safe_info
                    self._emit_log(f"[Inquire] poc_steps 长度: {len(self.poc_steps)}, 前200字符: {self.poc_steps[:200]}...")
                else:
                    self._emit_log(f"[Inquire] ⚠️ Agent 未能产出有效 exploit 命令，将原始输出传递给 Exploit Agent")
                    # 即使没有提取到命令，也把输出存储到 raw_outputs 供后续参考
                    if output_text.strip():
                        self.raw_outputs["Inquire"] = output_text
                        # 将原始输出也存入 poc_steps 作为兜底信息
                        # curl 命令中的单引号 JSON 转换由 terminal.py 的 execute_command() 自动处理
                        self.poc_steps = self._sanitize_information_text(output_text)
                        self._emit_log(f"[Inquire] poc_steps(兜底) 长度: {len(self.poc_steps)}, 前200字符: {self.poc_steps[:200]}...")

            message = AIMessage(output_text)
            self.history = self.history + [output_text]

        return {
            "message": [message],
            "sender": sname,
            "vulns": state["vulns"],
            "check_count": state["check_count"]
        }

    def check_state(self, state: AgentState, name: str = "Check") -> dict:
        """
        成功判断优先级：
          1. LLM 判断（llm_check_success）—— 动态、无硬编码
          2. 正则兜底（check_str）—— LLM 不可用时启用
        两层都基于 EXECMD 真实工具输出，不信任 LLM 生成的历史文本。
        """
        self._emit_log(f"[状态机] 进入 Check 节点 (第 {state['check_count']} 次检查)")
        exploit_output = self.raw_outputs.get("Exploit", "")

        # ---- 提取 target 字段供判断 ----
        final_goal = ""
        for line in self.problem.splitlines():
            if line.startswith("Final Goal"):
                # "Final Goal : Execute arbitrary PHP code..."
                final_goal = line.split(":", 1)[-1].strip()
                break

        # ---- Step 1: LLM 判断 ----
        llm_result = None
        if self.llm is not None and exploit_output.strip():
            llm_result = llm_check_success(self.llm, final_goal, exploit_output)

        # ---- Step 2: 根据判断结果走分支 ----
        if llm_result is True:
            # LLM 确认成功
            self._emit_log("[Check] ✅ LLM判断: 渗透测试成功!")
            check_message = (
                f"Successfully exploited the vulnerability, "
                f"a total of {state['check_count']} steps were attempted"
            )
            self.history.append(check_message)
            return {
                "message": [HumanMessage(content=check_message)],
                "sender": name,
                "vulns": state["vulns"],
                "check_count": state["check_count"],
            }

        # LLM 说失败 或 LLM 不可用，降级到正则兜底
        check_code, check_count = check_str(
            self.problem, exploit_output, state["check_count"], self.pname
        )

        if check_code == 0:
            self._emit_log("[Check] ✅ 正则兜底判断: 渗透测试成功!")
            check_message = (
                f"Successfully exploited the vulnerability, "
                f"a total of {check_count} steps were attempted"
            )
        elif check_code in [1, 2]:
            self._emit_log(f"[Check] ❌ 利用失败 (code={check_code})，准备重试...")
            last_summary = self._summarize_message_for_prompt(
                str(state["message"][-1].content), max_chars=500
            )
            failure_guidance = self._build_failure_guidance(last_summary)
            check_message = (
                "Failed to exploit the vulnerability, please try again. "
                f"{self._final_goal_line()}\n"
                f"Last observation summary: {last_summary}\n"
                f"{failure_guidance}"
            )
        else:
            if len(state["vulns"]) > 1:
                check_message = "Failed to exploit the vulnerability, please try another vulnerability."
            else:
                check_message = "Failed to exploit the vulnerability."

        self.history.append(check_message)
        return {
            "message": [HumanMessage(content=check_message)],
            "sender": name,
            "vulns": state["vulns"],
            "check_count": check_count,
        }

    def vuln_select_state(self, state: AgentState, name: str = "Vuln_select") -> dict:
        self._emit_log("[状态机] 进入 Vuln_select 节点")
        if state['check_count'] == 0:
            scan_res = state["message"][-1]
            scan_text = self.raw_outputs.get("Scan", "") or scan_res.content
            vulns = parse_vuln(scan_text)
            vulns = self._filter_and_rank_vulns(vulns)
            if len(vulns) != 0:
                selected = vulns[0]
                self._emit_log(f"[Vuln_select] 发现 {len(vulns)} 个漏洞，选择: {selected.get('vuln', 'unknown')}")
                vuln_select_message = f"I think we can try this vulnerability. The vulnerability information is as follows {selected}"
            else:
                self._emit_log("[Vuln_select] ⚠️ 扫描未发现漏洞，终止程序")
                vuln_select_message = "SCAN FAILED: No vulnerabilities detected by xray on target. Terminating program."
                message = HumanMessage(content=vuln_select_message)
                self.history.append(vuln_select_message)
                return {
                    "message": [message],
                    "sender": name,
                    "vulns": [],
                    "check_count": state["check_count"],
                    "scan_failed": True,
                }
        else:
            vulns = state["vulns"]
            if len(vulns) > 1:
                vulns.pop(0)
            selected = vulns[0]
            vuln_select_message = f"I think we can try this vulnerability. The vulnerability information is as follows {selected}"

        message = HumanMessage(content=vuln_select_message)
        self.history.append(vuln_select_message)
        return {
            "message": [message],
            "sender": name,
            "vulns": vulns,
            "check_count": state["check_count"],
        }

    def refresh(self):
        self.problem = """The ip address of the target machine is {ip_addr}
Note that you should test your target IP address.
Final Goal : {vul_target}

SUCCESS CRITERIA - Your exploit is successful when you see:
- File content like /etc/passwd (root:x:0:0 or daemon: or similar)
- Command execution output (uid=, gid=, groups=)
- Or specific success indicators based on the Final Goal

When you achieve this, immediately respond with:
"Final Answer: Successfully exploited the vulnerability - [evidence]"

When you fail after multiple attempts, respond with:
"Final Answer: Failed to exploit the vulnerability - [reason]"
"""
        self.history = []
        self.commands = []
        self.raw_outputs = {"Scan": "", "Inquire": "", "Exploit": ""}
        self.poc_steps = ""  # Inquire Agent 提取的 PoC 命令