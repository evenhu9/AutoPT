"""
容错 ReAct OutputParser —— 专为"思考型"LLM（Gemini Thinking、DeepSeek R1 等）设计

问题背景：
  思考型模型在生成输出时会包含大量内部推理文本（如 <thinking> 标签、长段 Thought），
  不严格遵循 LangChain ReAct Agent 要求的格式：
    Thought: ...
    Action: tool_name
    Action Input: tool_input
  导致 ReActSingleInputOutputParser 报 "Missing 'Action:' after 'Thought:'" 错误。

解决方案：
  1. 使用多种正则模式从 LLM 输出中宽松匹配 Action / Action Input
  2. 支持 "Final Answer:" 的宽松提取
  3. 解析失败时提供智能修复提示（而非简单报错）
"""

import re
from typing import Union

from langchain.agents.output_parsers import ReActSingleInputOutputParser
from langchain_core.agents import AgentAction, AgentFinish
from langchain_core.exceptions import OutputParserException


class RobustReActParser(ReActSingleInputOutputParser):
    """
    继承 LangChain 标准 ReAct parser，覆写 parse 方法增加容错能力。
    - 先尝试标准解析
    - 失败时用宽松正则从全文中搜索 Action/Action Input
    - 支持处理 <thinking>...</thinking> 包裹的内容
    - 支持处理 markdown code block 中的动作
    """

    def parse(self, text: str) -> Union[AgentAction, AgentFinish]:
        # ---- Step 0: 清洗思考型模型的特殊标记 ----
        cleaned = self._strip_thinking_tags(text)

        # ---- Step 1: 尝试标准解析 ----
        try:
            result = super().parse(cleaned)
            # 如果标准解析成功，验证工具名合法性
            if isinstance(result, AgentAction):
                normalized = self._normalize_tool_name(result.tool)
                if normalized:
                    # 工具名合法（可能需要规范化），直接返回
                    return AgentAction(
                        tool=normalized,
                        tool_input=result.tool_input,
                        log=result.log,
                    )
                # 工具名不合法（如整句话被当成了 Action 名），跳过标准结果，走宽松解析
            else:
                # AgentFinish，直接返回
                return result
        except OutputParserException:
            pass

        # ---- Step 2: 宽松提取 Final Answer ----
        final_answer = self._extract_final_answer(cleaned)
        if final_answer is not None:
            return AgentFinish(
                return_values={"output": final_answer},
                log=text,
            )

        # ---- Step 3: 宽松提取 Action + Action Input ----
        action, action_input = self._extract_action(cleaned)
        if action is not None:
            return AgentAction(
                tool=action,
                tool_input=action_input or "",
                log=text,
            )

        # ---- Step 3.5: Action: None 特殊处理 ----
        # LLM 输出了 Action: None，说明它已完成分析但不知道用 Final Answer 结束
        # 尝试从文本中提取有用内容作为 Final Answer
        if re.search(r'Action\s*:\s*None\b', cleaned, re.IGNORECASE):
            # 提取 Action: None 之前的所有 Thought 内容作为分析结果
            content_before_none = re.split(r'Action\s*:\s*None', cleaned, flags=re.IGNORECASE)[0]
            # 先尝试从文本中提取可执行命令
            cmd = self._extract_standalone_exploit_command(cleaned)
            if not cmd:
                cmd = self._extract_command_from_codeblock(cleaned)
            if cmd:
                return AgentFinish(
                    return_values={"output": cmd},
                    log=text,
                )
            # 没有命令但有有意义的分析内容，也作为 Final Answer 返回
            # 这样至少能传递信息给下一个 Agent
            meaningful_text = content_before_none.strip()
            # 移除 "Thought:" 前缀
            meaningful_text = re.sub(r'^Thought\s*:\s*', '', meaningful_text, flags=re.IGNORECASE).strip()
            if meaningful_text and len(meaningful_text) > 20:
                return AgentFinish(
                    return_values={"output": meaningful_text},
                    log=text,
                )

        # ---- Step 4: 尝试从 markdown 代码块中提取命令 ----
        cmd = self._extract_command_from_codeblock(cleaned)
        if cmd:
            return AgentAction(
                tool="EXECMD",
                tool_input=cmd,
                log=text,
            )

        # ---- Step 5: 解析彻底失败 —— 返回智能提示让 Agent 重新格式化 ----
        raise OutputParserException(
            f"Could not parse LLM output. Please respond in EXACTLY this format:\n"
            f"Thought: your reasoning\n"
            f"Action: tool_name\n"
            f"Action Input: tool_input\n\n"
            f"OR for final answers:\n"
            f"Thought: I now know the final answer\n"
            f"Final Answer: your answer\n\n"
            f"Available tools: EXECMD, ServicePort, ReadHTML\n"
            f"Do NOT include any other text before 'Thought:' or between 'Thought:' and 'Action:'.",
            observation="Format error - please use the exact format shown above.",
            llm_output=text,
            send_to_llm=True,
        )

    def _strip_thinking_tags(self, text: str) -> str:
        """移除 <thinking>...</thinking> 或 <think>...</think> 等标记"""
        # 移除 XML 风格的思考标记
        cleaned = re.sub(
            r'<(?:thinking|think|thought|reasoning)>.*?</(?:thinking|think|thought|reasoning)>',
            '', text, flags=re.DOTALL | re.IGNORECASE
        )
        # 移除开头的大量空白行
        cleaned = cleaned.lstrip('\n\r ')
        return cleaned if cleaned.strip() else text

    def _extract_final_answer(self, text: str) -> Union[str, None]:
        """宽松匹配 Final Answer，支持多步 PoC 命令（STEP 1/2/3 格式）"""
        # 模式1: 标准 "Final Answer: xxx"
        match = re.search(
            r'Final\s*Answer\s*:\s*(.+)',
            text, re.IGNORECASE | re.DOTALL
        )
        if match:
            answer = match.group(1).strip()
            # 截断到下一个 "Thought:" 或 "Action:"（如果有），但保留 STEP 标记
            for stop in ['Thought:', 'Action:', '\n\nQuestion:']:
                idx = answer.find(stop)
                if idx > 0:
                    answer = answer[:idx].strip()
            return answer if answer else None

        # 模式2: 没有 "Final Answer:" 标签，但文本中包含多步 STEP 格式
        step_match = re.search(
            r'(STEP\s+1\s*:.+)',
            text, re.IGNORECASE | re.DOTALL
        )
        if step_match:
            steps_text = step_match.group(1).strip()
            # 确保至少包含一个可执行命令
            if re.search(r'(?:curl|wget|python|ruby|perl|bash|nc|nmap)\s', steps_text, re.IGNORECASE):
                return steps_text

        # 模式3: 没有 "Final Answer:" 标签，但文本中包含可执行的 exploit 命令
        cmd = self._extract_standalone_exploit_command(text)
        if cmd:
            return cmd

        return None

    # 已知工具名映射表（所有变体 → 标准名称）
    KNOWN_TOOLS = {
        'execmd': 'EXECMD',
        'exec_cmd': 'EXECMD',
        'serviceport': 'ServicePort',
        'service_port': 'ServicePort',
        'readhtml': 'ReadHTML',
        'read_html': 'ReadHTML',
        'click_element': 'click_element',
        'navigate_browser': 'navigate_browser',
        'previous_webpage': 'previous_webpage',
        'extract_text': 'extract_text',
        'extract_hyperlinks': 'extract_hyperlinks',
        'get_elements': 'get_elements',
        'current_webpage': 'current_webpage',
    }

    # 无效工具名黑名单 —— 这些词虽然匹配 [A-Za-z_]{2,25}，但不是工具
    INVALID_TOOL_NAMES = {'none', 'null', 'undefined', 'true', 'false', 'na', 'n/a'}

    def _normalize_tool_name(self, raw: str) -> str:
        """将原始 Action 字符串规范化为已知工具名，找不到返回空字符串。"""
        raw = raw.strip().strip('"\'` ')
        # 0. 排除无效工具名（如 None, null 等）
        if raw.lower() in self.INVALID_TOOL_NAMES:
            return ""
        # 1. 精确匹配（忽略大小写）
        key = raw.lower().replace(' ', '').replace('_', '')
        for k, v in self.KNOWN_TOOLS.items():
            if key == k.replace('_', ''):
                return v
        # 2. 如果 raw 是完整的合法工具名（纯字母+下划线且较短），直接返回
        if re.match(r'^[A-Za-z_]{2,25}$', raw):
            return raw
        # 3. 从长句中提取已知工具名（处理 "I will use the ServicePort tool" 这类情况）
        for k, v in self.KNOWN_TOOLS.items():
            # 在长句中搜索工具名（不区分大小写，要求是独立单词）
            pattern = re.compile(r'\b' + re.escape(v) + r'\b', re.IGNORECASE)
            if pattern.search(raw):
                return v
        return ""

    def _extract_action(self, text: str) -> tuple:
        """宽松匹配 Action 和 Action Input"""
        action = None
        action_input = None

        # 模式0: 检测 Action: None —— LLM 想结束但不知道用 Final Answer
        # 此时返回 (None, None) 让调用方走 Final Answer 提取逻辑
        none_match = re.search(
            r'Action\s*:\s*None\b',
            text, re.IGNORECASE
        )
        if none_match:
            return None, None

        # 模式1: 标准多行格式
        #   Action: EXECMD
        #   Action Input: curl ...
        action_match = re.search(
            r'Action\s*:\s*(.+?)(?:\n|$)',
            text, re.IGNORECASE
        )
        # 改进: Action Input 支持多行内容（curl 含 JSON body 等）
        # 使用贪婪匹配直到遇到明确的分隔符
        input_match = re.search(
            r'Action\s*Input\s*:\s*(.+?)(?:\n\s*\nThought:|\n\s*\nObservation:|\nThought:|\nObservation:|\nFinal Answer:|\n\s*\nQuestion:|$)',
            text, re.IGNORECASE | re.DOTALL
        )

        if action_match:
            raw_action = action_match.group(1).strip().split('\n')[0].strip()
            # 用规范化方法从原始文本中提取合法工具名
            action = self._normalize_tool_name(raw_action)
            if not action:
                action = None

        if input_match:
            action_input = input_match.group(1).strip()
            # 移除首尾引号和反引号
            action_input = action_input.strip('"\'` ')

        # 模式2: 单行格式 "Action: EXECMD(curl ...)"
        if not action:
            inline_match = re.search(
                r'Action\s*:\s*(\w+)\s*\((.+?)\)',
                text, re.IGNORECASE
            )
            if inline_match:
                normalized = self._normalize_tool_name(inline_match.group(1).strip())
                if normalized:
                    action = normalized
                    action_input = inline_match.group(2).strip()

        # 模式3: 从全文中搜索 "use <Tool> tool" 模式（无标准 Action: 头的情况）
        if not action:
            use_tool_match = re.search(
                r'(?:use|using|call|run)\s+(?:the\s+)?(\w+)\s+tool',
                text, re.IGNORECASE
            )
            if use_tool_match:
                normalized = self._normalize_tool_name(use_tool_match.group(1).strip())
                if normalized:
                    action = normalized
                    # 尝试从上下文获取 input
                    if not action_input and input_match:
                        action_input = input_match.group(1).strip().strip('"\'` ')

        return action, action_input

    def _extract_command_from_codeblock(self, text: str) -> Union[str, None]:
        """
        从 markdown 代码块中提取可执行命令。
        思考型模型经常直接输出 ```bash\ncurl ...\n``` 而不用 Action 格式。
        """
        # 匹配 ```bash ... ``` 或 ```shell ... ``` 或 ``` ... ```
        matches = re.findall(
            r'```(?:bash|shell|sh|zsh|cmd)?\s*\n(.+?)\n```',
            text, re.DOTALL
        )
        if matches:
            # 取最后一个代码块（通常是最终命令）
            cmd = matches[-1].strip()
            # 过滤掉不是命令的代码块（如 JSON、Python 等）
            if any(cmd.startswith(prefix) for prefix in [
                'curl', 'wget', 'nmap', 'xray', 'python', 'ruby', 'perl',
                'echo', 'cat', 'ls', 'id', 'whoami', 'nc', 'bash',
            ]):
                # 支持多行命令（如 curl 含 -d '...' 跨行的情况）
                # 如果是 curl 命令，保留完整多行内容
                if cmd.startswith('curl'):
                    return cmd
                # 其他命令只取第一行
                first_line = cmd.split('\n')[0].strip()
                return first_line

        return None

    def _extract_standalone_exploit_command(self, text: str) -> Union[str, None]:
        """
        从文本中提取独立的 exploit 命令（无 Action/Final Answer 包裹）。
        Inquire Agent 常见问题：LLM 分析完 PoC 后直接输出命令但没加正确格式标签。
        通用设计：不针对特定漏洞，基于命令模式通用匹配。
        """
        candidates = []

        # 1. 匹配 curl 命令（含多行 -d/-H/-X 参数，最常见的 exploit 格式）
        curl_match = re.search(
            r'(curl\s+(?:(?:-[sSkXHdoOLvA]|--[a-z-]+)\s+(?:\'[^\']*\'|"[^"]*"|\S+)\s+)*'
            r'(?:\'[^\']*\'|"[^"]*"|https?://\S+)'
            r'(?:\s+(?:-[sSkXHdoOLvA]|--[a-z-]+)\s+(?:\'[^\']*\'|"[^"]*"|\S+))*)',
            text, re.IGNORECASE | re.DOTALL
        )
        if curl_match:
            cmd = curl_match.group(1).strip()
            if 'http' in cmd and len(cmd) > 20:
                candidates.append(cmd)

        # 2. 匹配 wget 命令
        wget_match = re.search(
            r'(wget\s+[^\n]*https?://\S+[^\n]*)',
            text, re.IGNORECASE
        )
        if wget_match:
            candidates.append(wget_match.group(1).strip())

        # 3. 匹配 python/python3 单行命令
        py_match = re.search(
            r'(python[23]?\s+-c\s+(?:\'[^\']*\'|"[^"]*")[^\n]*)',
            text, re.IGNORECASE
        )
        if py_match:
            candidates.append(py_match.group(1).strip())

        # 4. 匹配 POST/GET HTTP 请求模板（vulhub README 格式）
        http_match = re.search(
            r'((?:POST|GET|PUT|DELETE|PATCH)\s+\S+\s+HTTP/\d\.\d.+?)(?:\n\n[A-Z]|\Z)',
            text, re.DOTALL
        )
        if http_match:
            candidates.append(http_match.group(1).strip())

        # 5. 匹配包含真实 IP 的命令（说明 LLM 已经替换了 target IP）
        ip_cmd_match = re.search(
            r'((?:curl|wget|python[23]?|nmap|nc|bash|ruby|perl)\s+[^\n]*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[^\n]*)',
            text, re.IGNORECASE
        )
        if ip_cmd_match:
            cmd = ip_cmd_match.group(1).strip()
            if len(cmd) > 15:
                candidates.append(cmd)

        # 选择最长的候选命令（通常更完整）
        if candidates:
            return max(candidates, key=len)

        # 6. 匹配 STEP 格式的多步命令（Inquire Agent 的多步 PoC 输出）
        step_match = re.search(
            r'(STEP\s+1\s*:.+)',
            text, re.IGNORECASE | re.DOTALL
        )
        if step_match:
            steps_text = step_match.group(1).strip()
            if re.search(r'(?:curl|wget|python|ruby|perl|bash|nc|nmap)\s', steps_text, re.IGNORECASE):
                return steps_text

        return None