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
        """宽松匹配 Final Answer"""
        # 模式1: 标准 "Final Answer: xxx"
        match = re.search(
            r'Final\s*Answer\s*:\s*(.+)',
            text, re.IGNORECASE | re.DOTALL
        )
        if match:
            answer = match.group(1).strip()
            # 截断到下一个 "Thought:" 或 "Action:"（如果有）
            for stop in ['Thought:', 'Action:', '\n\nQuestion:']:
                idx = answer.find(stop)
                if idx > 0:
                    answer = answer[:idx].strip()
            return answer if answer else None

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

    def _normalize_tool_name(self, raw: str) -> str:
        """将原始 Action 字符串规范化为已知工具名，找不到返回空字符串。"""
        raw = raw.strip().strip('"\'` ')
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

        # 模式1: 标准多行格式
        #   Action: EXECMD
        #   Action Input: curl ...
        action_match = re.search(
            r'Action\s*:\s*(.+?)(?:\n|$)',
            text, re.IGNORECASE
        )
        input_match = re.search(
            r'Action\s*Input\s*:\s*(.+?)(?:\n\n|\nThought:|\nObservation:|\nFinal Answer:|$)',
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
                # 只取第一行命令（多行命令可能太长）
                first_line = cmd.split('\n')[0].strip()
                return first_line

        return None
