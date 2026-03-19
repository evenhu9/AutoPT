"""
ReAct OutputParser —— 在标准解析器基础上增加工具名规范化能力

功能：
  1. 优先使用 LangChain 标准 ReActSingleInputOutputParser 解析
  2. 标准解析失败时，用宽松正则提取 Action / Action Input / Final Answer
  3. 支持工具名规范化（处理大小写、下划线等变体）
"""

import re
from typing import Union

from langchain.agents.output_parsers import ReActSingleInputOutputParser
from langchain_core.agents import AgentAction, AgentFinish
from langchain_core.exceptions import OutputParserException


class RobustReActParser(ReActSingleInputOutputParser):
    """
    继承 LangChain 标准 ReAct parser，覆写 parse 方法增加工具名规范化能力。
    - 先尝试标准解析
    - 失败时用宽松正则从全文中搜索 Action/Action Input
    """

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

    def parse(self, text: str) -> Union[AgentAction, AgentFinish]:
        # ---- Step 1: 尝试标准解析 ----
        try:
            result = super().parse(text)
            if isinstance(result, AgentAction):
                normalized = self._normalize_tool_name(result.tool)
                if normalized:
                    return AgentAction(
                        tool=normalized,
                        tool_input=result.tool_input,
                        log=result.log,
                    )
                # 工具名不合法，跳过标准结果，走宽松解析
            else:
                return result
        except OutputParserException:
            pass

        # ---- Step 2: 宽松提取 Final Answer ----
        final_answer = self._extract_final_answer(text)
        if final_answer is not None:
            return AgentFinish(
                return_values={"output": final_answer},
                log=text,
            )

        # ---- Step 3: 宽松提取 Action + Action Input ----
        action, action_input = self._extract_action(text)
        if action is not None:
            return AgentAction(
                tool=action,
                tool_input=action_input or "",
                log=text,
            )

        # ---- Step 4: 解析失败 —— 返回提示让 Agent 重新格式化 ----
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

    def _normalize_tool_name(self, raw: str) -> str:
        """将原始 Action 字符串规范化为已知工具名，找不到返回空字符串。"""
        raw = raw.strip().strip('"\'` ')
        # 1. 精确匹配（忽略大小写）
        key = raw.lower().replace(' ', '').replace('_', '')
        for k, v in self.KNOWN_TOOLS.items():
            if key == k.replace('_', ''):
                return v
        # 2. 如果 raw 是纯字母+下划线且较短，直接返回
        if re.match(r'^[A-Za-z_]{2,25}$', raw):
            return raw
        # 3. 从长句中提取已知工具名（处理 "I will use the ServicePort tool" 这类情况）
        for k, v in self.KNOWN_TOOLS.items():
            pattern = re.compile(r'\b' + re.escape(v) + r'\b', re.IGNORECASE)
            if pattern.search(raw):
                return v
        return ""

    def _extract_final_answer(self, text: str) -> Union[str, None]:
        """宽松匹配 Final Answer"""
        match = re.search(
            r'Final\s*Answer\s*:\s*(.+)',
            text, re.IGNORECASE | re.DOTALL
        )
        if match:
            answer = match.group(1).strip()
            for stop in ['Thought:', 'Action:', '\n\nQuestion:']:
                idx = answer.find(stop)
                if idx > 0:
                    answer = answer[:idx].strip()
            return answer if answer else None
        return None

    def _extract_action(self, text: str) -> tuple:
        """宽松匹配 Action 和 Action Input"""
        action = None
        action_input = None

        # 模式1: 标准多行格式
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
            action = self._normalize_tool_name(raw_action)
            if not action:
                action = None

        if input_match:
            action_input = input_match.group(1).strip()
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

        return action, action_input
