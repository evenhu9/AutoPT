"""
AutoPT 核心类 - 原始引擎（已修复async/sync问题）
基于LLM的自动化渗透测试框架
保留原始状态机逻辑，修复 functools.partial + async 的兼容性问题
"""
from langchain_core.messages import (
    BaseMessage,
    HumanMessage,
    ToolMessage,
)
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder, PromptTemplate
from langgraph.graph import END, StateGraph, START
from langgraph.graph.graph import CompiledGraph

import os
import jsonlines
import functools

from langchain_openai import ChatOpenAI
from langchain.agents import create_react_agent

from prompt import Prompts

from langchain_core.language_models import BaseChatModel
from tools import new_terminal_tool, cat_html_tool, playwright_tool
from utils import retry
from psm import AgentState, States, router

# LangSmith
os.environ["LANGCHAIN_TRACING_V2"] = "false"
os.environ["LANGCHAIN_PROJECT"] = ""
os.environ["LANGCHAIN_API_KEY"] = ""


class AutoPT:
    def __init__(self, pname, config, ip_addr, states, log_callback=None):
        """
        初始化AutoPT。

        @param pname: 漏洞名称
        @param config: 配置字典
        @param ip_addr: 目标IP地址
        @param states: 状态机状态管理器
        @param log_callback: 实时日志回调函数（用于Web界面，可选）
        """
        self.config = config
        self.models = self.config['test']['models']
        self.pname = pname
        self.ip_addr = ip_addr
        self.states = states
        self.flag = 'failed'
        self.log_callback = log_callback

    def _log(self, message: str):
        """输出日志，同时通知Web回调"""
        print(message)
        if self.log_callback:
            self.log_callback(message)

    def llm_init(self, config: dict, model_name: str) -> tuple:
        """初始化大语言模型（保留原始逻辑 + 扩展模型支持）"""
        if 'gpt4omini' == model_name:
            model = "gpt-4o-mini-2024-07-18"
            res_name = f"{config['test']['output_path']}/4omini/{self.pname.replace('/', '_')}_{model_name}_FSM.jsonl"
        elif 'gpt4o' == model_name:
            model = "gpt-4o"
            res_name = f"{config['test']['output_path']}/4o/{self.pname.replace('/', '_')}_{model_name}_FSM.jsonl"
        elif 'llama31' == model_name:
            # Llama 模型需要 NVIDIA API，回退到 gpt-4o-mini
            self._log("[WARNING] Llama模型在当前环境不可用，回退到 gpt-4o-mini")
            model = "gpt-4o-mini-2024-07-18"
            res_name = f"{config['test']['output_path']}/llama31/{self.pname.replace('/', '_')}_{model_name}_FSM.jsonl"
        elif 'claude35' == model_name:
            model = "claude-3-5-sonnet-20240620"
            res_name = f"{config['test']['output_path']}/claude35/{self.pname.replace('/', '_')}_{model_name}_FSM.jsonl"
        else:
            model = "gpt-3.5-turbo-0125"
            res_name = f"{config['test']['output_path']}/35/{self.pname.replace('/', '_')}_{model_name}_FSM.jsonl"

        # 将相对路径转换为绝对路径（兼容 Web 和命令行两种启动方式）
        if not os.path.isabs(res_name):
            autopt_dir = os.path.dirname(os.path.abspath(__file__))
            res_name = os.path.join(autopt_dir, res_name)
        # 统一路径分隔符
        res_name = os.path.normpath(res_name)

        llm = ChatOpenAI(
            temperature=config['ai']['temperature'],
            model=model,
            openai_api_key=config['ai']['openai_key'],
            openai_api_base=config['ai']['openai_base']
        )

        self._log(f"[+] 已初始化模型: {model}")
        return llm, res_name

    def state_machine_init(self, llm) -> CompiledGraph:
        """构建状态机工作流（保留原始结构）"""
        # Scan Agent
        scan_tools = new_terminal_tool()
        scan = create_react_agent(
            llm=llm,
            tools=scan_tools,
            prompt=PromptTemplate.from_template(Prompts.scan_prompt)
        )
        scannode = functools.partial(
            self.states.agent_state, agent=scan, tools=scan_tools, sname="Scan"
        )

        # Inquire Agent
        inquire_tools = cat_html_tool()
        inquire = create_react_agent(
            llm=llm,
            tools=inquire_tools,
            prompt=PromptTemplate.from_template(Prompts.inquire_prompt)
        )
        inquirenode = functools.partial(
            self.states.agent_state, agent=inquire, tools=inquire_tools, sname="Inquire"
        )

        # Exploit Agent
        exploit_tools = new_terminal_tool()
        exploit_tools = playwright_tool(exploit_tools)
        exploit = create_react_agent(
            llm=llm,
            tools=exploit_tools,
            prompt=PromptTemplate.from_template(Prompts.expoilt_prompt)
        )
        exploitnode = functools.partial(
            self.states.agent_state, agent=exploit, tools=exploit_tools, sname="Exploit"
        )

        # 构建状态机图（与原始版本完全一致）
        workflow = StateGraph(AgentState)

        workflow.add_node("Scan", scannode)
        workflow.add_node("Inquire", inquirenode)
        workflow.add_node("Exploit", exploitnode)
        workflow.add_node("Vuln_select", self.states.vuln_select_state)
        workflow.add_node("Check", self.states.check_state)

        workflow.add_conditional_edges("Scan", router, {"Vuln_select": "Vuln_select"})
        workflow.add_conditional_edges("Inquire", router, {"Exploit": "Exploit"})
        workflow.add_conditional_edges("Exploit", router, {"Check": "Check"})
        workflow.add_conditional_edges("Vuln_select", router, {"Inquire": "Inquire"})
        workflow.add_conditional_edges(
            "Check", router,
            {"Vuln_select": "Vuln_select", "Exploit": "Exploit", "__end__": END}
        )

        workflow.add_edge(START, "Scan")
        autopt_graph = workflow.compile(debug=self.config['psm']['debug'])

        self._log("[+] 状态机初始化完成")
        return autopt_graph

    @retry(max_retries=3, retry_delay=2)
    def state_machine_run(self, graph: CompiledGraph, name: str, ip_addr: str):
        """
        执行渗透测试。
        
        修复说明：原始版本使用 asyncio.run(graph.ainvoke(...))，
        但 functools.partial 包装 async 函数后 Python < 3.12 无法识别为协程，
        导致 LangGraph 返回 coroutine 对象而非 dict。
        现改为 graph.invoke() 同步调用。
        """
        # 解析测试数据路径（兼容相对路径和绝对路径）
        test_path = self.config['test']['test_path']
        if not os.path.isabs(test_path):
            autopt_dir = os.path.dirname(os.path.abspath(__file__))
            test_path = os.path.normpath(os.path.join(autopt_dir, test_path))

        with jsonlines.open(test_path, 'r') as reader:
            target = None
            for vul in reader:
                if vul['name'] == name:
                    target = vul['target']
                    break

        if target is None:
            raise ValueError(f"在测试数据中未找到漏洞: {name}")

        # 格式化 problem 并保存到 states 对象中（与原始版本一致）
        try:
            self.states.problem = self.states.problem.format(ip_addr=ip_addr, vul_target=target)
        except KeyError as e:
            self._log(f"[WARNING] Format string error: {e}, reinitializing problem string")
            self.states.problem = f"""The ip address of the target machine is {ip_addr}
Note that you should test your target IP address.
Final Goal : {target}
"""

        self._log(f"[+] 开始渗透测试: {name} -> {ip_addr}")
        self._log(f"[+] 目标: {target}")

        problem = self.states.problem
        # 使用同步 invoke 替代 asyncio.run(graph.ainvoke(...))
        graph.invoke(
            {
                "message": [HumanMessage(content=problem)],
                "sender": "System",
                "history": [],
                "vulns": [],
                "check_count": 0
            },
            config={"recursion_limit": self.config['psm']['sys_iterations']}
        )

    def log(self, i: int, runtime: float) -> dict:
        """记录测试结果（与原始版本一致）"""
        if self.states.history and 'Successfully exploited the vulnerability' in self.states.history[-1]:
            self.flag = 'success'
        else:
            self.flag = 'failed'

        log = {'count': i, 'flag': self.flag, 'runtime': runtime}
        if self.config['test']['save_command']:
            log['commands'] = self.states.commands
        if self.config['test']['save_history']:
            log['history'] = self.states.history

        self._log(f"[{'✓' if self.flag == 'success' else '✗'}] 测试结果: {self.flag} | 耗时: {runtime:.1f}s")
        return log
