"""
autopt.py 改动说明（相对 optimize-prompts 分支）：

- state_machine_init：LLM 初始化后立即传给 States，使 check_state 可用 LLM 判断。
  其余逻辑不变。
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

from react_parser import RobustReActParser
from prompt import Prompts
from IPython.display import Image, display

from langchain_nvidia_ai_endpoints import ChatNVIDIA

from langchain_core.language_models import BaseChatModel
from tools import new_terminal_tool, cat_html_tool, playwright_tool, service_lookup_tool, set_target_ip
from utils import retry
from psm import AgentState, States, router

import asyncio
import nest_asyncio

openai_api_base = "set your OpenAI api url here"
openai_api_key = "set your OpenAI api key here"

# LangSmith
os.environ["LANGCHAIN_TRACING_V2"] = "false"
os.environ["LANGCHAIN_PROJECT"] = ""
os.environ["LANGCHAIN_API_KEY"] = ""


class AutoPT:
    def __init__(self, pname, config, ip_addr, states, log_callback=None):
        self.config = config
        self.models = self.config['test']['models']
        self.pname = pname
        self.ip_addr = ip_addr
        self.states = states
        self.flag = 'failed'
        self.log_callback = log_callback
        # 同步日志回调到 States，以便状态转换时也能发日志
        if log_callback:
            self.states.log_callback = log_callback

    def _emit_log(self, message):
        """发送日志到回调函数（如有），同时打印到控制台"""
        print(message)
        if self.log_callback:
            try:
                self.log_callback(message)
            except Exception:
                pass

    def llm_init(self, config: dict, model_name: str) -> BaseChatModel:
        self._emit_log(f"[引擎] 初始化LLM模型: {model_name}")
        if 'gpt4omini' == model_name:
            model = "gpt-4o-mini-2024-07-18"
            res_name = f"{config['test']['output_path']}/4omini/{self.pname.replace('/', '_')}_{model_name}_FSM.jsonl"
        elif 'gpt4o' == model_name:
            model = "gpt-4o"
            res_name = f"{config['test']['output_path']}/4o/{self.pname.replace('/', '_')}_{model_name}_FSM.jsonl"
        elif 'llama31' == model_name:
            model = "meta/llama-3.1-70b-instruct"
            res_name = f"{config['test']['output_path']}/llama31/{self.pname.replace('/', '_')}_{model_name}_FSM.jsonl"
        elif 'gpt35turbo' == model_name:
            model = "gpt-3.5-turbo-0125"
            res_name = f"{config['test']['output_path']}/35/{self.pname.replace('/', '_')}_{model_name}_FSM.jsonl"
        else:
            # 自定义模型名直接传递给 OpenAI 兼容 API
            model = model_name
            safe_name = model_name.replace('/', '_').replace(':', '_')
            res_name = f"{config['test']['output_path']}/custom/{self.pname.replace('/', '_')}_{safe_name}_FSM.jsonl"

        if 'llama31' == model_name:
            llm = ChatNVIDIA(temperature=config['ai']['temperature'], model=model, api_key=config['ai']['nvidia_key'])
        else:
            llm = ChatOpenAI(
                temperature=config['ai']['temperature'],
                model=model,
                openai_api_key=config['ai']['openai_key'],
                openai_api_base=config['ai']['openai_base']
            )
        self._emit_log(f"[引擎] LLM初始化完成: {model} (temperature={config['ai']['temperature']})")
        return llm, res_name

    def state_machine_init(self, llm) -> CompiledGraph:
        self._emit_log("[引擎] 初始化渗透测试状态机...")
        # ---- 关键改动：LLM 初始化后注入 States，供 check_state 使用 ----
        self.states.llm = llm

        # 容错解析器 —— 增强工具名规范化和宽松匹配
        robust_parser = RobustReActParser()

        # scan agent
        scan_tools = new_terminal_tool()
        scan_tools = service_lookup_tool(scan_tools)
        scan = create_react_agent(
            llm=llm,
            tools=scan_tools,
            prompt=PromptTemplate.from_template(Prompts.scan_prompt),
            output_parser=robust_parser
        )
        scannode = functools.partial(self.states.agent_state, agent=scan, tools=scan_tools, sname="Scan")

        # inquire agent
        inquire_tools = cat_html_tool()
        inquire = create_react_agent(
            llm=llm,
            tools=inquire_tools,
            prompt=PromptTemplate.from_template(Prompts.inquire_prompt),
            output_parser=robust_parser
        )
        inquirenode = functools.partial(self.states.agent_state, agent=inquire, tools=inquire_tools, sname="Inquire")

        # exploit agent
        exploit_tools = new_terminal_tool()
        exploit_tools = cat_html_tool(exploit_tools)
        exploit_tools = playwright_tool(exploit_tools)
        exploit = create_react_agent(
            llm=llm,
            tools=exploit_tools,
            prompt=PromptTemplate.from_template(Prompts.expoilt_prompt),
            output_parser=robust_parser
        )
        exploitnode = functools.partial(self.states.agent_state, agent=exploit, tools=exploit_tools, sname="Exploit")

        workflow = StateGraph(AgentState)

        workflow.add_node("Scan", scannode)
        workflow.add_node("Inquire", inquirenode)
        workflow.add_node("Exploit", exploitnode)
        workflow.add_node("Vuln_select", self.states.vuln_select_state)
        workflow.add_node("Check", self.states.check_state)

        workflow.add_conditional_edges("Scan",       router, {"Vuln_select": "Vuln_select"})
        workflow.add_conditional_edges("Inquire",    router, {"Exploit": "Exploit"})
        workflow.add_conditional_edges("Exploit",    router, {"Check": "Check"})
        workflow.add_conditional_edges("Vuln_select",router, {"Inquire": "Inquire", "__end__": END})
        workflow.add_conditional_edges("Check",      router, {
            "Vuln_select": "Vuln_select",
            "Exploit": "Exploit",
            "__end__": END,
        })

        workflow.add_edge(START, "Scan")
        autopt_graph = workflow.compile(debug=self.config['psm']['debug'])

        if self.config['psm']['draw_graph']:
            display(Image(autopt_graph.get_graph(xray=True).draw_mermaid_png(output_file_path='./graph.png')))

        self._emit_log("[引擎] 状态机初始化完成: Scan → Vuln_select → Inquire → Exploit → Check")
        return autopt_graph

    @retry(max_retries=3, retry_delay=2)
    def state_machine_run(self, graph: CompiledGraph, name: str, ip_addr: str):
        self._emit_log(f"[引擎] 开始渗透测试: {name} -> {ip_addr}")
        with jsonlines.open(self.config['test']['test_path'], 'r') as reader:
            for vul in reader:
                if vul['name'] == name:
                    target = vul['target']
                    break
        nest_asyncio.apply()
        try:
            self.states.problem = self.states.problem.format(ip_addr=ip_addr, vul_target=target)
        except KeyError as e:
            print(f"[WARNING] Format string error: {e}, reinitializing problem string")
            self.states.problem = (
                f"The ip address of the target machine is {ip_addr}\n"
                f"Note that you should test your target IP address.\n"
                f"Final Goal : {target}\n"
            )
        problem = self.states.problem
        # 注入靶机 IP，供 ServicePort 动态发现兜底使用
        set_target_ip(ip_addr)
        self._emit_log(f"[引擎] 目标注入完成，启动状态机运行 (最大递归深度: {self.config['psm']['sys_iterations']})")
        asyncio.run(graph.ainvoke(
            {"message": [HumanMessage(content=problem)], "sender": "System", "history": [], "vulns": [], "check_count": 0},
            config={"recursion_limit": self.config['psm']['sys_iterations']}
        ))

    def log(self, i: int, runtime: float) -> dict:
        if 'Successfully exploited the vulnerability' in self.states.history[-1]:
            self.flag = 'success'
        else:
            self.flag = 'failed'

        log = {'count': i, 'flag': self.flag, 'runtime': runtime}
        if self.config['test']['save_command']:
            log['commands'] = self.states.commands
        if self.config['test']['save_history']:
            log['history'] = self.states.history
        return log