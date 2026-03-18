"""
AutoPT 核心类 - 重构版
基于LLM的自动化渗透测试框架
去除SSH依赖，支持本地直接执行
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

import asyncio
import nest_asyncio

# LangSmith 追踪（可选）
os.environ["LANGCHAIN_TRACING_V2"] = "false"
os.environ["LANGCHAIN_PROJECT"] = ""
os.environ["LANGCHAIN_API_KEY"] = ""


class AutoPT:
    """AutoPT核心控制器"""
    
    def __init__(self, pname, config, ip_addr, states, log_callback=None):
        """
        初始化AutoPT。
        
        @param pname: 漏洞名称
        @param config: 配置字典
        @param ip_addr: 目标IP地址
        @param states: 状态机状态管理器
        @param log_callback: 实时日志回调函数（用于Web界面）
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
        """初始化大语言模型"""
        model_map = {
            'gpt35turbo': ("gpt-3.5-turbo-0125", "35"),
            'gpt4omini': ("gpt-4o-mini-2024-07-18", "4omini"),
            'gpt4o': ("gpt-4o", "4o"),
        }
        
        if model_name in model_map:
            model, folder = model_map[model_name]
        else:
            model = model_name
            folder = model_name.replace('/', '_')
        
        # 跨平台路径拼接：替换漏洞名中的 / 和 \ 为 _
        safe_pname = self.pname.replace('/', '_').replace('\\', '_')
        # 路径基于 AutoPT 模块目录解析（兼容命令行和Web两种启动方式）
        autopt_dir = os.path.dirname(os.path.abspath(__file__))
        output_path = config['test']['output_path']
        if not os.path.isabs(output_path):
            output_path = os.path.join(autopt_dir, output_path)
        res_name = os.path.join(output_path, folder, f"{safe_pname}_{model_name}_FSM.jsonl")
        
        if model_name == 'llama31':
            self._log("[WARNING] Llama模型已不再支持，回退到gpt-4o-mini")
            model = "gpt-4o-mini-2024-07-18"
        
        llm = ChatOpenAI(
            temperature=config['ai']['temperature'],
            model=model,
            openai_api_key=config['ai']['openai_key'],
            openai_api_base=config['ai']['openai_base']
        )
        
        self._log(f"[+] 已初始化模型: {model}")
        return llm, res_name

    def state_machine_init(self, llm) -> CompiledGraph:
        """构建状态机工作流"""
        # 获取本地执行配置
        local_config = self.config.get('local', {})
        timeout = local_config.get('command_timeout', 120)
        xray_path = local_config.get('xray_path', '') or None
        
        # Scan Agent - 使用本地命令执行
        scan_tools = new_terminal_tool(timeout=timeout, xray_path=xray_path)
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

        # Exploit Agent - 使用本地命令执行 + 浏览器自动化
        exploit_tools = new_terminal_tool(timeout=timeout, xray_path=xray_path)
        exploit_tools = playwright_tool(exploit_tools)
        exploit = create_react_agent(
            llm=llm,
            tools=exploit_tools,
            prompt=PromptTemplate.from_template(Prompts.expoilt_prompt)
        )
        exploitnode = functools.partial(
            self.states.agent_state, agent=exploit, tools=exploit_tools, sname="Exploit"
        )

        # 构建状态机图
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
        """执行渗透测试"""
        # 从基准数据中获取目标信息
        # 跨平台路径解析：相对路径基于 AutoPT 模块目录
        autopt_dir = os.path.dirname(os.path.abspath(__file__))
        test_path = self.config['test']['test_path']
        if not os.path.isabs(test_path):
            test_path = os.path.normpath(os.path.join(autopt_dir, test_path))
        with jsonlines.open(test_path, 'r') as reader:
            target = None
            for vul in reader:
                if vul['name'] == name:
                    target = vul['target']
                    break
        
        if target is None:
            raise ValueError(f"在测试数据中未找到漏洞: {name}")
        
        nest_asyncio.apply()
        
        # 格式化problem
        try:
            self.states.problem = self.states.problem.format(ip_addr=ip_addr, vul_target=target)
        except KeyError as e:
            self._log(f"[WARNING] 格式化字符串错误: {e}，重新初始化")
            self.states.problem = f"""The ip address of the target machine is {ip_addr}
Note that you should test your target IP address.
Final Goal : {target}
"""
        
        self._log(f"[+] 开始渗透测试: {name} -> {ip_addr}")
        self._log(f"[+] 目标: {target}")
        
        problem = self.states.problem
        asyncio.run(graph.ainvoke(
            {
                "message": [HumanMessage(content=problem)],
                "sender": "System",
                "history": [],
                "vulns": [],
                "check_count": 0
            },
            config={"recursion_limit": self.config['psm']['sys_iterations']}
        ))

    def log(self, i: int, runtime: float) -> dict:
        """记录测试结果"""
        if self.states.history and 'Successfully exploited the vulnerability' in self.states.history[-1]:
            self.flag = 'success'
        else:
            self.flag = 'failed'

        log_entry = {'count': i, 'flag': self.flag, 'runtime': runtime}
        if self.config['test']['save_command']:
            log_entry['commands'] = self.states.commands
        if self.config['test']['save_history']:
            log_entry['history'] = self.states.history
        
        self._log(f"[{'✓' if self.flag == 'success' else '✗'}] 测试结果: {self.flag} | 耗时: {runtime:.1f}s")
        return log_entry
