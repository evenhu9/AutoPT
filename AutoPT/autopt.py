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
from IPython.display import Image, display

from langchain_nvidia_ai_endpoints import ChatNVIDIA

from langchain_core.language_models import BaseChatModel
from tools import new_terminal_tool, cat_html_tool, playwright_tool
from utils import retry
from psm import AgentState, States, router


import asyncio
import nest_asyncio

openai_api_base = "set your OpenAI api url here"
openai_api_key = "set your OpenAI api key here"

# LangSmith
os.environ["LANGCHAIN_TRACING_V2"] = "true"
os.environ["LANGCHAIN_PROJECT"] = ""
os.environ["LANGCHAIN_API_KEY"] = ""


class AutoPT:
    def __init__(self, pname, config, ip_addr, states):
        self.config = config
        self.models = self.config['test']['models']
        self.pname = pname
        self.ip_addr = ip_addr
        self.states = states
        self.flag = 'failed'


    def llm_init(self, config: dict, model_name: str) -> BaseChatModel:
        if 'gpt4omini' ==  model_name:
            model = "gpt-4o-mini-2024-07-18"
            res_name = f"{config['test']['output_path']}/4omini/{self.pname.replace('/', '_')}_{model_name}_FSM.jsonl"
        # model = "gpt-4-turbo-2024-04-09"
        elif 'gpt4o' == model_name:
            model = "gpt-4o"
            res_name = f"{config['test']['output_path']}/4o/{self.pname.replace('/', '_')}_{model_name}_FSM.jsonl"
        elif 'llama31' == model_name:
            model = "meta/llama-3.1-70b-instruct"
            res_name = f"{config['test']['output_path']}/llama31/{self.pname.replace('/', '_')}_{model_name}_FSM.jsonl"

        elif 'claude35' == model_name:
            model = "claude-3-5-sonnet-20240620"
            res_name = f"{config['test']['output_path']}/claude35/{self.pname.replace('/', '_')}_{model_name}_FSM.jsonl"
        else:
            model = "gpt-3.5-turbo-0125"
            res_name = f"{config['test']['output_path']}/35/{self.pname.replace('/', '_')}_{model_name}_FSM.jsonl"

        if 'llama31' == model_name:
            llm = ChatNVIDIA(temperature=config['ai']['temperature'], model=model, api_key=config['ai']['nvidia_key'])
        else:
            llm = ChatOpenAI(temperature=config['ai']['temperature'], model=model, openai_api_key=config['ai']['openai_key'], openai_api_base=config['ai']['openai_base'])
        return llm, res_name



    def state_machine_init(self, llm) -> CompiledGraph:
        # scan agent
        scan_tools = new_terminal_tool()
        scan = create_react_agent(
            llm=llm,
            tools=scan_tools,
            prompt=PromptTemplate.from_template(Prompts.scan_prompt)
        )

        scannode = functools.partial(self.states.agent_state, agent=scan, tools=scan_tools, sname="Scan")

        # inquire agent
        inquire_tools = cat_html_tool()
        inquire = create_react_agent(
            llm=llm,
            tools=inquire_tools,
            prompt=PromptTemplate.from_template(Prompts.inquire_prompt)
        )

        inquirenode = functools.partial(self.states.agent_state, agent=inquire, tools=inquire_tools, sname="Inquire")

        # exploit agent
        exploit_tools = []
        exploit_tools = new_terminal_tool()
        exploit_tools = playwright_tool(exploit_tools)
        exploit = create_react_agent(
            llm=llm,
            tools=exploit_tools,
            prompt=PromptTemplate.from_template(Prompts.expoilt_prompt)
        )

        exploitnode = functools.partial(self.states.agent_state, agent=exploit, tools=exploit_tools, sname="Exploit")

        workflow = StateGraph(AgentState)

        workflow.add_node("Scan", scannode)
        workflow.add_node("Inquire", inquirenode)
        workflow.add_node("Exploit", exploitnode)
        workflow.add_node("Vuln_select", self.states.vuln_select_state)
        workflow.add_node("Check", self.states.check_state)

        workflow.add_conditional_edges(
            "Scan",
            router,
            {"Vuln_select": "Vuln_select"},
        )
        workflow.add_conditional_edges(
            "Inquire",
            router,
            {"Exploit": "Exploit"},
        )
        workflow.add_conditional_edges(
            "Exploit",
            router,
            {"Check": "Check"},
        )
        workflow.add_conditional_edges(
            "Vuln_select",
            router,
            {"Inquire": "Inquire"},
        )
        workflow.add_conditional_edges(
            "Check",
            router,
            {"Vuln_select": "Vuln_select", "Exploit": "Exploit", "__end__": END},
        )

        workflow.add_edge(START, "Scan")
        autopt_graph = workflow.compile(debug=self.config['psm']['debug'])
        
        # 画出执行架构图
        if self.config['psm']['draw_graph']:
            display(Image(autopt_graph.get_graph(xray=True).draw_mermaid_png(output_file_path='./graph.png')))


        return autopt_graph


    @retry(max_retries=3, retry_delay=2)
    def state_machine_run(self, graph: CompiledGraph, name: str, ip_addr: str):
        with jsonlines.open(self.config['test']['test_path'], 'r') as reader:
            for vul in reader:
                if vul['name'] == name:
                    target = vul['target']
                    break
        nest_asyncio.apply()
        # 格式化 problem 并保存到 states 对象中
        try:
            self.states.problem = self.states.problem.format(ip_addr=ip_addr, vul_target=target)
        except KeyError as e:
            # 如果格式化失败（例如字符串中包含意外的占位符），重新初始化
            print(f"[WARNING] Format string error: {e}, reinitializing problem string")
            self.states.problem = f"""The ip address of the target machine is {ip_addr}
Note that you should test your target IP address.
Final Goal : {target}
"""
        problem = self.states.problem
        asyncio.run(graph.ainvoke({"message": [HumanMessage(content=problem)], "sender": "System", "history": [], "vulns": [], "check_count": 0}, config={"recursion_limit": self.config['psm']['sys_iterations']}))



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
