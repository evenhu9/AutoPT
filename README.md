# AutoPT

基于大语言模型的自动化Web渗透测试工具

[![IEEE T-IFS](https://img.shields.io/badge/Paper-IEEE%20T--IFS-blue)](https://ieeexplore.ieee.org/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-brightgreen)](https://www.python.org/)
[![LangChain](https://img.shields.io/badge/LangChain-0.2.15-orange)](https://www.langchain.com/)

## 📖 项目简介

AutoPT (Automatic Penetration Testing) 是一个基于大语言模型（LLM）的自动化Web渗透测试框架。该项目通过使用LangChain和LangGraph构建智能Agent系统，能够自动化完成漏洞扫描、信息收集、漏洞利用等渗透测试流程。

本项目的论文 **"AutoPT: How Far Are We From the Fully Automated Web Penetration Testing?"** 已被 IEEE T-IFS 接收。

### 核心特性

- 🤖 **智能Agent系统**: 基于状态机设计的多Agent协作架构
- 🔍 **自动漏洞扫描**: 集成xray等工具进行自动化漏洞发现
- 💡 **智能决策**: 利用大语言模型进行漏洞分析和利用策略制定
- 🔧 **多工具集成**: 支持命令行工具、浏览器自动化等多种工具
- 📊 **完整测试基准**: 包含17个真实CVE漏洞的测试环境

## 🏗️ 系统架构

AutoPT采用基于状态机的多Agent架构，主要包含以下几个核心状态节点：

```
┌─────────┐      ┌──────────────┐      ┌─────────┐      ┌─────────┐      ┌───────┐
│  START  │ ───> │  Scan Agent  │ ───> │ Vuln    │ ───> │ Inquire │ ───> │Exploit│
└─────────┘      └──────────────┘      │ Select  │      │ Agent   │      │ Agent │
                                        └─────────┘      └─────────┘      └───┬───┘
                                             ▲                                  │
                                             │           ┌──────────┐           │
                                             └───────────┤  Check   │◄──────────┘
                                                         └────┬─────┘
                                                              │
                                                              ▼
                                                           ┌─────┐
                                                           │ END │
                                                           └─────┘
```

### 核心组件说明

1. **Scan Agent (扫描代理)**: 使用xray等工具进行漏洞扫描
2. **Vuln Select (漏洞选择)**: 从扫描结果中选择合适的漏洞进行利用
3. **Inquire Agent (查询代理)**: 收集漏洞相关信息，分析利用方法
4. **Exploit Agent (利用代理)**: 执行漏洞利用操作
5. **Check (验证)**: 验证漏洞利用是否成功

## 🛠️ 技术栈

### 核心框架
- **Python 3.8+**: 主要开发语言
- **LangChain 0.2.15**: LLM应用开发框架
- **LangGraph 0.2.16**: 状态机和工作流编排
- **LangChain OpenAI 0.1.23**: OpenAI模型接口
- **LangChain NVIDIA AI Endpoints 0.2.2**: NVIDIA模型接口

### 大语言模型支持
- GPT-4o / GPT-4o-mini
- GPT-3.5-turbo
- Claude 3.5 Sonnet
- Llama 3.1 70B

### 工具和库
- **Paramiko 3.4.0**: SSH连接和命令执行
- **Playwright**: 浏览器自动化
- **BeautifulSoup4 4.12.3**: HTML解析
- **Requests 2.32.3**: HTTP请求
- **PyYAML 6.0.1**: 配置文件解析
- **jsonlines 4.0.0**: JSONL格式数据处理

## 📁 代码结构

```
AutoPT/
├── AutoPT/                      # 主程序目录
│   ├── main.py                  # 程序入口
│   ├── autopt.py                # AutoPT核心类
│   ├── prompt.py                # Agent提示词模板
│   ├── tools.py                 # 工具定义
│   ├── utils.py                 # 工具函数
│   ├── terminal.py              # 交互式Shell实现
│   ├── requirements.txt         # 依赖包列表
│   ├── config/
│   │   └── config.yml          # 配置文件
│   └── psm/                    # 状态机模块 (Penetration State Machine)
│       ├── __init__.py
│       ├── state.py            # 状态定义和处理
│       ├── trans.py            # 状态转换逻辑
│       └── utils.py            # 辅助函数
├── bench/                       # 测试基准数据集
│   ├── README.md
│   └── [各种CVE漏洞环境]
└── README.md                    # 项目说明文档
```

### 核心文件说明

#### `main.py`
程序入口文件，负责：
- 解析命令行参数（漏洞名称、目标IP）
- 加载配置文件
- 初始化AutoPT实例
- 运行渗透测试并保存结果

#### `autopt.py`
AutoPT核心类，包含：
- `llm_init()`: 初始化不同的大语言模型
- `state_machine_init()`: 构建状态机工作流
- `state_machine_run()`: 执行渗透测试流程
- `log()`: 记录测试结果

#### `prompt.py`
定义三个核心Agent的提示词：
- `scan_prompt`: 扫描Agent的指令模板
- `inquire_prompt`: 查询Agent的指令模板
- `exploit_prompt`: 利用Agent的指令模板

#### `tools.py`
定义Agent可使用的工具：
- `new_terminal_tool()`: 命令行执行工具
- `cat_html_tool()`: HTML内容提取工具
- `playwright_tool()`: 浏览器自动化工具

#### `terminal.py`
实现与远程Shell的交互：
- `InteractiveShell`: 通过SSH连接到测试环境
- `execute_command()`: 执行命令并返回结果
- `parse_vuln()`: 解析xray扫描结果

#### `psm/state.py`
状态机核心逻辑：
- `AgentState`: 定义Agent间传递的状态
- `States`: 管理整个渗透测试流程的状态
- `agent_state()`: Agent状态处理
- `check_state()`: 验证漏洞利用结果
- `vuln_select_state()`: 选择漏洞进行利用

#### `psm/trans.py`
状态转换路由：
- `router()`: 根据当前状态和消息内容决定下一个状态

## 🚀 安装与配置

### 环境要求

- Python 3.8+
- Docker (用于运行测试环境)
- Ubuntu 22.04 (推荐)

### 安装步骤

1. **克隆仓库**
```bash
git clone https://github.com/evenhu9/AutoPT.git
cd AutoPT
```

2. **安装依赖**
```bash
cd AutoPT
pip install -r requirements.txt
```

3. **配置API密钥**

编辑 `AutoPT/config/config.yml` 文件：

```yaml
ai:
  # OpenAI API配置
  openai_base: "https://api.openai.com/v1"  # 或你的API代理地址
  openai_key: "your-openai-api-key-here"
  # NVIDIA API配置（使用Llama模型时需要）
  nvidia_key: "your-nvidia-api-key-here"
  # 模型参数
  temperature: 0

test:
  test_path: "../bench/data.jsonl"
  output_path: "result"
  save_history: True
  save_command: True
  # 选择要测试的模型
  models: ['gpt4omini']  # 可选: gpt35turbo, gpt4omini, gpt4o, claude35, llama31

psm:
  sys_iterations: 15      # 系统最大迭代次数
  exp_iterations: 1       # 利用阶段迭代次数
  query_iterations: 1     # 查询阶段迭代次数
  scan_iterations: 1      # 扫描阶段迭代次数
  debug: False
  draw_graph: False       # 是否生成状态机图
```

4. **配置测试环境**

需要配置一个运行xray等渗透测试工具的Docker环境。默认连接配置在 `terminal.py` 中：

```python
hostname='172.17.0.2'
port=22
username='root'
password='123456'
```

### 测试环境搭建

AutoPT需要一个预配置的Docker环境来执行渗透测试。参考 `bench/README.md` 搭建测试环境：

```bash
# 安装Docker
curl -s https://get.docker.com/ | sh
systemctl start docker

# 进入具体漏洞环境目录
cd bench/[漏洞类型]/[CVE编号]

# 启动测试环境
docker compose up -d
```

## 📝 使用方法

### 基本用法

```bash
cd AutoPT
python main.py --name <漏洞名称> --ip_addr <目标IP地址>
```

### 参数说明

- `--name`: 漏洞名称，对应 `bench/data.jsonl` 中的漏洞条目
- `--ip_addr`: 目标机器的IP地址

### 使用示例

测试Elasticsearch CVE-2015-1427漏洞：

```bash
# 1. 启动测试环境
cd bench/Security\ Logging\ and\ Monitoring\ Failures/elasticsearch/CVE-2015-1427/
docker compose up -d

# 2. 运行AutoPT
cd ../../../../AutoPT
python main.py --name "elasticsearch/CVE-2015-1427" --ip_addr "172.17.0.2"
```

### 结果输出

测试结果会保存在 `result/` 目录下，文件名格式为：
```
result/[模型名称]/[漏洞名称]_[模型名称]_FSM.jsonl
```

每条结果包含：
- `count`: 测试轮次
- `flag`: 成功/失败标志 (success/failed)
- `runtime`: 运行时间（秒）
- `commands`: 执行的命令列表（如果启用）
- `history`: 完整的执行历史（如果启用）

示例输出：
```json
{
  "count": 0,
  "flag": "success",
  "runtime": 45.2,
  "commands": ["xray ws --url 172.17.0.2:9200", "curl -X POST ..."],
  "history": ["Scan completed...", "Vulnerability found...", "Successfully exploited..."]
}
```

## 🎯 测试基准

项目包含17个基于真实CVE的漏洞测试环境，涵盖OWASP Top 10的多个类别：

- **Cryptographic Failures**: Joomla CVE-2017-8917, Zabbix CVE-2016-10134
- **Identification and Authentication Failures**: OFBiz CVE-2023-51467, Nacos CVE-2021-29441
- **Security Misconfiguration**: Apache Druid CVE-2021-25646, TeamCity CVE-2023-42793
- **Vulnerable Components**: Confluence CVE-2019-3396, RocketChat CVE-2021-22911
- **Software and Data Integrity Failures**: Confluence CVE-2022-26134, Tomcat CVE-2020-1938
- **SSRF**: WebLogic SSRF, Apisix CVE-2021-45232
- **Security Logging and Monitoring Failures**: Elasticsearch CVE-2015-1427, WebLogic CVE-2017-10271
- **Insecure Design**: Nginx解析漏洞, Tomcat CVE-2017-12615

详见 `bench/` 目录和 `AutoPT/finalbench.jsonl` 文件。

## 🔧 工作流程

1. **扫描阶段**: Scan Agent使用xray对目标进行漏洞扫描
2. **漏洞选择**: 从扫描结果中选择合适的漏洞
3. **信息查询**: Inquire Agent收集漏洞详细信息和利用方法
4. **漏洞利用**: Exploit Agent根据信息执行漏洞利用
5. **结果验证**: 检查利用是否成功，失败则返回重试或选择其他漏洞

整个流程由状态机自动控制，大语言模型负责分析和决策。

## 📊 支持的模型

AutoPT支持多个主流大语言模型：

| 模型 | 配置名称 | API提供商 |
|------|---------|----------|
| GPT-4o | gpt4o | OpenAI |
| GPT-4o-mini | gpt4omini | OpenAI |
| GPT-3.5-turbo | gpt35turbo | OpenAI |
| Claude 3.5 Sonnet | claude35 | Anthropic (通过OpenAI兼容接口) |
| Llama 3.1 70B | llama31 | NVIDIA AI |

## ⚙️ 高级配置

### 调整迭代次数

在 `config.yml` 中调整各阶段的迭代限制：

```yaml
psm:
  sys_iterations: 15      # 整体流程最大迭代次数
  exp_iterations: 1       # Exploit Agent单次最大操作数
  query_iterations: 1     # Inquire Agent单次最大操作数
  scan_iterations: 1      # Scan Agent单次最大操作数
```

### 启用调试模式

```yaml
psm:
  debug: True            # 显示详细的状态机执行信息
  draw_graph: True       # 生成状态机可视化图（保存为graph.png）
```

### LangSmith追踪

在 `autopt.py` 中配置LangSmith以追踪LLM调用：

```python
os.environ["LANGCHAIN_TRACING_V2"] = "true"
os.environ["LANGCHAIN_PROJECT"] = "your-project-name"
os.environ["LANGCHAIN_API_KEY"] = "your-langsmith-api-key"
```

## 🤝 贡献

欢迎提交Issue和Pull Request！

## 📄 许可证

请遵守相关开源协议。

## ⚠️ 法律与道德声明

**重要**: 本项目仅用于系统安全研究和教育目的。

**禁止将本项目用于：**
- 未经授权的渗透测试
- 任何非法活动
- 攻击未获得明确授权的系统

**使用者责任：**
- 使用本工具前必须获得目标系统所有者的明确授权
- 使用者需自行承担使用本工具产生的一切法律责任
- 开发者不对任何滥用行为负责

**请遵守当地法律法规，做一个负责任的安全研究者。**

## 📚 引用

如果本项目对您的研究有帮助，请引用我们的论文：

```
@article{autopt2024,
  title={AutoPT: How Far Are We From the Fully Automated Web Penetration Testing?},
  author={[Authors]},
  journal={IEEE Transactions on Information Forensics and Security},
  year={2024}
}
```

## 📧 联系方式

如有问题或建议，请通过GitHub Issues联系我们。
