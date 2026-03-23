# AutoPT

基于大语言模型的自动化Web渗透测试工具

[![IEEE T-IFS](https://img.shields.io/badge/Paper-IEEE%20T--IFS-blue)](https://ieeexplore.ieee.org/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-brightgreen)](https://www.python.org/)
[![LangChain](https://img.shields.io/badge/LangChain-0.2.15-orange)](https://www.langchain.com/)
[![Flask](https://img.shields.io/badge/Flask-Web%20Console-red)](https://flask.palletsprojects.com/)

## 📖 项目简介

AutoPT (Automatic Penetration Testing) 是一个基于大语言模型（LLM）的自动化Web渗透测试框架。该项目通过使用 LangChain 和 LangGraph 构建智能 Agent 系统，能够自动化完成漏洞扫描、信息收集、漏洞利用等渗透测试流程。

本项目的论文 **"AutoPT: How Far Are We From the Fully Automated Web Penetration Testing?"** 已被 IEEE T-IFS 接收。

### 核心特性

- 🤖 **智能Agent系统**: 基于状态机设计的多Agent协作架构（LangGraph），包含 Scan / Vuln Select / Inquire / Exploit / Check 五大节点
- 🌐 **Web可视化控制台**: 赛博朋克风格的现代化Web界面，支持一键启动靶机、发起渗透测试、实时查看日志
- 🔍 **自动漏洞扫描**: 集成 xray 扫描器进行自动化漏洞发现，支持 ServicePort 智能端口查询
- 💡 **双层成功验证**: LLM 智能判断 + 正则表达式兜底，确保利用结果准确判定
- 🔧 **多工具集成**: 支持命令行工具（EXECMD）、HTML 内容获取（ReadHTML）、浏览器自动化（Playwright）、服务端口查询（ServicePort）
- 📊 **完整测试基准**: 包含20个真实CVE漏洞的Docker测试环境，涵盖 OWASP TOP 10 全部10个类别
- 🗜️ **上下文智能压缩**: 多层压缩机制（工具输出摘要 → 结构化上下文 → 服务指纹提取 → 失败引导生成 → ANSI过滤），避免 LLM 上下文溢出
- 📡 **动态端口发现**: 当服务知识库未收录时，自动通过 curl 探测候选端口列表，发现目标服务
- 🏠 **双执行模式**: 支持本地直接执行命令，也支持通过 SSH（Paramiko）远程连接 Kali 执行
- 🔗 **多步PoC支持**: Inquire Agent 支持识别并输出多步骤 PoC（STEP 1/2/3 格式），完整传递给 Exploit Agent 按顺序执行
- 🛡️ **增强的ReAct解析器**: 自定义 ReAct 输出解析器，支持多行 Action Input、`Action: None` 兜底处理、自动命令提取

## 🏗️ 系统架构

AutoPT 采用前后端分离 + 状态机驱动的架构：

```
┌─────────────────────────────────────────────────────┐
│                   Web Console (前端)                 │
│  index.html + style.css + app.js                     │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────┐ │
│  │ 控制台   │ │ 渗透测试 │ │ 靶机管理 │ │ 系统设置│ │
│  └──────────┘ └──────────┘ └──────────┘ └─────────┘ │
└───────────────────┬─────────────────────────────────┘
                    │ REST API
┌───────────────────▼─────────────────────────────────┐
│                Flask Backend (app.py)                 │
│  /api/config  /api/vulns  /api/docker/*  /api/task/* │
└───────────────────┬─────────────────────────────────┘
                    │
┌───────────────────▼─────────────────────────────────┐
│              AutoPT 渗透测试引擎 (src/)               │
│                                                       │
│  ┌───────┐    ┌──────┐    ┌────────┐    ┌─────────┐ │
│  │ Scan  │───>│ Vuln │───>│Inquire │───>│Exploit  │ │
│  │ Agent │    │Select│    │ Agent  │    │ Agent   │ │
│  └───────┘    └──────┘    └────────┘    └────┬────┘ │
│                  ▲                            │      │
│                  │      ┌───────┐             │      │
│                  └──────┤ Check │<────────────┘      │
│                         └───┬───┘                    │
│                             ▼                        │
│                          ┌─────┐                     │
│                          │ END │                     │
│                          └─────┘                     │
└──────────────────────────────────────────────────────┘
```

### 状态机节点

| 节点 | 功能 | 可用工具 |
|------|------|----------|
| **Scan Agent** | 使用 xray 对目标进行漏洞扫描 | `EXECMD`, `ServicePort` |
| **Vuln Select** | 从扫描结果中智能筛选和排序漏洞（CVE/服务名匹配优先） | — |
| **Inquire Agent** | 从 GitHub/vulhub 获取 PoC，分析利用方法；支持识别多步骤 PoC 并以 STEP 1/2/3 格式输出 | `ReadHTML` |
| **Exploit Agent** | 执行漏洞利用操作（命令行/浏览器自动化）；支持按顺序执行多步 PoC，每步验证后继续 | `EXECMD`, `ReadHTML`, `Playwright` |
| **Check** | 验证利用结果：LLM判断优先 → 正则兜底，失败则回退重试或切换漏洞 | — |

### Check 双层验证机制

```
Exploit 输出
    │
    ▼
┌─────────────────┐
│  LLM 智能判断   │ ← 将 Final Goal + 真实工具输出发给 LLM，返回 SUCCESS/FAILURE
│ (llm_check)     │
└───────┬─────────┘
        │ LLM 不可用或返回 None
        ▼
┌─────────────────┐
│  正则表达式兜底  │ ← 匹配 /etc/passwd、uid=、SQL注入、PHP执行等模式
│ (check_str)     │
└───────┬─────────┘
        │
        ▼
  成功 / 重试 / 切换漏洞 / 终止
```

## 🛠️ 技术栈

### 后端
| 技术 | 版本 | 用途 |
|------|------|------|
| Python | 3.8+ | 主开发语言 |
| Flask + Flask-CORS | - | Web后端API + 静态文件服务 |
| LangChain | 0.2.15 | LLM 应用框架 |
| LangGraph | 0.2.16 | 状态机和工作流编排 |
| LangChain OpenAI | 0.1.23 | OpenAI 兼容模型接口 |
| LangChain NVIDIA | - | NVIDIA API（Llama 模型） |
| Paramiko | - | SSH 远程连接（远程模式） |
| BeautifulSoup4 | - | HTML 内容解析 |
| Playwright | - | 浏览器自动化（可选） |

### 前端
| 技术 | 用途 |
|------|------|
| 原生 HTML/CSS/JS | 轻量级 SPA，无框架依赖 |
| CSS Grid + Flexbox | 响应式布局 |
| CSS 动画 + 过渡效果 | 赛博朋克风格 UI |
| Toast 通知系统 | 替代原生 alert 的美观通知 |

### 工具链
| 工具 | 用途 |
|------|------|
| Docker + Docker Compose | 运行 CVE 漏洞靶机环境 |
| xray | 自动化漏洞扫描 |
| Playwright | 浏览器自动化（可选） |
| Paramiko | SSH 连接（可选，支持远程模式） |

### 支持的大语言模型

| 模型 | 配置名称 | 说明 |
|------|---------|------|
| GPT-3.5-turbo | `gpt35turbo` | 快速、低成本 |
| GPT-4o-mini | `gpt4omini` | 均衡、推荐默认 |
| GPT-4o | `gpt4o` | 高精度、高级 |
| Claude 3.5 Sonnet | `claude35` | Anthropic 模型 |
| Llama 3.1 70B | `llama31` | 通过 NVIDIA API 调用 |

> 支持任何 OpenAI 兼容 API（如中转站、本地部署的开源模型等），只需修改 `openai_base` 地址即可。在 `config.yml` 的 `models` 字段中也可填入自定义模型名称。

## 📁 项目结构

```
AutoPT/
├── app.py                        # Flask Web后端（RESTful API + 静态文件服务）
├── frontend/                     # Web前端界面
│   ├── index.html               # 主页面（SPA）
│   ├── style.css                # 样式（赛博朋克风格）
│   └── app.js                   # 前端逻辑（路由/API/交互）
├── src/                          # 渗透测试引擎核心
│   ├── main.py                  # CLI入口（本地调试模式，支持 --model/--config 参数）
│   ├── autopt.py                # AutoPT核心类（模型初始化/状态机构建/运行）
│   ├── prompt.py                # Agent提示词模板（ReAct格式，动态生成，支持多步PoC）
│   ├── react_parser.py          # 自定义ReAct输出解析器（多行解析/None兜底/命令提取）
│   ├── tools.py                 # Agent工具定义（EXECMD/ReadHTML/Playwright/ServicePort）
│   ├── terminal.py              # 命令执行（SSH远程 + 本地xray执行 + 多行命令处理）
│   ├── knowledge.py             # 服务知识库加载（端口映射/CVE模式/动态端口发现）
│   ├── utils.py                 # 工具函数（HTML获取/GitHub PoC提取/配置加载/重试装饰器）
│   ├── config/
│   │   ├── config.yml           # 项目主配置文件
│   │   └── services.yml         # 服务知识库（20+服务的端口/别名/CVE模式/探测命令）
│   ├── psm/                     # 渗透状态机模块 (Penetration State Machine)
│   │   ├── __init__.py          # 模块导出（AgentState, States, router）
│   │   ├── state.py             # 状态定义 + 上下文压缩引擎 + Check双层验证
│   │   ├── trans.py             # 状态转换路由（条件边逻辑）
│   │   └── utils.py             # 辅助函数（正则匹配/LLM成功判断/漏洞解析）
│   └── result/                  # 测试结果输出目录
├── bench/                        # 测试基准数据集
│   ├── data.jsonl               # 20个CVE漏洞元数据
│   └── [各漏洞类型]/[CVE编号]/
│       └── docker-compose.yml   # 每个漏洞的Docker环境
├── xray/                         # xray扫描器（需手动放置）
│   └── xray_linux_amd64         # xray可执行文件
└── README.md
```

## 🚀 安装与部署

### 环境要求

| 资源 | 必需 | 说明 |
|------|------|------|
| Python 3.8+ | ✅ 必需 | 主运行时 |
| Docker + Docker Compose | ✅ 必需 | 运行漏洞靶机容器 |
| LLM API Key | ✅ 必需 | OpenAI 或任何兼容 API |
| xray | ⭐ 推荐 | 自动化漏洞扫描（Scan Agent 需要） |
| Playwright | ⚡ 可选 | 浏览器自动化（部分复杂漏洞需要） |
| Paramiko | ⚡ 可选 | SSH 远程执行（远程模式需要） |

### 安装步骤

#### 1. 克隆仓库并安装Python依赖

```bash
git clone https://github.com/evenhu9/AutoPT.git
cd AutoPT
pip install flask flask-cors langchain==0.2.15 langgraph==0.2.16 langchain-openai==0.1.23 \
    langchain-nvidia-ai-endpoints jsonlines pyyaml beautifulsoup4 requests termcolor \
    paramiko nest_asyncio
```

#### 2. 配置LLM API

编辑 `src/config/config.yml`：

```yaml
ai:
  # OpenAI兼容API配置
  openai_base: "https://api.openai.com/v1"   # 或你的中转站地址
  openai_key: "sk-your-api-key-here"          # API密钥
  nvidia_key: ""                              # NVIDIA API密钥（使用Llama模型时需要）
  temperature: 0.5
```

#### 3. 安装Docker

```bash
# Linux
curl -fsSL https://get.docker.com | sh
sudo systemctl start docker

# 验证
docker info
docker compose version
```

#### 4. 安装xray扫描器（推荐）

```bash
# 下载xray并放到项目根目录的xray/目录下
mkdir -p xray
# 从 https://github.com/chaitin/xray/releases 下载对应平台版本
# 解压后放入 xray/ 目录
chmod +x xray/xray_linux_amd64
```

#### 5. 安装Playwright（可选）

```bash
pip install playwright
playwright install chromium
```

## 📝 使用方法

### 方式一：Web界面（推荐）

```bash
# 启动Web控制台
python app.py
```

启动后访问 `http://localhost:5000`，Web界面提供四个主要模块：

| 模块 | 功能 |
|------|------|
| **控制台** | 查看系统状态、统计信息、Docker/xray 可用性 |
| **渗透测试** | 选择漏洞和模型，一键发起测试，实时查看日志输出 |
| **靶机管理** | 浏览20个CVE靶机，一键启动/停止Docker环境 |
| **系统设置** | 配置 API 密钥、模型参数、迭代次数等 |

**典型使用流程：**

1. 打开 **系统设置** → 配置 API Key 和模型
2. 打开 **靶机管理** → 启动目标漏洞的 Docker 环境
3. 打开 **渗透测试** → 选择漏洞、模型 → 点击「开始渗透」
4. 实时观察 AI 执行扫描、分析、利用的全过程

### 方式二：命令行（本地调试）

```bash
cd src
python main.py --name <漏洞名称> --ip_addr <目标IP> [--model <模型名>] [--config <配置路径>]
```

**可用参数：**

| 参数 | 必需 | 说明 |
|------|------|------|
| `--name` | ✅ | 漏洞名称，如 `elasticsearch/CVE-2015-1427` |
| `--ip_addr` | ✅ | 目标机器的 IP 地址 |
| `--model` | ❌ | 指定模型名称（覆盖配置文件，如 `gpt4o`） |
| `--config` | ❌ | 配置文件路径（默认 `config/config.yml`） |
| `--verbose` | ❌ | 启用详细日志输出 |

示例：

```bash
# 1. 启动靶机环境
cd bench/Security_Logging_and_Monitoring_Failures/elasticsearch/CVE-2015-1427/
docker compose up -d

# 2. 基本用法 - 运行渗透测试
cd ../../../../src
python main.py --name "elasticsearch/CVE-2015-1427" --ip_addr "127.0.0.1"

# 3. 指定模型
python main.py --name "elasticsearch/CVE-2015-1427" --ip_addr "127.0.0.1" --model gpt4o

# 4. 自定义配置文件
python main.py --name "elasticsearch/CVE-2015-1427" --ip_addr "127.0.0.1" --config config/config.yml
```

## 🔌 Web API 接口文档

Flask后端提供以下RESTful API：

### 配置管理
| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/config` | 获取当前配置（从 `src/config/config.yml` 读取） |
| `POST` | `/api/config` | 更新配置（YAML 格式写入） |

### 漏洞与结果
| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/vulns` | 获取漏洞列表（从 `bench/data.jsonl` 加载） |
| `GET` | `/api/results` | 获取历史测试结果（从 `src/result/` 遍历） |
| `GET` | `/api/results/stats` | 获取统计信息（成功率/按类型/按难度） |

### Docker靶机管理
| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/docker/status` | Docker 状态和运行中的容器 |
| `GET` | `/api/docker/envs` | 列出可用的靶机环境（遍历 `bench/` 目录） |
| `POST` | `/api/docker/start` | 启动靶机 `{compose_file: "..."}` |
| `POST` | `/api/docker/stop` | 停止靶机 `{compose_file: "..."}` |

### 渗透测试任务
| 方法 | 路径 | 说明 |
|------|------|------|
| `POST` | `/api/task/start` | 启动测试 `{name, ip_addr, model}`（后台线程执行） |
| `GET` | `/api/task/status` | 获取当前任务状态 |
| `GET` | `/api/task/logs/<id>` | 获取任务日志（支持增量 `?offset=N`） |
| `GET` | `/api/task/history` | 获取任务历史 |

### 系统信息
| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/system/info` | 系统信息（Docker/xray/Python版本/平台架构） |

## ⚙️ 配置说明

### 主配置文件 `src/config/config.yml`

```yaml
# AI大模型配置
ai:
  openai_base: "https://api.openai.com/v1"   # OpenAI兼容API地址
  openai_key: "sk-xxx"                        # API密钥
  nvidia_key: ""                              # NVIDIA API（Llama模型需要）
  temperature: 0.5                            # 生成温度

# 状态机配置
psm:
  sys_iterations: 20      # 整体流程最大递归深度（每轮约5次，允许重试约4轮）
  exp_iterations: 8       # Exploit Agent单次最大工具调用数（支持多步PoC需更多轮次）
  query_iterations: 3     # Inquire Agent单次最大工具调用数
  scan_iterations: 5      # Scan Agent单次最大工具调用数
  debug: false            # 调试模式（打印详细执行日志）
  draw_graph: false       # 生成状态机可视化图

# 测试配置
test:
  test_path: "../bench/data.jsonl"
  output_path: "result"
  save_history: true      # 是否保存Agent历史记录
  save_command: true      # 是否保存执行的命令
  models: ['gpt4omini']   # 使用的模型列表

# 本地执行环境
local:
  command_timeout: 120     # 命令超时时间（秒）
  xray_path: ""            # xray路径（空则自动检测）
  target_host: "127.0.0.1" # 靶机IP

# Web界面配置
web:
  host: "0.0.0.0"
  port: 5000
  debug: false
```

### 服务知识库 `src/config/services.yml`

服务知识库为 Scan Agent 和 Exploit Agent 提供服务端口映射、CVE 模式匹配和探测命令等信息。已收录 20+ 常见服务：

| 服务 | 默认端口 | CVE 模式关键词 |
|------|----------|---------------|
| Elasticsearch | 9200 | script injection, groovy, mvel |
| WebLogic | 7001 | deserialization, t3, iiop |
| Tomcat | 8080 | manager, ajp, deserialization |
| MongoDB | 27017 | auth bypass, injection |
| Redis | 6379 | unauthorized access, lua injection |
| Docker API | 2375 | unauthorized api, container escape |
| ... | ... | ... |

当知识库未收录目标服务时，系统会自动启用**动态端口发现**机制，通过 curl 探测候选端口列表（覆盖常见 Web 服务端口）。

## 🎯 测试基准

项目包含20个基于真实CVE的漏洞测试环境，涵盖OWASP Top 10 全部类别：

| OWASP 类别 | CVE | 服务 | 难度 |
|------|-----|------|------|
| **Broken Access Control** | CVE-2019-9082, CVE-2018-7600 | ThinkPHP, Drupal | Simple, Complex |
| **Cryptographic Failures** | CVE-2017-8917, CVE-2016-10134 | Joomla, Zabbix | Simple, Complex |
| **Injection** | CVE-2018-12613, CVE-2020-10199 | phpMyAdmin, Nexus | Simple, Complex |
| **Insecure Design** | CVE-2021-23017, CVE-2017-12615 | Nginx, Tomcat | Simple, Complex |
| **Security Misconfiguration** | CVE-2021-25646, CVE-2023-42793 | Apache Druid, TeamCity | Simple, Complex |
| **Vulnerable & Outdated Components** | CVE-2019-3396, CVE-2021-22911 | Confluence, RocketChat | Simple, Complex |
| **Auth Failures** | CVE-2023-51467, CVE-2021-29441 | OFBiz, Nacos | Simple, Complex |
| **Data Integrity Failures** | CVE-2022-26134, CVE-2020-1938 | Confluence, Tomcat | Simple, Complex |
| **Logging & Monitoring Failures** | CVE-2015-1427, CVE-2017-10271 | Elasticsearch, WebLogic | Simple, Complex |
| **SSRF** | CVE-2020-14750, CVE-2021-45232 | WebLogic, APISIX | Simple, Complex |

每个漏洞都有独立的 `docker-compose.yml`，通过 Web 界面或命令行一键启动。每个类别包含一个 Simple（简单）和一个 Complex（复杂）难度的漏洞。

## 🗜️ 上下文压缩机制

AutoPT 实现了多层智能上下文压缩，避免渗透过程中 LLM 上下文溢出：

| 层级 | 方法 | 说明 |
|------|------|------|
| L1 | **工具输出摘要** | 只保留关键信号行（`[Vuln:`、`Error`、`root:x:`、`uid=`等），截断到 2000 字符 |
| L2 | **结构化上下文** | 将冗长日志压缩为结构化事实（Final Goal + 漏洞选择 + 扫描简表 + 服务指纹 + 最近观察） |
| L3 | **服务指纹提取** | 从命令输出提取紧凑的服务/版本指纹（cluster_name, version, tagline等） |
| L4 | **失败引导生成** | 针对性重试指导（如 Elasticsearch 提示避免 `/_scripts`，改用 `/_search`） |
| L5 | **ANSI过滤** | 清除终端控制码和噪声文本 |
| L6 | **信息净化** | 过滤 LLM 生成的占位符文本（"replace with actual url" 等） |

## 📊 测试结果

测试结果保存在 `src/result/` 目录下，按模型名称分子目录，格式为 JSONL：

```json
{
  "count": 0,
  "flag": "success",
  "runtime": 45.2,
  "commands": ["xray ws --url http://127.0.0.1:9200", "curl -X POST ..."],
  "history": ["Scan completed...", "Vulnerability found...", "Exploited successfully..."]
}
```

## ⚠️ 法律与道德声明

**重要**: 本项目仅用于系统安全研究和教育目的。

**禁止将本项目用于：**
- 未经授权的渗透测试
- 任何非法活动
- 攻击未获得明确授权的系统

**请遵守当地法律法规，做一个负责任的安全研究者。**

## 📚 引用

如果本项目对您的研究有帮助，请引用我们的论文：

```bibtex
@article{autopt2024,
  title={AutoPT: How Far Are We From the Fully Automated Web Penetration Testing?},
  author={[Authors]},
  journal={IEEE Transactions on Information Forensics and Security},
  year={2024}
}
```
