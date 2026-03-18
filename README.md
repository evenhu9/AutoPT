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

- 🤖 **智能Agent系统**: 基于状态机设计的多Agent协作架构（LangGraph）
- 🌐 **Web可视化控制台**: 提供现代化的Web界面，支持一键启动靶机、发起渗透测试、实时查看日志
- 🔍 **自动漏洞扫描**: 集成xray等工具进行自动化漏洞发现
- 💡 **智能决策**: 利用大语言模型进行漏洞分析和利用策略制定
- 🔧 **多工具集成**: 支持命令行工具、浏览器自动化（Playwright）等
- 📊 **完整测试基准**: 包含20个真实CVE漏洞的Docker测试环境，涵盖OWASP TOP 10多种类型
- 🗜️ **上下文智能压缩**: 多层压缩机制（工具输出摘要 → 结构化上下文 → 服务指纹提取），避免LLM上下文溢出
- 🏠 **本地执行模式**: 支持本地直接执行命令（无需SSH远程连接）

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
│              AutoPT 渗透测试引擎                      │
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

### 核心组件

| 组件 | 功能 |
|------|------|
| **Scan Agent** | 使用xray对目标进行漏洞扫描 |
| **Vuln Select** | 从扫描结果中智能选择合适的漏洞 |
| **Inquire Agent** | 收集漏洞详细信息，分析利用方法 |
| **Exploit Agent** | 执行漏洞利用操作（命令行/浏览器自动化） |
| **Check** | 验证利用是否成功，失败则回退重试 |

## 🛠️ 技术栈

### 后端
| 技术 | 版本 | 用途 |
|------|------|------|
| Python | 3.8+ | 主开发语言 |
| Flask + Flask-CORS | - | Web后端API |
| LangChain | 0.2.15 | LLM应用框架 |
| LangGraph | 0.2.16 | 状态机和工作流编排 |
| LangChain OpenAI | 0.1.23 | OpenAI兼容模型接口 |

### 前端
| 技术 | 用途 |
|------|------|
| 原生HTML/CSS/JS | 轻量级SPA，无框架依赖 |
| CSS Grid + Flexbox | 响应式布局 |
| CSS动画 + 过渡效果 | 赛博朋克风格UI |
| Toast通知系统 | 替代原生alert的美观通知 |

### 工具链
| 工具 | 用途 |
|------|------|
| Docker + Docker Compose | 运行CVE漏洞靶机环境 |
| xray | 自动化漏洞扫描 |
| Playwright | 浏览器自动化（可选） |
| Paramiko | SSH连接（可选，支持远程模式） |

### 支持的大语言模型

| 模型 | 配置名称 | 说明 |
|------|---------|------|
| GPT-3.5-turbo | `gpt35turbo` | 快速、低成本 |
| GPT-4o-mini | `gpt4omini` | 均衡、推荐默认 |
| GPT-4o | `gpt4o` | 高精度、高级 |

> 支持任何 OpenAI 兼容 API（如中转站、本地部署的开源模型等），只需修改 `openai_base` 地址即可。

## 📁 项目结构

```
AutoPT/
├── app.py                        # Flask Web后端（RESTful API）
├── frontend/                     # Web前端界面
│   ├── index.html               # 主页面（SPA）
│   ├── style.css                # 样式（赛博朋克风格）
│   └── app.js                   # 前端逻辑（路由/API/交互）
├── AutoPT/                       # 渗透测试引擎核心
│   ├── main.py                  # CLI入口（命令行模式）
│   ├── autopt.py                # AutoPT核心类（模型初始化/状态机构建/运行）
│   ├── prompt.py                # Agent提示词模板
│   ├── tools.py                 # Agent工具定义（终端/HTML解析/浏览器）
│   ├── terminal.py              # 命令执行（本地Shell / SSH远程）
│   ├── utils.py                 # 工具函数（配置加载等）
│   ├── config/
│   │   └── config.yml           # 项目配置文件
│   └── psm/                     # 渗透状态机模块 (Penetration State Machine)
│       ├── state.py             # 状态定义 + 上下文压缩引擎
│       ├── trans.py             # 状态转换路由
│       └── utils.py             # 辅助函数
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
| LLM API Key | ✅ 必需 | OpenAI或任何兼容API |
| xray | ⭐ 推荐 | 自动化漏洞扫描（扫描阶段需要） |
| Playwright | ⚡ 可选 | 浏览器自动化（部分复杂漏洞需要） |

### 安装步骤

#### 1. 克隆仓库并安装Python依赖

```bash
git clone https://github.com/evenhu9/AutoPT.git
cd AutoPT
pip install -r AutoPT/config/requirements.txt
```

#### 2. 配置LLM API

编辑 `AutoPT/config/config.yml`：

```yaml
ai:
  # OpenAI兼容API配置
  openai_base: "https://api.openai.com/v1"   # 或你的中转站地址
  openai_key: "sk-your-api-key-here"          # API密钥
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
| **控制台** | 查看系统状态、统计信息、Docker/xray可用性 |
| **渗透测试** | 选择漏洞和模型，一键发起测试，实时查看日志输出 |
| **靶机管理** | 浏览20个CVE靶机，一键启动/停止Docker环境 |
| **系统设置** | 配置API密钥、模型参数、迭代次数等 |

**典型使用流程：**

1. 打开 **系统设置** → 配置API Key和模型
2. 打开 **靶机管理** → 启动目标漏洞的Docker环境
3. 打开 **渗透测试** → 选择漏洞、模型 → 点击「开始渗透」
4. 实时观察AI执行扫描、分析、利用的全过程

### 方式二：命令行

```bash
cd AutoPT
python main.py --name <漏洞名称> --ip_addr <目标IP>
```

示例：

```bash
# 1. 启动靶机环境
cd bench/Security\ Logging\ and\ Monitoring\ Failures/elasticsearch/CVE-2015-1427/
docker compose up -d

# 2. 运行渗透测试
cd ../../../../AutoPT
python main.py --name "elasticsearch/CVE-2015-1427" --ip_addr "127.0.0.1"
```

## 🔌 Web API 接口文档

Flask后端提供以下RESTful API：

### 配置管理
| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/config` | 获取当前配置 |
| `POST` | `/api/config` | 更新配置 |

### 漏洞与结果
| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/vulns` | 获取漏洞列表（20个CVE） |
| `GET` | `/api/results` | 获取历史测试结果 |
| `GET` | `/api/results/stats` | 获取统计信息（成功率/按类型/按难度） |

### Docker靶机管理
| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/docker/status` | Docker状态和运行中的容器 |
| `GET` | `/api/docker/envs` | 列出可用的靶机环境 |
| `POST` | `/api/docker/start` | 启动靶机 `{compose_file: "..."}` |
| `POST` | `/api/docker/stop` | 停止靶机 `{compose_file: "..."}` |

### 渗透测试任务
| 方法 | 路径 | 说明 |
|------|------|------|
| `POST` | `/api/task/start` | 启动测试 `{name, ip_addr, model}` |
| `GET` | `/api/task/status` | 获取当前任务状态 |
| `GET` | `/api/task/logs/<id>` | 获取任务日志（支持增量`?offset=N`） |
| `GET` | `/api/task/history` | 获取任务历史 |

### 系统信息
| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/system/info` | 系统信息（Docker/xray/Python版本） |

## ⚙️ 配置说明

完整配置文件 `AutoPT/config/config.yml`：

```yaml
# AI大模型配置
ai:
  openai_base: "https://api.openai.com/v1"   # OpenAI兼容API地址
  openai_key: "sk-xxx"                        # API密钥
  nvidia_key: ""                              # NVIDIA API（可选）
  temperature: 0.5                            # 生成温度

# 状态机配置
psm:
  sys_iterations: 15      # 整体流程最大迭代次数
  exp_iterations: 3       # Exploit Agent单次最大操作数
  query_iterations: 1     # Inquire Agent单次最大操作数
  scan_iterations: 1      # Scan Agent单次最大操作数
  debug: false            # 调试模式
  draw_graph: false       # 生成状态机可视化图

# 测试配置
test:
  test_path: "../bench/data.jsonl"
  output_path: "result"
  save_history: true
  save_command: true
  models: ['gpt4omini']   # 可选: gpt35turbo, gpt4omini, gpt4o

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

## 🎯 测试基准

项目包含20个基于真实CVE的漏洞测试环境，涵盖OWASP Top 10的多个类别：

| 类别 | CVE | 服务 |
|------|-----|------|
| **Cryptographic Failures** | CVE-2017-8917, CVE-2016-10134 | Joomla, Zabbix |
| **Authentication Failures** | CVE-2023-51467, CVE-2021-29441 | OFBiz, Nacos |
| **Security Misconfiguration** | CVE-2021-25646, CVE-2023-42793 | Apache Druid, TeamCity |
| **Vulnerable Components** | CVE-2019-3396, CVE-2021-22911 | Confluence, RocketChat |
| **Data Integrity Failures** | CVE-2022-26134, CVE-2020-1938 | Confluence, Tomcat |
| **SSRF** | WebLogic SSRF, CVE-2021-45232 | WebLogic, Apisix |
| **Logging Failures** | CVE-2015-1427, CVE-2017-10271 | Elasticsearch, WebLogic |
| **Insecure Design** | Nginx解析漏洞, CVE-2017-12615 | Nginx, Tomcat |

每个漏洞都有独立的 `docker-compose.yml`，通过Web界面或命令行一键启动。

## 📊 测试结果

测试结果保存在 `AutoPT/result/` 目录下，格式为 JSONL：

```json
{
  "count": 0,
  "flag": "success",
  "runtime": 45.2,
  "commands": ["xray ws --url 127.0.0.1:9200", "curl -X POST ..."],
  "history": ["Scan completed...", "Vulnerability found...", "Exploited successfully..."]
}
```

## 🔧 上下文压缩机制

AutoPT 实现了多层智能上下文压缩，避免渗透过程中LLM上下文溢出：

| 层级 | 方法 | 说明 |
|------|------|------|
| L1 | 工具输出摘要 | 只保留关键信号行（漏洞、错误、版本），截断到2000字符 |
| L2 | 结构化上下文 | 将冗长日志压缩为结构化事实（漏洞列表+服务指纹） |
| L3 | 服务指纹提取 | 从命令输出提取紧凑的服务/版本指纹 |
| L4 | 失败引导生成 | 针对性重试指导，避免重复侦察 |
| L5 | ANSI过滤 | 清除终端控制码和噪声文本 |

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
