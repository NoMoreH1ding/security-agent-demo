"""
Planner 节点 - 任务规划与分发

职责：
1. 解析用户自然语言指令
2. 提取目标 IP、认证信息、扫描深度等关键参数
3. 为 Recon/Analysis/Verification/Reporting 各节点生成专属任务指令
4. 隔离原始用户输入中的"越权指令"（如"生成报告"），防止污染下游节点
"""

import re
import json
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_core.output_parsers import StrOutputParser
from schema.models import AgentState

PLANNER_SYSTEM_PROMPT = """你是一个专业的渗透测试任务规划器。
你的任务是将用户的自然语言指令拆解为结构化的子任务，分发给后续的专业节点。

### 可用的下游节点及其职责：
- **recon**: 网络层侦察。仅负责：主机存活检查、端口扫描、WAF 探测。**禁止**访问 URL 路径、尝试登录、执行破坏性操作。
- **analysis**: 漏洞发现与分析。负责：服务深度识别、Nuclei 扫描、目录爆破、SQL 注入探测、参数 Fuzz 等。
- **verification**: 漏洞验证与 PoC。负责：HTTP 请求验证、SQLmap 深度利用、登录状态测试。
- **reporting**: 审计报告生成。负责：汇总所有发现，生成正式报告。

### 你的输出格式：
你必须输出一个 JSON 对象，包含以下字段：
```json
{
    "targets": ["目标IP或域名"],
    "recon_task": "给 recon 节点的专属指令。只包含网络层侦察任务，不包含任何 URL 访问、登录、报告生成指令。",
    "analysis_task": "给 analysis 节点的专属指令。包含漏洞发现任务，如果用户提到了特定服务或端口，请在此说明。",
    "verification_task": "给 verification 节点的专属指令。包含漏洞验证和 PoC 获取任务。",
    "reporting_task": "给 reporting 节点的专属指令。说明报告需要包含的内容。",
    "auth_credentials": {"目标:端口": "Cookie 或认证信息"},
    "scan_depth": "basic | standard | deep"
}
```

### 关键规则：
1. **隔离原则**：recon_task 中**绝对不能**包含访问 URL 路径、尝试登录、执行 setup/reset 等指令。recon 只做端口扫描。
2. **完整性**：根据用户输入尽可能填充所有字段。如果用户未提及某阶段任务，该字段填写 "按标准流程执行"。
3. **认证信息提取**：如果用户提到了用户名/密码，请提取到 auth_credentials。格式示例：{"192.168.1.1:80": "PHPSESSID=xxx; security=low"}
4. **扫描深度**：basic=仅端口扫描, standard=+漏洞扫描, deep=+Fuzz/登录验证。

### 示例：
用户输入: "对 192.168.1.100 进行安全审计，80 端口是 DVWA，用 admin/password 登录，看看有没有 SQL 注入"

输出:
```json
{
    "targets": ["192.168.1.100"],
    "recon_task": "对 192.168.1.100 执行网络层侦察：确认主机存活、扫描开放端口、探测 WAF 状态。",
    "analysis_task": "对 80 端口的 DVWA 服务进行漏洞分析：执行 Nuclei 扫描、目录爆破、SQL 注入探测（重点关注 SQL 注入漏洞）。",
    "verification_task": "使用 admin/password 凭证登录 DVWA 后，对发现的 SQL 注入点进行深度验证，获取数据库版本信息。",
    "reporting_task": "生成包含侦察结果、漏洞发现、SQL 注入验证 PoC 和认证突破证据的审计报告。",
    "auth_credentials": {"192.168.1.100:80": "username=admin&password=password"},
    "scan_depth": "deep"
}
```

只输出 JSON，不要输出任何其他内容。"""


def planner_node(state: AgentState):
    """
    Planner 节点：解析用户输入，为后续节点分发任务。
    使用规则+LLM 混合解析，确保可靠性。
    """
    from langchain_deepseek import ChatDeepSeek
    from utils.config import Config
    
    user_input = ""
    for msg in state.get("messages", []):
        if isinstance(msg, HumanMessage):
            content = msg.content if isinstance(msg.content, str) else str(msg.content)
            user_input += content
    
    # 第一步：规则提取目标 IP
    targets = state.get("targets", [])
    if not targets:
        ip_match = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', user_input)
        targets = ip_match if ip_match else ["unknown"]
    
    # 第二步：使用 LLM 生成任务分解
    llm = ChatDeepSeek(
        model="deepseek-chat",
        api_key=Config.DEEPSEEK_API_KEY,
        base_url=Config.BASE_URL,
        temperature=0.1
    )
    
    planner_messages = [
        SystemMessage(content=PLANNER_SYSTEM_PROMPT),
        HumanMessage(content=f"用户输入: {user_input}\n\n请输出 JSON 任务分解：")
    ]
    
    try:
        response = llm.invoke(planner_messages)
        content = response.content
        
        # 提取 JSON（可能包裹在 ```json ... ``` 中）
        json_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', content)
        if json_match:
            json_str = json_match.group(1)
        else:
            json_str = content
        
        plan = json.loads(json_str)
    except Exception as e:
        # 降级：使用默认任务分解
        plan = {
            "recon_task": f"对目标 {', '.join(targets)} 执行网络层侦察：确认主机存活、扫描开放端口、探测 WAF 状态。",
            "analysis_task": "按标准流程执行漏洞分析：服务深度识别、Nuclei 扫描、目录爆破。",
            "verification_task": "按标准流程执行漏洞验证：HTTP 请求验证、PoC 获取。",
            "reporting_task": "生成包含所有发现的正式审计报告。",
            "auth_credentials": {},
            "scan_depth": "standard"
        }
    
    # 第三步：构建专属任务指令
    planned_tasks = {
        "recon": plan.get("recon_task", f"对目标 {', '.join(targets)} 执行网络层侦察。"),
        "analysis": plan.get("analysis_task", "按标准流程执行漏洞分析。"),
        "verification": plan.get("verification_task", "按标准流程执行漏洞验证。"),
        "reporting": plan.get("reporting_task", "生成正式审计报告。"),
    }
    
    # 第四步：提取认证凭证
    sessions = state.get("sessions", {})
    auth_creds = plan.get("auth_credentials", {})
    if auth_creds:
        sessions.update(auth_creds)
    
    return {
        "targets": targets,
        "planned_tasks": planned_tasks,
        "sessions": sessions,
    }
