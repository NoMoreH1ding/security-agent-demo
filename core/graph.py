import operator
from typing import Annotated, Sequence, TypedDict, List, Dict, Literal, Optional, Any

from langchain_core.messages import BaseMessage, SystemMessage
from langchain_deepseek import ChatDeepSeek
from langgraph.graph import END, StateGraph
from langgraph.prebuilt import ToolNode

from tools import ALL_TOOLS
from utils.config import Config
from schema import HostInfo, Vulnerability, ScanRecord

# 定义 Agent 状态
class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], operator.add]
    # 新增结构化状态字段
    targets: List[str]
    discovered_hosts: Dict[str, HostInfo]
    vulnerabilities: List[Vulnerability]
    scan_history: List[ScanRecord]
    current_phase: Literal["recon", "scanning", "analyzing", "reporting"]

# 系统提示词定义
RECON_PROMPT = """你是一名专业的侦察专家。你的任务是发现目标并确定其开放端口。
目前可用的工具：
1. host_survival_check: 检查目标主机是否在线。
2. quick_port_scan: 快速确定目标的端口开放信息。

工作流程：
- 首先使用 host_survival_check 确认目标存活。
- 若目标存活，使用 quick_port_scan 获取开放端口列表。
任务完成后，请简洁地总结发现。
"""

ANALYSIS_PROMPT = """你是一名专业的安全分析师。你的任务是深入探测服务版本并进行漏洞研判。
目前可用的工具：
1. service_detail_scan: 针对开放端口进行深入的服务版本和 OS 探测。

工作流程：
- 针对发现的开放端口，使用 service_detail_scan 获取详细信息。
- 根据收集到的版本信息研判存在的重大 CVE 漏洞和风险。
"""

REPORT_PROMPT = """你是一名专业的安全审计员。你的任务是将所有发现总结成一份结构化的 Markdown 报告。
报告应包含：
1. 目标主机状态
2. 开放端口与服务版本表格
3. 潜在漏洞与风险分析
4. 后续修复建议
"""

def create_security_graph(model_name: str = "deepseek-chat"):
    # 初始化模型
    llm = ChatDeepSeek(
        model=model_name,
        api_key=Config.DEEPSEEK_API_KEY,
        base_url=Config.BASE_URL,
        temperature=0.1
    )
    
    # 按节点分配工具
    from tools.discovery import host_survival_check, quick_port_scan, service_detail_scan
    recon_tools = [host_survival_check, quick_port_scan]
    analysis_tools = [service_detail_scan]
    
    # 侦察节点：仅绑定发现工具
    llm_recon = llm.bind_tools(recon_tools)
    def recon_node(state: AgentState):
        messages = [SystemMessage(content=RECON_PROMPT)] + list(state['messages'])
        response = llm_recon.invoke(messages)
        return {"messages": [response], "current_phase": "recon"}

    # 分析节点：仅绑定深入扫描工具
    llm_analysis = llm.bind_tools(analysis_tools)
    def analysis_node(state: AgentState):
        # 提取之前发现的端口信息，帮助分析师决策
        messages = [SystemMessage(content=ANALYSIS_PROMPT)] + list(state['messages'])
        response = llm_analysis.invoke(messages)
        return {"messages": [response], "current_phase": "scanning"}

    # 报告节点
    def reporting_node(state: AgentState):
        messages = [SystemMessage(content=REPORT_PROMPT)] + list(state['messages'])
        response = llm.invoke(messages)
        return {"messages": [response], "current_phase": "reporting"}

    def should_continue(state: AgentState):
        messages = state['messages']
        last_message = messages[-1]
        
        # 如果有工具调用，跳转到 tools 节点
        if hasattr(last_message, "tool_calls") and last_message.tool_calls:
            return "tools"

        # 如果没有工具调用，根据当前阶段决定下一步
        phase = state.get("current_phase")
        if phase == "recon":
            return "analyze"
        elif phase == "scanning":
            return "report"
        return END

    workflow = StateGraph(AgentState)

    workflow.add_node("recon", recon_node)
    workflow.add_node("analysis", analysis_node)
    workflow.add_node("reporting", reporting_node)
    workflow.add_node("tools", ToolNode(ALL_TOOLS)) # tools 节点持有所有工具，但各 node 仅调用被绑定的

    workflow.set_entry_point("recon")

    # 侦察阶段循环
    workflow.add_conditional_edges("recon", should_continue, {
        "tools": "tools",
        "analyze": "analysis",
        END: END
    })

    # 工具节点逻辑：执行完后回到触发它的阶段
    def tools_condition(state: AgentState):
        phase = state.get("current_phase")
        if phase == "recon":
            return "recon"
        return "analysis"

    workflow.add_conditional_edges("tools", tools_condition, {
        "recon": "recon",
        "analysis": "analysis"
    })

    # 分析阶段循环
    workflow.add_conditional_edges("analysis", should_continue, {
        "tools": "tools",
        "report": "reporting",
        END: END
    })

    workflow.add_edge("reporting", END)

    return workflow.compile()

