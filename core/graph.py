import operator
import sqlite3
import re
from typing import Annotated, Sequence, TypedDict, List, Dict, Literal, Optional, Any

from langchain_core.messages import BaseMessage, SystemMessage, HumanMessage, AIMessage, ToolMessage
from langchain_deepseek import ChatDeepSeek
from langgraph.graph import END, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.checkpoint.sqlite import SqliteSaver

from tools import ALL_TOOLS
from utils.config import Config
from schema import HostInfo, Vulnerability, ScanRecord

# 定义 Agent 状态
class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], operator.add]
    targets: List[str]
    discovered_hosts: Dict[str, HostInfo]
    vulnerabilities: List[Vulnerability]
    scan_history: List[ScanRecord]
    current_phase: Literal["recon", "scanning", "analyzing", "reporting"]
    review_approved: bool

# --- 优化后的提示词：严禁冗余输出 ---

RECON_PROMPT = """你是一名高效的侦察专家。
任务：发现目标并识别开放端口。
约束：
1. 仅输出工具调用或对发现端口的极简总结（如：发现端口 80, 445）。
2. **严禁生成任何形式的正式报告或建议**。
3. 任务完成后直接结束当前回复。
"""

ANALYSIS_PROMPT = """你是一名深度的安全分析师。
任务：探测服务版本并识别漏洞风险。
当前已发现的主机信息：
{port_info}

约束：
1. 专注于识别具体服务的 CVE 漏洞和利用路径。
2. 仅输出工具调用或关键漏洞发现。
3. **不要生成总结性报告**。
"""

REPORT_PROMPT = """你是一名专业的安全审计员。
任务：根据以下发现生成最终报告。

结构化发现数据：
{findings}

约束：
1. 产出详尽的 Markdown 格式渗透测试报告。
2. 包含目标状态、端口表、漏洞研判及加固建议。
"""

# --- 辅助函数：上下文压缩与状态维护 ---

def filter_messages(messages: Sequence[BaseMessage]) -> List[BaseMessage]:
    """
    压缩上下文：
    1. 确保 ToolMessage 必须跟在对应的 AIMessage 后面。
    2. 移除过旧的工具交互对，只保留最近的交互。
    """
    if not messages:
        return []
    
    # 保留最后 6 条消息，但要确保消息完整性（AIMessage + ToolMessage 对）
    # 简单的做法：寻找最后几条消息，如果是 ToolMessage，向前追溯找到 AIMessage
    keep_count = 6
    last_msgs = list(messages[-keep_count:])
    
    # 修正：如果第一条是 ToolMessage，需要补齐其前面的 AIMessage
    if last_msgs and isinstance(last_msgs[0], ToolMessage):
        # 向前找匹配的 AIMessage
        tool_call_id = last_msgs[0].tool_call_id
        for m in reversed(messages[:-keep_count]):
            if isinstance(m, AIMessage) and m.tool_calls:
                if any(tc['id'] == tool_call_id for tc in m.tool_calls):
                    last_msgs.insert(0, m)
                    break
    
    # 进一步截断过长的内容
    final_msgs = []
    for m in last_msgs:
        if isinstance(m, (ToolMessage, AIMessage, HumanMessage)) and m.content and len(str(m.content)) > 1500:
            new_msg = m.copy()
            new_msg.content = str(m.content)[:1000] + "... [内容过长已截断]"
            final_msgs.append(new_msg)
        else:
            final_msgs.append(m)
            
    return final_msgs

def create_security_graph(model_name: str = "deepseek-chat", use_checkpoint: bool = True, enable_hitl: bool = False):
    llm = ChatDeepSeek(
        model=model_name,
        api_key=Config.DEEPSEEK_API_KEY,
        base_url=Config.BASE_URL,
        temperature=0.1
    )
    
    from tools.discovery import host_survival_check, quick_port_scan, service_detail_scan
    recon_tools = [host_survival_check, quick_port_scan]
    analysis_tools = [service_detail_scan]
    
    # 侦察节点
    llm_recon = llm.bind_tools(recon_tools)
    def recon_node(state: AgentState):
        msgs = filter_messages(state['messages'])
        # 第一次交互时添加 SystemMessage
        messages = [SystemMessage(content=RECON_PROMPT)] + msgs
        response = llm_recon.invoke(messages)
        return {"messages": [response], "current_phase": "recon"}

    # 分析节点
    llm_analysis = llm.bind_tools(analysis_tools)
    def analysis_node(state: AgentState):
        port_info = ""
        for ip, host in state.get('discovered_hosts', {}).items():
            port_info += f"- Host: {ip}\n"
            for svc in host.services:
                port_info += f"  - Port: {svc.port}/{svc.protocol}, Service: {svc.service_name}, Version: {svc.version}\n"
        
        msgs = filter_messages(state['messages'])
        system_msg = SystemMessage(content=ANALYSIS_PROMPT.format(port_info=port_info or "尚无详细信息"))
        messages = [system_msg] + msgs
        response = llm_analysis.invoke(messages)
        return {"messages": [response], "current_phase": "scanning"}

    # 报告节点
    def reporting_node(state: AgentState):
        findings = f"发现的主机数: {len(state.get('discovered_hosts', {}))}\n"
        for ip, host in state.get('discovered_hosts', {}).items():
            findings += f"IP: {ip}\n"
            for svc in host.services:
                findings += f"- {svc.port}: {svc.service_name} ({svc.version})\n"
        
        msgs = filter_messages(state['messages'])
        system_msg = SystemMessage(content=REPORT_PROMPT.format(findings=findings))
        messages = [system_msg] + msgs
        response = llm.invoke(messages)
        return {"messages": [response], "current_phase": "reporting"}

    def human_review_node(state: AgentState):
        if not enable_hitl:
            return {"review_approved": True}
        return {"review_approved": state.get("review_approved", False)}

    def should_continue(state: AgentState):
        messages = state['messages']
        last_message = messages[-1]
        if hasattr(last_message, "tool_calls") and last_message.tool_calls:
            if enable_hitl and state.get("current_phase") == "scanning":
                return "review"
            return "tools"
        phase = state.get("current_phase")
        if phase == "recon": return "analyze"
        elif phase == "scanning": return "report"
        return END

    workflow = StateGraph(AgentState)
    workflow.add_node("recon", recon_node)
    workflow.add_node("analysis", analysis_node)
    workflow.add_node("human_review", human_review_node)
    workflow.add_node("reporting", reporting_node)
    workflow.add_node("tools", ToolNode(ALL_TOOLS))

    workflow.set_entry_point("recon")
    workflow.add_conditional_edges("recon", should_continue, {"tools": "tools", "analyze": "analysis", END: END})

    def tools_condition(state: AgentState):
        return "recon" if state.get("current_phase") == "recon" else "analysis"

    workflow.add_conditional_edges("tools", tools_condition, {"recon": "recon", "analysis": "analysis"})
    workflow.add_conditional_edges("analysis", should_continue, {"tools": "tools", "review": "human_review", "report": "reporting", END: END})
    workflow.add_conditional_edges("human_review", lambda state: "tools" if state.get("review_approved") else "analysis", {"tools": "tools", "analysis": "analysis"})
    workflow.add_edge("reporting", END)

    if use_checkpoint:
        conn = sqlite3.connect("checkpoints.sqlite", check_same_thread=False)
        return workflow.compile(checkpointer=SqliteSaver(conn))
    return workflow.compile()
