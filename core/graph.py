import sqlite3
from langchain_deepseek import ChatDeepSeek
from langgraph.graph import END, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.checkpoint.sqlite import SqliteSaver

from tools import ALL_TOOLS
from utils.config import Config
from schema.models import AgentState
from core.nodes.security_nodes import (
    create_recon_node,
    create_analysis_node,
    create_verification_node,
    human_review_node,
    create_reporting_node,
    observer_node
)

def should_continue(state: AgentState, enable_hitl: bool = False):
    messages = state['messages']
    last_message = messages[-1]
    
    # 如果有工具调用，跳转到 tools 节点
    if hasattr(last_message, "tool_calls") and last_message.tool_calls:
        # 如果启用了 HITL 且当前是分析阶段（涉及深入扫描工具），则进入审核
        if enable_hitl and state.get("current_phase") == "scanning":
            return "review"
        return "tools"

    # 如果没有工具调用，根据当前阶段决定下一步
    phase = state.get("current_phase")
    if phase == "recon":
        return "analyze"
    elif phase == "scanning":
        # 这是一个关键跳转：如果 Analysis 发现了漏洞，下一步去验证
        if state.get("vulnerabilities"):
            return "verify"
        return "report"
    return END

def create_security_graph(model_name: str = "deepseek-chat", use_checkpoint: bool = True, enable_hitl: bool = False):
    # 初始化核心模型
    llm = ChatDeepSeek(
        model=model_name,
        api_key=Config.DEEPSEEK_API_KEY,
        base_url=Config.BASE_URL,
        temperature=0.1
    )
    
    # 按节点分配工具组
    from tools.discovery import host_survival_check, quick_port_scan, service_detail_scan
    from tools.web import nuclei_scan, waf_detection
    recon_tools = [host_survival_check, quick_port_scan, waf_detection]
    analysis_tools = [service_detail_scan, nuclei_scan, waf_detection]
    
    # 构建节点实例
    llm_recon = llm.bind_tools(recon_tools)
    llm_analysis = llm.bind_tools(analysis_tools)
    
    node_recon = create_recon_node(llm_recon)
    node_analysis = create_analysis_node(llm_analysis)
    node_verification = create_verification_node(llm_analysis) # 验证节点也使用分析工具
    node_reporting = create_reporting_node(llm)

    # 初始化工作流图
    workflow = StateGraph(AgentState)

    # 添加节点
    workflow.add_node("recon", node_recon)
    workflow.add_node("analysis", node_analysis)
    workflow.add_node("verification", node_verification)
    workflow.add_node("human_review", human_review_node)
    workflow.add_node("reporting", node_reporting)
    workflow.add_node("tools", ToolNode(ALL_TOOLS))
    workflow.add_node("observer", observer_node)

    # 设置入口
    workflow.set_entry_point("recon")

    # 1. Recon 阶段
    workflow.add_conditional_edges("recon", 
        lambda state: should_continue(state, enable_hitl), 
        {
            "tools": "tools",
            "analyze": "analysis",
            END: END
        }
    )

    # 2. 工具回调闭环
    workflow.add_edge("tools", "observer")
    workflow.add_conditional_edges("observer", 
        lambda state: "recon" if state["current_phase"] == "recon" else "analysis",
        {
            "recon": "recon",
            "analysis": "analysis"
        }
    )

    # 3. Analysis 阶段
    workflow.add_conditional_edges("analysis", 
        lambda state: should_continue(state, enable_hitl), 
        {
            "tools": "tools",
            "review": "human_review",
            "verify": "verification",
            "report": "reporting",
            END: END
        }
    )

    # 4. Verification 阶段
    workflow.add_conditional_edges("verification", 
        lambda state: "tools" if (hasattr(state['messages'][-1], "tool_calls") and state['messages'][-1].tool_calls) else "reporting",
        {
            "tools": "tools",
            "reporting": "reporting"
        }
    )

    # 5. 人工审核逻辑
    workflow.add_conditional_edges("human_review", 
        lambda state: "tools" if state.get("review_approved") else "analysis",
        {
            "tools": "tools",
            "analysis": "analysis"
        }
    )

    workflow.add_edge("reporting", END)

    # 编译并配置持久化
    if use_checkpoint:
        db_path = "checkpoints.sqlite"
        conn = sqlite3.connect(db_path, check_same_thread=False)
        memory = SqliteSaver(conn)
        return workflow.compile(checkpointer=memory)
    else:
        return workflow.compile()
