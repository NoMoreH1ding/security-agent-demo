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
from core.nodes.planner_node import planner_node

def should_continue(state: AgentState, enable_hitl: bool = False):
    messages = state['messages']
    last_message = messages[-1]
    phase = state.get("current_phase")
    
    # 1. 如果有工具调用，始终跳转到 tools 节点
    if hasattr(last_message, "tool_calls") and last_message.tool_calls:
        if enable_hitl and phase == "analysis":
            return "review"
        return "tools"

    # 2. 阶段转换指令识别
    content = last_message.content if last_message.content else ""
    content_upper = content.upper()
    
    # 如果已经在验证阶段，且提到完成或报告，则结束
    if phase == "verification":
        if "[DONE]" in content_upper or "[REPORT]" in content_upper:
            return "report"
        # 即使它误输了 [VERIFY]，在验证阶段也应视为完成，除非有工具调用
        if "[VERIFY]" in content_upper:
            return END

    # 从分析阶段跳转到验证
    if "[VERIFY]" in content_upper:
        return "verify"
    
    if "[REPORT]" in content_upper:
        return "report"

    # 3. 阶段终结逻辑
    return END

def create_security_graph(model_name: str = "deepseek-chat", use_checkpoint: bool = True, enable_hitl: bool = False):
    # ... (llm 初始化部分保持不变)
    llm = ChatDeepSeek(
        model=model_name,
        api_key=Config.DEEPSEEK_API_KEY,
        base_url=Config.BASE_URL,
        temperature=0.1
    )
    
    # 按角色重新分配工具组：严禁权限重叠
    from tools.recon import host_survival_check, quick_port_scan, waf_detection
    from tools.analysis import service_detail_scan, sqlmap_scan, nuclei_scan, dir_search, fingerprint_whatweb
    from tools.verification import web_request, sqlmap_verify, web_login_analyzer
    from tools.common import web_request as common_web_request
    from tools.shiro_detect import shiro_detect

    # ANALYSIS 阶段补全专项扫描工具，减少对通用 web_request 的依赖
    recon_tools = [host_survival_check, quick_port_scan, waf_detection]
    analysis_tools = [
        service_detail_scan, sqlmap_scan, nuclei_scan, 
        dir_search, fingerprint_whatweb, web_login_analyzer, 
        common_web_request, shiro_detect
    ]
    verification_tools = [web_request, sqlmap_verify, web_login_analyzer, nuclei_scan]


    
    # 构建节点实例
    llm_recon = llm.bind_tools(recon_tools)
    llm_analysis = llm.bind_tools(analysis_tools)
    node_recon = create_recon_node(llm_recon)
    node_analysis = create_analysis_node(llm_analysis)
    # 验证节点使用专用工具组
    node_verification = create_verification_node(llm.bind_tools(verification_tools))
    node_reporting = create_reporting_node(llm)

    # 初始化工作流图
    workflow = StateGraph(AgentState)

    # 添加节点
    workflow.add_node("planner", planner_node)
    workflow.add_node("recon", node_recon)
    workflow.add_node("analysis", node_analysis)
    workflow.add_node("verification", node_verification)
    workflow.add_node("human_review", human_review_node)
    workflow.add_node("reporting", node_reporting)
    workflow.add_node("tools", ToolNode(ALL_TOOLS))
    workflow.add_node("observer", observer_node)

    # 动态入口：根据 phase 决定起点
    def route_start(state: AgentState):
        phase = state.get("current_phase")
        if phase == "recon": return "recon"
        if phase == "analysis": return "analysis"
        if phase == "verification": return "verification"
        if phase == "reporting": return "reporting"
        return "planner"

    workflow.set_conditional_entry_point(
        route_start,
        {
            "recon": "recon",
            "analysis": "analysis",
            "verification": "verification",
            "reporting": "reporting",
            "planner": "planner"
        }
    )

    # 0. Planner 默认流向 (仅当从 planner 开始时)
    workflow.add_edge("planner", "recon")

    # 1. Recon 阶段
    workflow.add_conditional_edges("recon", 
        lambda state: should_continue(state, enable_hitl), 
        {
            "tools": "tools",
            "verify": "analysis",
            "report": "reporting",
            END: END
        }
    )

    # 2. 工具回调闭环
    workflow.add_edge("tools", "observer")
    workflow.add_conditional_edges("observer", 
        lambda state: state["current_phase"],
        {
            "recon": "recon",
            "verification": "verification",
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
        lambda state: should_continue(state, enable_hitl), 
        {
            "tools": "tools",
            "review": "human_review",
            "report": "reporting",
            "verify": "verification",
            END: END
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
