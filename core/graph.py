import operator
from typing import Annotated, Sequence, TypedDict

from langchain_core.messages import BaseMessage, SystemMessage
from langchain_deepseek import ChatDeepSeek
from langgraph.graph import END, StateGraph
from langgraph.prebuilt import ToolNode

from tools import ALL_TOOLS
from utils.config import Config

# 定义 Agent 状态
class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], operator.add]

# 系统提示词，基于最新工具集进行优化
SYSTEM_PROMPT = """你是一名专业的自动化渗透测试助手（AI-PTA）。
你的目标是根据用户提供的意图，利用合适的工具进行渗透测试，并进行深度的漏洞研判。
你运行在 Kali Linux 系统中，拥有标准的红队工具链。

目前可用的工具：
1. host_survival_check: 检查目标主机是否在线。在进行任何扫描前必须先执行此操作。
2. quick_port_scan: 快速确定目标的端口开放信息（不含版本）。
3. service_detail_scan: 针对开放端口进行深入的服务版本和 OS 探测。

工作流程建议：
- 首先使用 host_survival_check 确认目标存活。
- 若目标存活，使用 quick_port_scan 获取开放端口列表。
- 针对发现的开放端口，使用 service_detail_scan 获取详细的服务和版本信息。
- 最后，根据收集到的指纹信息进行漏洞研判。

分析要求：
1. **版本关联**：根据服务版本号，研判该服务版本存在的重大 CVE 漏洞。
2. **风险分级**：使用 [高/中/低/紧急] 标识每个发现。
3. **报告生成**：任务完成后，输出一份包含识别到的 OS、服务、潜在漏洞及后续建议的详细报告。

在进行任何操作前，请先思考并制定计划。
"""

def create_security_graph(model_name: str = "deepseek-chat"):
    tools = ALL_TOOLS
    tool_node = ToolNode(tools)
    
    # 初始化模型
    llm = ChatDeepSeek(
        model=model_name,
        api_key=Config.DEEPSEEK_API_KEY,
        base_url=Config.BASE_URL,
        temperature=0.1
    )
    llm_with_tools = llm.bind_tools(tools)

    def call_model(state: AgentState):
        messages = state['messages']
        # 如果是第一次交互，且没有 SystemMessage，则添加一个
        if not any(isinstance(m, SystemMessage) for m in messages):
            messages = [SystemMessage(content=SYSTEM_PROMPT)] + list(messages)
        
        response = llm_with_tools.invoke(messages)
        return {"messages": [response]}

    def should_continue(state: AgentState):
        messages = state['messages']
        last_message = messages[-1]
        if hasattr(last_message, "tool_calls") and last_message.tool_calls:
            return "tools"
        return END

    workflow = StateGraph(AgentState)

    workflow.add_node("agent", call_model)
    workflow.add_node("tools", tool_node)

    workflow.set_entry_point("agent")
    workflow.add_conditional_edges("agent", should_continue, {
        "tools": "tools",
        END: END
    })
    workflow.add_edge("tools", "agent")

    return workflow.compile()
