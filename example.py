import operator
from typing import Annotated, List, Sequence, TypedDict, cast
from pydantic import SecretStr

from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage, AIMessage
from langchain_core.runnables import RunnableConfig
from langchain_deepseek import ChatDeepSeek
from langgraph.graph import END, StateGraph
from langgraph.prebuilt import ToolNode

from tools import ALL_TOOLS
from utils.config import Config
from core.callbacks import AgentTraceCallbackHandler

# 1. 定义增强型状态 (State)
# 除了消息列表，我们增加了 'plan' 用于存储待执行的任务清单
class PlanState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], operator.add]
    plan: List[str]          # 当前的任务计划列表
    past_steps: List[str]    # 已经完成的步骤记录

# 2. 定义规划逻辑 (Planner Node)
PLANNER_PROMPT = """你是一名红队指挥官。根据用户提供的目标，参考你现有的工具能力，制定一份**可落地**的渗透测试计划。

### 你目前拥有的工具能力：
{tools_info}

### 约束：
1. **量力而行**：计划中的每一步都必须能够通过上述工具之一来完成。不要规划你无法执行的任务。
2. **逻辑严密**：计划应包含逻辑步骤（例如：存活探测 -> 端口扫描 -> 服务识别 -> 报告生成）。
3. **输出格式**：直接输出步骤列表，每行一个步骤，不要包含 Markdown 格式，不要包含数字编号。"""

def planner_node(state: PlanState):
    api_key = SecretStr(cast(str, Config.DEEPSEEK_API_KEY))
    llm = ChatDeepSeek(model="deepseek-chat", api_key=api_key)

    # 动态获取工具的名称和描述，让 Planner 知道自己“能干什么”
    tools_info = "\n".join([f"- {t.name}: {t.description}" for t in ALL_TOOLS])

    # 填充提示词模板
    system_prompt = PLANNER_PROMPT.format(tools_info=tools_info)

    user_query = state['messages'][0].content
    response = llm.invoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=f"目标任务: {user_query}")
    ])

    content = response.content if isinstance(response.content, str) else str(response.content)
    plan = [line.strip() for line in content.split('\n') if line.strip()]

    print(f"\n[Planner] 基于现有工具能力制定的计划: {plan}")
    return {"plan": plan}


# 3. 定义执行逻辑 (Executor Node)
EXECUTOR_PROMPT = """你是一名专业的渗透测试执行员。
你目前正在执行一个更大计划中的**特定子步骤**。

### 你的当前任务：
{current_step}

### 已完成的步骤：
{past_steps}

### 强制约束：
1. **任务特化**：
   - 如果当前任务涉及“报告”、“总结”或“研判”，请整合之前所有发现，输出详尽的 Markdown 报告。
   - 否则，请保持简洁，不要提前执行后续步骤。
2. **最小化干扰**：在非报告阶段，给出简洁结论即可。
3. **完成即停**：完成特定任务后，如果没有工具调用，请明确告知结果。"""

def executor_node(state: PlanState):
    api_key = SecretStr(cast(str, Config.DEEPSEEK_API_KEY))
    llm = ChatDeepSeek(model="deepseek-chat", api_key=api_key)
    llm_with_tools = llm.bind_tools(ALL_TOOLS)

    # 提取进度信息
    current_step = state['plan'][0] if state['plan'] else "总结并结束"
    past_steps = ", ".join(state.get('past_steps', [])) if state.get('past_steps') else "无"

    # 构建上下文
    system_msg = SystemMessage(content=EXECUTOR_PROMPT.format(
        current_step=current_step,
        past_steps=past_steps
    ))

    messages = [system_msg] + list(state['messages'])
    response = llm_with_tools.invoke(messages)

    return {"messages": [response]}


# 4. 定义重规划逻辑 (Re-planner Node)
# 在工具执行完后，判断是否需要更新计划
def replanner_node(state: PlanState):
    # 这里简单地将已完成的步骤从计划中移除
    # 在更复杂的实现中，可以调用 LLM 根据工具结果来决定是否增加新的任务步骤
    new_plan = state['plan'][1:] if state['plan'] else []
    last_step = state['plan'][0] if state['plan'] else "Unknown"
    
    print(f"\n[Replanner] 步骤 '{last_step}' 已尝试执行，剩余计划: {new_plan}")
    return {"plan": new_plan, "past_steps": state.get('past_steps', []) + [last_step]}

# 5. 定义跳转逻辑
def should_continue(state: PlanState):
    last_msg = state['messages'][-1]
    # 如果 Agent 还在调用工具，继续留在执行循环内 (executor -> tools -> executor)
    if isinstance(last_msg, AIMessage) and last_msg.tool_calls:
        return "tools"
    # 如果没有工具调用，说明当前步骤的“思考/操作”已结束，进入计划推进阶段
    return "replan"

# 6. 构建并编译图
def create_example_graph():
    workflow = StateGraph(PlanState)

    # 添加节点
    workflow.add_node("planner", planner_node)      # 规划阶段
    workflow.add_node("executor", executor_node)    # 执行阶段
    workflow.add_node("tools", ToolNode(ALL_TOOLS)) # 工具层
    workflow.add_node("replan", replanner_node)     # 更新计划阶段

    # 设置连线
    workflow.set_entry_point("planner")
    workflow.add_edge("planner", "executor")
    
    # 执行器决策：是调用工具，还是推进计划？
    workflow.add_conditional_edges("executor", should_continue, {
        "tools": "tools",
        "replan": "replan"
    })
    
    # 工具返回后回到执行器，继续完成当前步骤 (ReAct 循环)
    workflow.add_edge("tools", "executor")

    # 计划推进后，判断是否还有剩余任务
    workflow.add_conditional_edges("replan", 
        lambda state: END if not state['plan'] else "executor",
        {END: END, "executor": "executor"}
    )

    return workflow.compile()

# --- 测试运行 ---
if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()
    Config.validate()

    graph = create_example_graph()
    trace_handler = AgentTraceCallbackHandler()
    
    target = "192.168.43.1"
    inputs: PlanState = {
        "messages": [HumanMessage(content=f"对 {target} 进行安全评估，")],
        "plan": [],
        "past_steps": []
    }
    
    print("\n>>> 开始执行 Planner-Executor 工作流示例 <<<\n")
    final_state = inputs
    for event in graph.stream(inputs, config={"callbacks": [trace_handler]}):
        for node, value in event.items():
            print(f"--- 节点 [{node}] 执行完毕 ---")
            # 记录最新的状态
            final_state = value

    # 任务结束后，打印最终的 AI 消息（即渗透测试报告）
    if "messages" in final_state and final_state["messages"]:
        print(f"\n{'='*20} 最终渗透测试报告 {'='*20}\n")
        print(final_state["messages"][-1].content)
        print(f"\n{'='*57}\n")
