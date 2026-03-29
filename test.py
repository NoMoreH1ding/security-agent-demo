from langchain_core.messages import HumanMessage
from langchain_core.runnables import RunnableConfig
from dotenv import load_dotenv
from core.graph import create_security_graph, AgentState
from utils.config import Config
from core.callbacks import AgentTraceCallbackHandler

load_dotenv()
Config.validate()
trace_handler = AgentTraceCallbackHandler()

# 使用 LangGraph 创建 Agent
agent_graph = create_security_graph()

# 运行代理
target = "127.0.0.1"
user_input = f"确定一下目标 {target} 的指纹信息"

inputs: AgentState = {"messages": [HumanMessage(content=user_input)]}
config: RunnableConfig = {"callbacks": [trace_handler]}

print("--- 启动分析 ---")
# 简单调用 invoke
response = agent_graph.invoke(inputs, config=config)

print("\n--- 完整返回 ---")
print(response)

# 只获取最后的结果
print("\n--- 最终答案 ---")
print(response["messages"][-1].content)
