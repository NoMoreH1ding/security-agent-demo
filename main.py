import os
from dotenv import load_dotenv
from langchain_core.messages import HumanMessage
from langchain_core.runnables import RunnableConfig
from core.graph import create_security_graph, AgentState
from utils.config import Config
from core.callbacks import AgentTraceCallbackHandler

# 1. 初始化环境与配置
load_dotenv()
Config.validate()

# 2. 初始化追踪回调（可选）
# 它可以捕捉 Agent 的推理过程、工具调用及返回结果
trace_handler = AgentTraceCallbackHandler()

# 3. 这里的重构重点：使用 LangGraph 创建安全工作流
# create_security_graph 内部封装了 ChatDeepSeek 模型、SystemPrompt 以及 nmap 工具
# 这取代了原有的 create_agent 和 create_react_agent
agent_graph = create_security_graph()

def main():
    # 示例目标（你可以根据需要修改或通过命令行传入）
    target = "127.0.0.1"
    user_input = f"对 {target} 进行端口扫描、服务版本探测，并给出详细漏洞研判报告。"
    
    print(f"\n{'='*50}")
    print(f"--- 启动安全分析 Agent (LangGraph 版) ---")
    print(f"目标: {target}")
    print(f"{'='*50}\n")
    
    # 4. 执行器
    # 在 LangGraph 中，执行器即为编译后的图 (CompiledGraph)
    # 我们使用 stream 模式来观察执行过程，类似于 AgentExecutor 的 verbose=True
    inputs: AgentState = {"messages": [HumanMessage(content=user_input)]}
    
    # 传入回调配置，以便在控制台或日志中观察链路
    config: RunnableConfig = {"callbacks": [trace_handler]}
    
    # 开始执行工作流
    for event in agent_graph.stream(inputs, config=config):
        for node_name, value in event.items():
            if "messages" in value:
                last_message = value["messages"][-1]
                
                # 针对不同节点输出不同的格式，增强可读性
                if node_name == "agent":
                    # 模型思考内容
                    if last_message.content:
                        print(f"\n[Agent Thought]:\n{last_message.content}")
                    # 工具调用信息
                    if hasattr(last_message, "tool_calls") and last_message.tool_calls:
                        for tool_call in last_message.tool_calls:
                            print(f"\n[Action]: {tool_call['name']}")
                            print(f"[Action Input]: {tool_call['args']}")
                            
                elif node_name == "tools":
                    # 工具执行后的观察结果
                    print(f"\n[Observation Result]:\n{last_message.content}")

    print(f"\n{'='*50}")
    print(f"--- 任务执行完毕 ---")
    print(f"{'='*50}\n")

if __name__ == "__main__":
    main()
