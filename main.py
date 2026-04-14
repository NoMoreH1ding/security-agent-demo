import os
import re
from dotenv import load_dotenv
from langchain_core.messages import HumanMessage, ToolMessage
from core.graph import create_security_graph, AgentState
from utils.config import Config
from core.callbacks import AgentTraceCallbackHandler
from schema import HostInfo, ServiceInfo

# 1. 初始化环境与配置
load_dotenv()
Config.validate()

trace_handler = AgentTraceCallbackHandler()
agent_graph = create_security_graph(use_checkpoint=True, enable_hitl=False)

def main():
    target = "192.168.43.150"
    user_input = f"""
    对目标 {target} 进行全方位的安全审计：
    1. 侦察所有开放端口及 Web 服务状态。
    2. 针对 80 端口的 DVWA 服务，尝试使用用户名 admin 和密码 password 登录 /login.php。一旦获取 Cookie，请执行授权后的漏洞深度扫描。
    3. 针对 8080 和 8081 端口的服务进行深度漏洞研判（如 Spring Gateway、SQL 注入等）。
    4. 汇总所有发现，生成一份包含身份突破证据和漏洞 PoC 的最终审计报告。
    """

    print(f"\n{'='*50}")
    print(f"--- 启动安全分析 Agent (全量实战验证版) ---")
    print(f"目标: {target}")
    print(f"{'='*50}\n")

    inputs: AgentState = {
        "messages": [HumanMessage(content=user_input)],
        "targets": [target],
        "discovered_hosts": {},
        "vulnerabilities": [],
        "scan_history": [],
        "current_phase": "recon",
        "sessions": {},
        "review_approved": False
    }

    config = {
        "callbacks": [trace_handler],
        "configurable": {"thread_id": "auth_isolation_test_001"}
    }
    
    # 开始执行工作流
    for event in agent_graph.stream(inputs, config=config):
        for node_name, value in event.items():
            # 注意：结构化状态更新 (discovered_hosts, vulnerabilities, sessions) 
            # 现在完全由图内部的 'observer' 节点自动处理，此处无需手动解析输出。
            
            if "messages" in value:
                last_message = value["messages"][-1]
                if node_name in ["recon", "analysis", "reporting"]:
                    if last_message.content:
                        print(f"\n[{node_name.upper()}]:\n{last_message.content}")
                    if hasattr(last_message, "tool_calls") and last_message.tool_calls:
                        for tool_call in last_message.tool_calls:
                            print(f"\n[Action]: {tool_call['name']}({tool_call['args']})")
                elif node_name == "tools":
                    print(f"\n[Observation]:\n{last_message.content[:200]}... (已截断显示)")

    print(f"\n{'='*50}\n--- 任务执行完毕 ---\n{'='*50}\n")

if __name__ == "__main__":
    main()
