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

def update_state_from_output(state: AgentState, node_name: str, value: dict):
    """
    从工具输出中解析信息并更新结构化状态。
    这是一个简易实现，实际可由专门的 Parser 节点完成。
    """
    if node_name != "tools":
        return
    
    last_msg = value["messages"][-1]
    if not isinstance(last_msg, ToolMessage):
        return

    content = last_msg.content
    
    # 简单的正则提取 (针对 nmap_parser 的输出)
    # 提取 IP (从目标字段或上下文)
    # 这里我们简化处理，实际中应从 tool_call 的参数中获取 target
    
    # 解析开放端口 (quick_port_scan 输出: 发现开放端口: 80/tcp (http), ...)
    if "发现开放端口:" in content:
        ports = re.findall(r"(\d+)/(\w+)\s+\((.*?)\)", content)
        # 假设我们只有一个目标
        target = state["targets"][0]
        if target not in state["discovered_hosts"]:
            state["discovered_hosts"][target] = HostInfo(ip=target)
        
        host = state["discovered_hosts"][target]
        for p_num, p_proto, p_svc in ports:
            if not any(s.port == int(p_num) for s in host.services):
                host.services.append(ServiceInfo(port=int(p_num), protocol=p_proto, service_name=p_svc))

    # 解析详细服务信息 (service_detail_scan 输出表格)
    if "| Port/Proto | Service | Version/Info |" in content:
        target = state["targets"][0]
        host = state["discovered_hosts"].get(target)
        if host:
            # 提取表格行
            rows = re.findall(r"\| (\d+)/(\w+) \| (.*?) \| (.*?) \|", content)
            for p_num, p_proto, p_svc, p_ver in rows:
                for s in host.services:
                    if s.port == int(p_num):
                        s.service_name = p_svc.strip()
                        s.version = p_ver.strip()

def main():
    target = "192.168.43.150"
    user_input = f"对 {target} 的 8080 端口进行漏洞深度研判，特别关注 Web 安全风险并给出详细修复方案。"
    
    print(f"\n{'='*50}")
    print(f"--- 启动安全分析 Agent (LangGraph 优化版) ---")
    print(f"目标: {target}")
    print(f"{'='*50}\n")
    
    inputs: AgentState = {
        "messages": [HumanMessage(content=user_input)],
        "targets": [target],
        "discovered_hosts": {},
        "vulnerabilities": [],
        "scan_history": [],
        "current_phase": "recon",
        "review_approved": False
    }
    
    config = {
        "callbacks": [trace_handler],
        "configurable": {"thread_id": "verification_node_test_001"}
    }
    
    # 开始执行工作流
    for event in agent_graph.stream(inputs, config=config):
        for node_name, value in event.items():
            # 更新结构化状态
            update_state_from_output(inputs, node_name, value)
            
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
