import os
import uuid
from dotenv import load_dotenv
from langchain_core.messages import HumanMessage
from core.graph import create_security_graph
from utils.config import Config
from core.callbacks import AgentTraceCallbackHandler
from schema.models import AgentState, HostInfo

# 初始化环境
load_dotenv()
Config.validate()

trace_handler = AgentTraceCallbackHandler()
agent_graph = create_security_graph(use_checkpoint=True, enable_hitl=False)

def run_isolated_task(phase: str, target: str, task_description: str, master_state: AgentState, thread_id: str):
    """在一个独立的会话中运行特定目标的特定阶段任务"""
    print(f"\n{'*'*30}")
    print(f"启动专项任务 -> 目标: {target} | 阶段: {phase.upper()}")
    print(f"{'*'*30}\n")

    # 关键修复：子任务的初始输入必须根据 phase 决定
    task_input: AgentState = {
        "messages": [HumanMessage(content=task_description)],
        "targets": [target],
        "discovered_hosts": master_state["discovered_hosts"],
        "vulnerabilities": master_state["vulnerabilities"],
        "scan_history": master_state["scan_history"],
        "current_phase": phase,
        "sessions": master_state["sessions"],
        "review_approved": False,
        "planned_tasks": {}
    }

    config = {
        "callbacks": [trace_handler],
        "configurable": {"thread_id": thread_id}
    }

    last_state = task_input
    for event in agent_graph.stream(task_input, config=config):
        for node_name, value in event.items():
            if "messages" in value:
                last_message = value["messages"][-1]
                # 打印日志（只打印业务节点的输出，忽略工具执行细节的 verbose 打印）
                if node_name in ["recon", "analysis", "verification", "reporting"]:
                    if last_message.content:
                        print(f"\n[{node_name.upper()}]:\n{last_message.content}")
                    if hasattr(last_message, "tool_calls") and last_message.tool_calls:
                        for tool_call in last_message.tool_calls:
                            print(f"\n[{node_name.upper()} Action]: {tool_call['name']}({tool_call['args']})")
                elif node_name == "tools":
                    print(f"\n[Observation]:\n{last_message.content[:200]}... (已截断)")
            
            # 更新本地最后状态
            if node_name == "observer":
                last_state.update(value)
    
    return last_state

def main():
    target_host = "192.168.43.150"
    session_id = str(uuid.uuid4())[:8]
    
    # 全局主状态，用于汇聚所有结果
    master_state: AgentState = {
        "discovered_hosts": {},
        "vulnerabilities": [],
        "scan_history": [],
        "sessions": {},
        "messages": [],
        "targets": [target_host],
        "current_phase": "recon",
        "review_approved": False,
        "planned_tasks": {}
    }

    # === 第一阶段：全量基础设施侦察 (Global Recon) ===
    recon_instruction = f"对目标 {target_host} 进行全量端口扫描和 WAF 探测，识别所有 Web 服务。"
    master_state = run_isolated_task(
        phase="recon", 
        target=target_host, 
        task_description=recon_instruction,
        master_state=master_state,
        thread_id=f"recon_{session_id}"
    )

    # === 第二阶段：任务拆分与专项分析 (Isolated Analysis) ===
    web_services = []
    for ip, host in master_state["discovered_hosts"].items():
        for svc in host.services:
            # 识别可能是 Web 的端口
            if svc.port in [80, 443, 8080, 8081, 8443, 8888] or "http" in (svc.service_name or "").lower():
                web_services.append(f"{ip}:{svc.port}")

    print(f"\n[Manager]: 侦察完成，发现 {len(web_services)} 个 Web 目标，准备启动隔离审计...")

    for service in web_services:
        analysis_instruction = f"""
        你是该目标的专项审计员。
        目标服务: {service}
        任务：在非授权状态下探测该服务的安全漏洞（重点关注 RCE、信息泄露、未授权访问）。
        要求：
        1. 仅针对 {service} 进行操作。
        2. 禁止重复探测已在历史记录中完成的任务。
        3. 发现漏洞后立即获取 PoC 证据。
        """
        # 针对每个服务开启独立 thread，上下文完全隔离
        service_state = run_isolated_task(
            phase="analysis",
            target=service,
            task_description=analysis_instruction,
            master_state=master_state,
            thread_id=f"audit_{service.replace('.', '_').replace(':', '_')}_{session_id}"
        )
        
        # 将该服务的发现汇总到 master_state
        master_state["vulnerabilities"].extend([v for v in service_state["vulnerabilities"] if v not in master_state["vulnerabilities"]])
        master_state["sessions"].update(service_state["sessions"])
        master_state["scan_history"].extend(service_state["scan_history"])

    # === 第三阶段：全量审计报告 (Global Reporting) ===
    print(f"\n[Manager]: 所有专项审计完成，正在汇总生成最终报告...")
    report_instruction = "汇总所有专项小组的发现，生成一份包含所有受影响端口、漏洞细节和 PoC 证据的正式审计报告。"
    run_isolated_task(
        phase="reporting",
        target=target_host,
        task_description=report_instruction,
        master_state=master_state,
        thread_id=f"report_{session_id}"
    )

    print(f"\n{'='*50}\n--- 整个分布式审计任务执行完毕 ---\n{'='*50}\n")

if __name__ == "__main__":
    main()
