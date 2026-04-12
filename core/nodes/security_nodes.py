import re
from langchain_core.messages import SystemMessage, ToolMessage, AIMessage, HumanMessage
from core.prompts import RECON_PROMPT, ANALYSIS_PROMPT, REPORT_PROMPT
from schema.models import AgentState, HostInfo, ServiceInfo
from utils.token_optimizer import summarize_messages

def get_context_snapshot(state: AgentState) -> str:
    """根据当前结构化状态生成简短的上下文概览。"""
    if not state.get("discovered_hosts"):
        return "当前尚未发现存活资产。"
    
    snapshot = "【当前已发现资产概览】\n"
    for ip, host in state["discovered_hosts"].items():
        ports = [f"{s.port}/{s.protocol} ({s.service_name})" for s in host.services]
        snapshot += f"- 目标: {ip} | 开放端口: {', '.join(ports) if ports else '尚未探测详细端口'}\n"
    
    if state.get("vulnerabilities"):
        snapshot += f"【已发现漏洞】: {', '.join([v.cve_id for v in state['vulnerabilities']])}\n"
    return snapshot

def create_recon_node(llm_with_tools):
    def recon_node(state: AgentState):
        messages = summarize_messages(state['messages'])
        snapshot = get_context_snapshot(state)
        full_messages = [SystemMessage(content=RECON_PROMPT + "\n\n" + snapshot)] + messages
        response = llm_with_tools.invoke(full_messages)
        return {"messages": [response], "current_phase": "recon"}
    return recon_node

from core.prompts import RECON_PROMPT, ANALYSIS_PROMPT, REPORT_PROMPT, VERIFICATION_PROMPT

def create_verification_node(llm_with_tools):
    def verification_node(state: AgentState):
        messages = summarize_messages(state['messages'])
        snapshot = get_context_snapshot(state)
        full_messages = [SystemMessage(content=VERIFICATION_PROMPT + "\n\n" + snapshot)] + messages
        response = llm_with_tools.invoke(full_messages)
        return {"messages": [response], "current_phase": "scanning"} # 验证阶段依然属于扫描大类
    return verification_node

def create_analysis_node(llm_with_tools):
    def analysis_node(state: AgentState):
        messages = summarize_messages(state['messages'])
        snapshot = get_context_snapshot(state)
        # 增加极其强硬的格式约束，防止其生成报告
        instruction = "\n\n[FORMAT CONSTRAINT]: 你处于‘分诊’阶段。禁止输出任何 Markdown 报告标题（如 # 报告）。只能列出：1. 疑似漏洞 2. 目标URL 3. 下步验证建议。违者将导致下游流程出错。"
        full_messages = [SystemMessage(content=ANALYSIS_PROMPT + snapshot + instruction)] + messages
        response = llm_with_tools.invoke(full_messages)
        return {"messages": [response], "current_phase": "scanning"}
    return analysis_node

def observer_node(state: AgentState):
    """
    专门负责信息提取与上下文清理的节点。
    """
    messages = list(state['messages'])
    last_msg = messages[-1]
    
    # 1. 结构化信息提取
    if isinstance(last_msg, ToolMessage):
        content = last_msg.content
        target_ip = state["targets"][0]
        if target_ip not in state["discovered_hosts"]:
            state["discovered_hosts"][target_ip] = HostInfo(ip=target_ip)
        host = state["discovered_hosts"][target_ip]
        
        if "发现开放端口:" in content:
            ports = re.findall(r"(\d+)/(\w+)\s+\((.*?)\)", content)
            for p_num, p_proto, p_svc in ports:
                if not any(s.port == int(p_num) for s in host.services):
                    host.services.append(ServiceInfo(port=int(p_num), protocol=p_proto, service_name=p_svc))

        if "| ID | 漏洞名称 |" in content:
            vuln_rows = re.findall(r"\| ([\w\-]+) \| (.*?) \| (.*?) \| `(.*?)` \|", content)
            for v_id, v_name, v_sev, v_match in vuln_rows:
                if not any(v.cve_id == v_id for v in state["vulnerabilities"]):
                    from schema.models import Vulnerability
                    state["vulnerabilities"].append(Vulnerability(
                        cve_id=v_id, title=v_name.strip(), severity=v_sev.strip(),
                        description=f"发现位置: {v_match}", target=target_ip
                    ))
                    print(f"\n[Observer]: 已提取结构化漏洞数据 -> {v_id}")

    # 2. 阶段性上下文压缩逻辑
    if len(messages) > 10:
        print("\n[Observer]: 上下文过长，正在执行阶段性压缩...")
        summary_content = "【阶段性进度综述】\n" + get_context_snapshot(state)
        # 强制清空除第一条需求和最新状态外的所有历史
        optimized_messages = [messages[0], AIMessage(content=summary_content)]
    else:
        optimized_messages = summarize_messages(messages)
    
    return {
        "messages": optimized_messages, 
        "discovered_hosts": state["discovered_hosts"],
        "vulnerabilities": state["vulnerabilities"]
    }

def human_review_node(state: AgentState):
    return {"review_approved": state.get("review_approved", False)}

def create_reporting_node(llm):
    def reporting_node(state: AgentState):
        # 报告节点完全依赖结构化状态
        # 将结构化对象转为简单的字符串描述
        vulns_desc = "\n".join([f"- {v.cve_id}: {v.title} ({v.severity})" for v in state["vulnerabilities"]])
        hosts_desc = str(state["discovered_hosts"])
        
        report_input = f"资产数据：\n{hosts_desc}\n\n发现漏洞清单：\n{vulns_desc}\n\n请根据以上数据生成最终审计报告。"
        
        messages = [SystemMessage(content=REPORT_PROMPT), HumanMessage(content=report_input)]
        response = llm.invoke(messages)
        return {"messages": [response], "current_phase": "reporting"}
    return reporting_node
