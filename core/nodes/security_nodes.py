import re
import logging
from langchain_core.messages import SystemMessage, ToolMessage, AIMessage, HumanMessage
from core.prompts import RECON_PROMPT, ANALYSIS_PROMPT, REPORT_PROMPT, VERIFICATION_PROMPT
from schema.models import AgentState, HostInfo, ServiceInfo
from utils.token_optimizer import summarize_messages, filter_legal_messages, retry_on_api_error
from core.parsers.recon_output_parser import validate_recon_output

logger = logging.getLogger(__name__)

def get_context_snapshot(state: AgentState) -> str:
    """生成结构化状态快照注入 Prompt"""
    if not state.get("discovered_hosts"):
        return "当前尚未发现存活资产。"
    
    snapshot = "【当前已发现资产概览】\n"
    for ip, host in state["discovered_hosts"].items():
        ports = [f"{s.port}/{s.protocol} ({s.service_name})" for s in host.services]
        snapshot += f"- 目标: {ip} | 开放端口: {', '.join(ports) if ports else '尚未探测详细端口'}\n"
    
    if state.get("vulnerabilities"):
        snapshot += f"【已发现漏洞】: {', '.join([v.cve_id for v in state['vulnerabilities']])}\n"
    
    sessions = state.get("sessions", {})
    if sessions:
        snapshot += f"【可用 Session 凭证】: {', '.join(sessions.keys())}\n"
        
    return snapshot

def create_recon_node(llm_with_tools):
    @retry_on_api_error(max_retries=3, initial_delay=1.0)
    def safe_invoke(messages):
        """带重试机制的 LLM 调用"""
        return llm_with_tools.invoke(messages)
    
    def recon_node(state: AgentState):
        messages = filter_legal_messages(summarize_messages(state['messages'], max_tokens=15000))
        snapshot = get_context_snapshot(state)
        constraint = (
            "\n\n[⚠️ 职责硬约束 - 网络层专属]:\n"
            "- 你只有 nmap 和 wafw00f 工具，没有任何 HTTP 客户端。\n"
            "- 禁止尝试访问 URL 路径（如 /login, /setup, /admin）。\n"
            "- 禁止尝试登录、获取 Cookie、或执行 setup/reset 等破坏性操作。\n"
            "- 严格按顺序执行: host_survival_check → quick_port_scan → waf_detection → 输出结果。\n"
            "- 输出仅包含: IP、端口、服务名、WAF 状态。"
        )

        # 过滤用户输入中的"生成报告"类指令，防止 RECON 被误导
        cleaned_messages = []
        for msg in messages:
            if hasattr(msg, "content") and isinstance(msg.content, str):
                if "生成" in msg.content and ("报告" in msg.content or "审计" in msg.content):
                    # 替换为简化版用户输入
                    cleaned_messages.append(HumanMessage(content="[系统指令: 执行基础设施侦察]"))
                    logger.info("[RECON] 已过滤用户输入中的报告生成指令")
                    continue
            cleaned_messages.append(msg)

        # 注入 Planner 分配的任务指令
        task_instruction = ""
        if state.get("planned_tasks") and "recon" in state["planned_tasks"]:
            task_instruction = f"\n\n[Planner 分配的任务]: {state['planned_tasks']['recon']}"
        
        full_messages = [SystemMessage(content=RECON_PROMPT + "\n\n" + snapshot + constraint + task_instruction)] + cleaned_messages
        
        try:
            response = safe_invoke(full_messages)
        except Exception as e:
            logger.error(f"[RECON] LLM 调用失败: {e}")
            # 降级：返回一个基本响应，允许流程继续
            target = state["targets"][0] if state.get("targets") else "未知"
            return {"messages": [AIMessage(content=f"RECON 阶段因 API 错误跳过。目标: {target}")], "current_phase": "recon"}

        # 输出解析：强制重试机制（不只是净化）
        if hasattr(response, "content") and response.content:
            max_retries = 2
            for attempt in range(max_retries):
                validation = validate_recon_output(response.content)
                if validation["valid"]:
                    break
                
                logger.warning(f"[RECON] 输出越界 (尝试 {attempt+1}/{max_retries}): {validation['violations']}")
                
                # 注入纠错指令，强制 LLM 重新生成
                correction = (
                    f"\n\n[❌ 错误!] 你的上一个回复违反了 RECON 职责边界。"
                    f"违规内容: {', '.join(validation['violations'])}。"
                    f"你必须重新输出仅包含以下内容的回复: 1. 目标 IP 2. 开放端口列表 3. WAF 状态。"
                    f"不要使用 Markdown 标题，不要分析漏洞，不要给出建议。"
                )
                retry_messages = full_messages + [response, HumanMessage(content=correction)]
                try:
                    response = safe_invoke(retry_messages)
                except Exception as e:
                    logger.error(f"[RECON] 重试调用失败: {e}")
                    # 重试也失败，使用降级输出
                    target = state["targets"][0] if state.get("targets") else "未知"
                    response.content = f"目标: {target}\nRECON 阶段因 API 错误终止。"
            
            # 如果重试后仍然越界，强制使用极简输出
            final_validation = validate_recon_output(response.content)
            if not final_validation["valid"]:
                logger.error(f"[RECON] 重试后仍越界，强制使用极简格式")
                # 从结构化状态中提取信息，生成合规输出
                target = state["targets"][0] if state.get("targets") else "未知"
                host = state["discovered_hosts"].get(target)
                if host:
                    ports_str = ", ".join([f"{s.port}/{s.protocol} ({s.service_name or 'unknown'})" for s in host.services])
                    response.content = f"目标: {target}\n开放端口: {ports_str}"
                else:
                    response.content = f"目标: {target}\n侦察阶段完成。"

        return {"messages": [response], "current_phase": "recon"}
    return recon_node

def create_verification_node(llm_with_tools):
    @retry_on_api_error(max_retries=3, initial_delay=1.0)
    def safe_invoke(messages):
        """带重试机制的 LLM 调用"""
        return llm_with_tools.invoke(messages)
    
    def verification_node(state: AgentState):
        messages = filter_legal_messages(summarize_messages(state['messages'], max_tokens=15000))
        snapshot = get_context_snapshot(state)
        # 注入身份引导
        auth_hint = ""
        if state.get("sessions"):
            auth_hint = "\n[可用凭证列表]:\n" + "\n".join([f"- {target}: {cookie}" for target, cookie in state["sessions"].items()])
            auth_hint += "\n请在操作对应目标时带上正确的 cookie 参数。"
            
        # 注入 Planner 分配的任务指令
        task_instruction = ""
        if state.get("planned_tasks") and "verification" in state["planned_tasks"]:
            task_instruction = f"\n\n[Planner 分配的任务]: {state['planned_tasks']['verification']}"
        
        full_messages = [SystemMessage(content=VERIFICATION_PROMPT + "\n\n" + snapshot + auth_hint + task_instruction)] + messages
        
        try:
            response = safe_invoke(full_messages)
        except Exception as e:
            logger.error(f"[VERIFICATION] LLM 调用失败: {e}")
            # 降级：返回一个基本响应，允许流程继续
            vuln_count = len(state.get("vulnerabilities", []))
            return {"messages": [AIMessage(content=f"VERIFICATION 阶段因 API 错误跳过。发现 {vuln_count} 个漏洞待验证。")], "current_phase": "verifying"}
        
        return {"messages": [response], "current_phase": "verifying"}
    return verification_node

def create_analysis_node(llm_with_tools):
    @retry_on_api_error(max_retries=3, initial_delay=1.0)
    def safe_invoke(messages):
        """带重试机制的 LLM 调用"""
        return llm_with_tools.invoke(messages)
    
    def analysis_node(state: AgentState):
        messages = filter_legal_messages(summarize_messages(state['messages'], max_tokens=15000))
        snapshot = get_context_snapshot(state)
        auth_hint = "\n[可用凭证已同步]: " + ", ".join(state.get("sessions", {}).keys()) if state.get("sessions") else ""
        
        # 注入 Planner 分配的任务指令
        task_instruction = ""
        if state.get("planned_tasks") and "analysis" in state["planned_tasks"]:
            task_instruction = f"\n\n[Planner 分配的任务]: {state['planned_tasks']['analysis']}"
        
        instruction = "\n\n[FORMAT CONSTRAINT]: 你处于‘分诊’阶段。禁止输出 Markdown 标题。只能列出：1. 疑似漏洞 2. 目标URL 3. 下步验证建议。"
        full_messages = [SystemMessage(content=ANALYSIS_PROMPT + snapshot + auth_hint + task_instruction + instruction)] + messages
        
        try:
            response = safe_invoke(full_messages)
        except Exception as e:
            logger.error(f"[ANALYSIS] LLM 调用失败: {e}")
            # 降级：返回一个基本响应，允许流程继续
            target = state["targets"][0] if state.get("targets") else "未知"
            vuln_count = len(state.get("vulnerabilities", []))
            return {"messages": [AIMessage(content=f"ANALYSIS 阶段因 API 错误跳过。目标: {target}, 已有 {vuln_count} 个漏洞待验证。")], "current_phase": "scanning"}
        
        return {"messages": [response], "current_phase": "scanning"}
    return analysis_node

def observer_node(state: AgentState):
    """专门负责信息提取与状态同步"""
    messages = list(state['messages'])
    last_msg = messages[-1]
    
    if isinstance(last_msg, ToolMessage):
        content = last_msg.content
        target_ip = state["targets"][0]
        if target_ip not in state["discovered_hosts"]:
            state["discovered_hosts"][target_ip] = HostInfo(ip=target_ip)
        host = state["discovered_hosts"][target_ip]
        
        # 提取端口 (支持多种 Nmap 格式)
        if "发现开放端口:" in content or "Port/Proto" in content:
            ports = re.findall(r"(\d+)/(\w+)\s+\((.*?)\)", content)
            if not ports: # 尝试解析 Markdown 表格格式
                ports = re.findall(r"\| (\d+)/(\w+) \| (.*?) \|", content)
            for p_num, p_proto, p_svc in ports:
                if not any(s.port == int(p_num) for s in host.services):
                    host.services.append(ServiceInfo(port=int(p_num), protocol=p_proto, service_name=p_svc.strip()))

        # 提取 Fuzz 路径 (来自 ffuf_parser)
        if "FFUF 扫描结果" in content or "发现隐藏路径" in content:
            # 匹配模式：- [状态码] URL: 链接
            fuzz_matches = re.findall(r"- \[(\d+)\] URL: (.*?)\n", content)
            for code, url in fuzz_matches:
                # 记录在 scan_history 中作为后续分析的素材
                if not any(r.parameters.get("url") == url for r in state["scan_history"] if r.tool_name == "ffuf"):
                    state["scan_history"].append(ScanRecord(
                        tool_name="ffuf", parameters={"url": url, "status_code": code},
                        timestamp="auto", status="success"
                    ))
                    print(f"\n[Observer]: 已同步 Fuzz 发现 -> {url} ({code})")

        # 提取漏洞
        if "| ID | 漏洞名称 |" in content:
            vuln_rows = re.findall(r"\| ([\w\-]+) \| (.*?) \| (.*?) \| `(.*?)` \|", content)
            for v_id, v_name, v_sev, v_match in vuln_rows:
                if not any(v.cve_id == v_id for v in state["vulnerabilities"]):
                    from schema.models import Vulnerability
                    state["vulnerabilities"].append(Vulnerability(
                        cve_id=v_id, title=v_name.strip(), severity=v_sev.strip(),
                        description=f"发现位置: {v_match}", target=target_ip
                    ))
                    print(f"\n[Observer]: 已同步漏洞 -> {v_id}")

        # 提取 Set-Cookie (隔离域存储)
        if "Set-Cookie:" in content:
            origin_url = "unknown"
            for m in reversed(messages[:-1]):
                if hasattr(m, "tool_calls") and m.tool_calls:
                    origin_url = m.tool_calls[0].get("args", {}).get("url", "unknown")
                    break
            cookie_match = re.search(r"Set-Cookie: (.*?)\n", content)
            if cookie_match and cookie_match.group(1) != "None":
                from urllib.parse import urlparse
                parsed = urlparse(origin_url)
                netloc = parsed.netloc or target_ip
                if "sessions" not in state: state["sessions"] = {}
                state["sessions"][netloc] = cookie_match.group(1)
                print(f"\n[Observer]: 已隔离同步凭证 -> {netloc}")

    # 阶段性截断 (仅保留最近 10 条以节省空间，filter_legal_messages 会负责补全 tool 对)
    if len(messages) > 15:
        print("\n[Observer]: 正在修剪上下文历史...")
        # 注意：这里我们只做截断，真正的合法性检查在业务节点调用 invoke 前完成
        messages = [messages[0]] + messages[-14:]
    
    return {
        "messages": messages, 
        "discovered_hosts": state["discovered_hosts"],
        "vulnerabilities": state["vulnerabilities"],
        "sessions": state.get("sessions", {})
    }

def human_review_node(state: AgentState):
    return {"review_approved": state.get("review_approved", False)}

def create_reporting_node(llm):
    @retry_on_api_error(max_retries=3, initial_delay=1.0)
    def safe_invoke(messages):
        """带重试机制的 LLM 调用"""
        return llm.invoke(messages)
    
    def reporting_node(state: AgentState):
        vulns_desc = "\n".join([f"- {v.cve_id}: {v.title} ({v.severity})" for v in state["vulnerabilities"]])
        hosts_desc = str(state["discovered_hosts"])
        auth_status = f"已获取 {len(state.get('sessions', {}))} 个域的 Session"
        
        # 注入 Planner 分配的报告任务指令
        report_task = ""
        if state.get("planned_tasks") and "reporting" in state["planned_tasks"]:
            report_task = f"\n\n报告要求：{state['planned_tasks']['reporting']}"
        
        report_input = f"资产数据：\n{hosts_desc}\n\n漏洞清单：\n{vulns_desc}\n\n认证状态：{auth_status}{report_task}\n\n请生成正式审计报告。"
        messages = [SystemMessage(content=REPORT_PROMPT), HumanMessage(content=report_input)]
        
        try:
            response = safe_invoke(messages)
        except Exception as e:
            logger.error(f"[REPORTING] LLM 调用失败: {e}")
            # 降级：返回一个基本报告，允许流程继续
            vuln_count = len(state.get("vulnerabilities", []))
            host_count = len(state.get("discovered_hosts", {}))
            session_count = len(state.get("sessions", {}))
            return {"messages": [AIMessage(content=f"报告生成阶段因 API 错误跳过。共发现 {host_count} 个主机，{vuln_count} 个漏洞，{session_count} 个 Session。")], "current_phase": "reporting"}
        
        return {"messages": [response], "current_phase": "reporting"}
    return reporting_node
