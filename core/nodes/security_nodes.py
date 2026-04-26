import re
import logging
from langchain_core.messages import SystemMessage, ToolMessage, AIMessage, HumanMessage
from core.prompts import RECON_PROMPT, ANALYSIS_PROMPT, REPORT_PROMPT, VERIFICATION_PROMPT
from schema.models import AgentState, HostInfo, ServiceInfo
from utils.token_optimizer import summarize_messages, filter_legal_messages, retry_on_api_error
from core.parsers.recon_output_parser import validate_recon_output

logger = logging.getLogger(__name__)

def normalize_target(target: str) -> str:
    """统一目标格式，保留 URL 路径以便区分不同端点的请求记录"""
    if not target or target == "unknown": return "unknown"
    # 去掉协议头 (http://, https://)
    if "://" in target:
        target = target.split("://", 1)[1]
    # 不再盲目通过 '/' 分割（那会丢失路径信息），仅去掉末尾的斜杠以保持一致性
    if target.endswith("/"):
        target = target[:-1]
    return target

def get_context_snapshot(state: AgentState) -> str:
    """生成结构化状态快照，包含攻击成本警告和漏洞饱和度提醒"""
    if not state.get("discovered_hosts"):
        return "当前尚未发现存活资产。"

    snapshot = "【当前已发现资产概览】\n"
    for ip, host in state["discovered_hosts"].items():
        waf_info = host.os if host.os else "未知"
        ports = [f"{s.port}/{s.protocol} ({s.service_name})" for s in host.services]
        snapshot += f"- 目标: {ip} | WAF: {waf_info} | 开放端口: {', '.join(ports) if ports else '尚未探测详细端口'}\n"

    # 提取当前目标的漏洞情况，用于饱和度告警
    target_vulns = {}
    if state.get("vulnerabilities"):
        for v in state["vulnerabilities"]:
            t = v.target or "global"
            if t not in target_vulns: target_vulns[t] = []
            target_vulns[t].append(f"{v.cve_id}({v.severity})")

    if state.get("scan_history"):
        snapshot += "\n【已扫描工具历史记录 & 饱和度监控】\n"
        tool_counts = {}
        path_records = {} # 记录每个目标已尝试的具体路径
        for record in state["scan_history"]:
            param_target = record.parameters.get("target") or record.parameters.get("url") or "Global"
            target = normalize_target(param_target)
            if target not in tool_counts: tool_counts[target] = {}
            tool_counts[target][record.tool_name] = tool_counts[target].get(record.tool_name, 0) + 1

            # 如果是 web_request，提取具体的路径
            if record.tool_name == "web_request":
                if target not in path_records: path_records[target] = set()
                path_records[target].add(param_target)

        for target, tools in tool_counts.items():
            tool_list = [f"{name}({count}次)" for name, count in tools.items()]
            snapshot += f"- {target}: 已执行 [{', '.join(tool_list)}]\n"

            # 显示已尝试的具体路径（限制显示最近10个，防止 snapshot 过大）
            if target in path_records:
                paths = list(path_records[target])[-10:]
                snapshot += f"  └ 已试路径: {', '.join(paths)}\n"

            # 如果某个目标已经有高危漏洞且探测次数过多，添加硬限制警告
            target_ip = target.split(":")[0]
            if target_ip in target_vulns or target in target_vulns:
                vulns = target_vulns.get(target_ip) or target_vulns.get(target)
                if any("CRITICAL" in v or "HIGH" in v for v in vulns):
                    snapshot += f"  ⚠️ [饱和度警告]: 该目标已发现高危漏洞 {vulns}。严禁继续执行探测。必须立即输出 [VERIFY] 并结束任务！\n"

    return snapshot + "\n"
def create_recon_node(llm_with_tools):
    @retry_on_api_error(max_retries=3, initial_delay=1.0)
    def safe_invoke(messages): return llm_with_tools.invoke(messages)
    
    def recon_node(state: AgentState):
        messages = filter_legal_messages(summarize_messages(state['messages']))
        snapshot = get_context_snapshot(state)
        # 强制侦察职责
        constraint = "\n\n[⚠️ 职责硬约束]: 仅执行基础设施探测 (Survival, Port, WAF)。严禁访问应用层路径。"
        full_messages = [SystemMessage(content=RECON_PROMPT + "\n\n" + snapshot + constraint)] + messages
        try:
            response = safe_invoke(full_messages)
            return {"messages": [response], "current_phase": "recon"}
        except Exception as e:
            return {"messages": [AIMessage(content="RECON 错误")], "current_phase": "recon"}
    return recon_node

def create_analysis_node(llm_with_tools):
    @retry_on_api_error(max_retries=3, initial_delay=1.0)
    def safe_invoke(messages): return llm_with_tools.invoke(messages)
    
    def analysis_node(state: AgentState):
        messages = filter_legal_messages(summarize_messages(state['messages']))
        snapshot = get_context_snapshot(state)
        # 增加对 web_request 的使用约束
        cost_warning = "\n\n[⚠️ 重要准则]: 你的工具调用额度有限。严禁重复请求已在历史记录中出现的 URL。严禁无意义地多次刷新同一页面。优先使用 nuclei_scan 等自动化工具进行批量分析。\n\n[🚫 严格登录限制]: 针对任何登录页面，禁止进行任何登录尝试（包括弱口令测试）。严禁使用 web_request 工具向登录页面发送 POST 请求进行登录尝试。web_login_analyzer 工具已明确告知禁止登录尝试，请严格遵守。仅记录登录入口点信息，优先测试其他无需认证的漏洞模块（如目录遍历、信息泄露、参数注入等）。"
        instruction = "\n\n[FORMAT]: 你处于‘分诊’阶段。列出：1. 疑似漏洞 2. 目标URL 3. 下步验证建议。"
        full_messages = [SystemMessage(content=ANALYSIS_PROMPT + snapshot + cost_warning + instruction)] + messages
        try:
            response = safe_invoke(full_messages)
            return {"messages": [response], "current_phase": "analysis"}
        except Exception as e:
            return {"messages": [AIMessage(content="ANALYSIS 错误")], "current_phase": "analysis"}
    return analysis_node

def create_verification_node(llm_with_tools):
    @retry_on_api_error(max_retries=3, initial_delay=1.0)
    def safe_invoke(messages): return llm_with_tools.invoke(messages)
    
    def verification_node(state: AgentState):
        messages = filter_legal_messages(summarize_messages(state['messages']))
        snapshot = get_context_snapshot(state)
        full_messages = [SystemMessage(content=VERIFICATION_PROMPT + "\n\n" + snapshot)] + messages
        try:
            response = safe_invoke(full_messages)
            return {"messages": [response], "current_phase": "verification"}
        except Exception as e:
            return {"messages": [AIMessage(content="VERIFICATION 错误")], "current_phase": "verification"}
    return verification_node

def observer_node(state: AgentState):
    """提取状态并去重历史记录"""
    messages = list(state['messages'])
    last_msg = messages[-1]
    
    if isinstance(last_msg, ToolMessage):
        from schema.models import ScanRecord
        # 提取工具调用信息
        target_info = "unknown"
        tool_name = "unknown"
        tool_args = {}
        for m in reversed(messages[:-1]):
            if isinstance(m, AIMessage) and m.tool_calls:
                for tc in m.tool_calls:
                    if tc.get("id") == last_msg.tool_call_id:
                        tool_name = tc.get("name")
                        tool_args = tc.get("args", {})
                        target_info = tool_args.get("target") or tool_args.get("ip") or tool_args.get("url") or "unknown"
                        break
                if tool_name != "unknown": break
        
        # 记录历史
        norm_target = normalize_target(target_info)
        if not any(r.timestamp == last_msg.tool_call_id for r in state.get("scan_history", [])):
            state["scan_history"].append(ScanRecord(
                tool_name=tool_name, parameters=tool_args,
                timestamp=last_msg.tool_call_id, status="success"
            ))

        # 提取主机资产
        target_ip = norm_target.split(":")[0]
        if target_ip != "unknown":
            if target_ip not in state["discovered_hosts"]:
                state["discovered_hosts"][target_ip] = HostInfo(ip=target_ip)
            host = state["discovered_hosts"][target_ip]
            # 记录 WAF 结果
            if "WAF" in last_msg.content:
                if "No WAF detected" in last_msg.content: host.os = "None"
                elif "is behind" in last_msg.content: 
                    host.os = last_msg.content.split("is behind")[1].split(".")[0].strip()

            # 记录端口
            ports = re.findall(r"(\d+)/(\w+)\s+\((.*?)\)", last_msg.content)
            for p_num, p_proto, p_svc in ports:
                if not any(s.port == int(p_num) for s in host.services):
                    host.services.append(ServiceInfo(port=int(p_num), protocol=p_proto, service_name=p_svc.strip()))

            # 记录漏洞 (包含端口信息)
            if "| ID |" in last_msg.content:
                vuln_rows = re.findall(r"\| ([\w\-]+) \| (.*?) \| (.*?) \|", last_msg.content)
                for v_id, v_name, v_sev in vuln_rows:
                    vuln_target = target_info if target_info != "unknown" else target_ip
                    if not any(v.cve_id == v_id and v.target == vuln_target for v in state["vulnerabilities"]):
                        from schema.models import Vulnerability
                        state["vulnerabilities"].append(Vulnerability(
                            cve_id=v_id, title=v_name.strip(), severity=v_sev.strip(),
                            description="检测发现", target=vuln_target
                        ))

    return {
        "discovered_hosts": state["discovered_hosts"],
        "vulnerabilities": state["vulnerabilities"],
        "scan_history": state["scan_history"],
        "sessions": state.get("sessions", {})
    }

def human_review_node(state: AgentState): return {"review_approved": state.get("review_approved", False)}

def create_reporting_node(llm):
    def reporting_node(state: AgentState):
        messages = [SystemMessage(content=REPORT_PROMPT), HumanMessage(content=f"漏洞数据: {state['vulnerabilities']}")]
        response = llm.invoke(messages)
        return {"messages": [response], "current_phase": "reporting"}
    return reporting_node
