import asyncio
import queue
import threading
import time
import uuid
from typing import Any

from langchain_core.messages import HumanMessage
from langchain_core.callbacks import BaseCallbackHandler

from core.graph import create_security_graph
from utils.config import Config
from schema.models import AgentState


class EventQueueCallback(BaseCallbackHandler):
    """LangChain callback that pushes events to a shared queue for WebSocket streaming."""

    def __init__(self, event_queue: queue.Queue):
        self.queue = event_queue

    def _put(self, event_type: str, data: dict):
        self.queue.put({"type": event_type, **data, "timestamp": time.time()})

    def on_llm_start(self, serialized, prompts, *, run_id, **kwargs):
        self._put("llm_start", {"node": self._detect_node(prompts[0])})

    def on_llm_end(self, response, *, run_id, **kwargs):
        text = response.generations[0][0].text
        self._put("llm_end", {"content": text[:500]})

    def on_tool_start(self, serialized, input_str, *, run_id, **kwargs):
        name = serialized.get("name", "Unknown")
        self._put("tool_call", {"name": name, "args": input_str[:200]})

    def on_tool_end(self, output, *, run_id, **kwargs):
        self._put("tool_result", {"content": str(output)[:300]})

    def on_tool_error(self, error, *, run_id, **kwargs):
        self._put("error", {"message": str(error)})

    @staticmethod
    def _detect_node(prompt: str) -> str:
        if "侦察专家" in prompt:
            return "recon"
        if "安全分析师" in prompt:
            return "analysis"
        if "漏洞验证" in prompt or "验证专家" in prompt:
            return "verification"
        if "安全审计员" in prompt:
            return "reporting"
        return "unknown"


def run_agent(target: str, task_description: str, event_queue: queue.Queue,
              session_id: str | None = None) -> AgentState:
    """Run agent in a background thread, pushing events to the queue."""

    event_queue.put({"type": "status", "phase": "starting", "message": "正在初始化..."})

    # Build graph with the streaming callback
    callback = EventQueueCallback(event_queue)
    graph = create_security_graph(use_checkpoint=False, enable_hitl=False)

    sid = session_id or str(uuid.uuid4())[:8]
    master_state: AgentState = {
        "discovered_hosts": {},
        "vulnerabilities": [],
        "scan_history": [],
        "sessions": {},
        "messages": [],
        "targets": [target],
        "current_phase": "recon",
        "review_approved": False,
        "planned_tasks": {},
    }

    thread_id = f"recon_{sid}"

    # Phase 1: Recon
    event_queue.put({"type": "phase_change", "phase": "recon", "message": "侦察阶段：端口扫描与 WAF 探测"})
    last_state = _stream_phase(graph, "recon", target, task_description,
                               master_state, thread_id, callback, event_queue)

    # Merge recon results
    master_state["discovered_hosts"] = last_state.get("discovered_hosts", {})
    master_state["scan_history"] = last_state.get("scan_history", [])
    master_state["sessions"] = last_state.get("sessions", {})
    master_state["messages"] = last_state.get("messages", [])

    # Phase 2: Analysis (per web service)
    web_services = []
    for ip, host in master_state["discovered_hosts"].items():
        for svc in host.services:
            if svc.port in [80, 443, 8080, 8081, 8443, 8888] or "http" in (svc.service_name or "").lower():
                web_services.append(f"{ip}:{svc.port}")

    event_queue.put({"type": "phase_change", "phase": "analysis",
                     "message": f"分析阶段：发现 {len(web_services)} 个 Web 目标，启动隔离审计",
                     "web_services": web_services})

    for service in web_services:
        svc_thread = f"audit_{service.replace('.', '_').replace(':', '_')}_{sid}"
        analysis_instruction = f"""
作为该目标的专项审计员。
目标服务: {service}
任务：在非授权状态下探测该服务的安全漏洞（重点关注 RCE、信息泄露、未授权访问）。
要求：
1. 仅针对 {service} 进行操作。
2. 禁止重复探测已在历史记录中完成的任务。
3. 发现漏洞后立即获取 PoC 证据。"""
        svc_state = _stream_phase(graph, "analysis", service, analysis_instruction,
                                  master_state, svc_thread, callback, event_queue)
        master_state["vulnerabilities"].extend(
            [v for v in svc_state.get("vulnerabilities", []) if v not in master_state["vulnerabilities"]]
        )
        master_state["sessions"].update(svc_state.get("sessions", {}))
        master_state["scan_history"].extend(svc_state.get("scan_history", []))

    # Phase 3: Reporting
    event_queue.put({"type": "phase_change", "phase": "reporting",
                     "message": "报告阶段：汇总所有发现，生成审计报告"})
    _stream_phase(graph, "reporting", target,
                  "汇总所有专项小组的发现，生成一份包含所有受影响端口、漏洞细节和 PoC 证据的正式审计报告。",
                  master_state, f"report_{sid}", callback, event_queue)

    event_queue.put({"type": "done", "message": "审计任务完成"})
    return master_state


def _stream_phase(graph, phase: str, target: str, instruction: str,
                   master_state: AgentState, thread_id: str,
                   callback: EventQueueCallback, event_queue: queue.Queue) -> dict:
    """Run one phase via graph.stream and push node/tool events to the queue."""

    task_input: AgentState = {
        "messages": [HumanMessage(content=instruction)],
        "targets": [target],
        "discovered_hosts": master_state.get("discovered_hosts", {}),
        "vulnerabilities": master_state.get("vulnerabilities", []),
        "scan_history": master_state.get("scan_history", []),
        "current_phase": phase,
        "sessions": master_state.get("sessions", {}),
        "review_approved": False,
        "planned_tasks": {},
    }

    config = {"callbacks": [callback], "configurable": {"thread_id": thread_id}}
    last_state = task_input

    for event in graph.stream(task_input, config=config):
        for node_name, value in event.items():
            if node_name in ["recon", "analysis", "verification", "reporting"]:
                msg = value.get("messages", [None])[-1] if "messages" in value else None
                content = msg.content if msg and msg.content else ""
                event_queue.put({
                    "type": "node_output",
                    "node": node_name,
                    "content": content[:500],
                })
                # Track state updates
                if "discovered_hosts" in value:
                    event_queue.put({
                        "type": "state_update",
                        "discovered_hosts": _summarize_hosts(value["discovered_hosts"]),
                    })
                if "vulnerabilities" in value:
                    event_queue.put({
                        "type": "state_update",
                        "vulnerabilities": [str(v) for v in value["vulnerabilities"]],
                    })
            elif node_name == "tools":
                msg = value.get("messages", [None])[-1] if "messages" in value else None
                content = msg.content if msg and msg.content else ""
                event_queue.put({
                    "type": "tool_observation",
                    "node": "tools",
                    "content": str(content)[:300],
                })

            if node_name == "observer":
                last_state.update(value)

    return last_state


def _summarize_hosts(hosts: dict) -> list:
    result = []
    for ip, host in hosts.items():
        ports = [f"{s.port}/{s.service_name or s.protocol or '?'}" for s in host.services]
        result.append({"ip": ip, "status": host.status, "os": host.os, "ports": ports})
    return result
