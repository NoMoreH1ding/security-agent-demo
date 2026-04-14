import operator
from typing import List, Optional, Dict, Any, Annotated, Sequence, Literal, TypedDict
from pydantic import BaseModel, Field
from langchain_core.messages import BaseMessage

class ServiceInfo(BaseModel):
    """服务详细信息"""
    port: int
    protocol: str = "tcp"
    service_name: Optional[str] = None
    version: Optional[str] = None
    product: Optional[str] = None
    extrainfo: Optional[str] = None
    status: str = "open"

class HostInfo(BaseModel):
    """主机发现信息"""
    ip: str
    status: str = "unknown"
    os: Optional[str] = None
    services: List[ServiceInfo] = Field(default_factory=list)

class Vulnerability(BaseModel):
    """发现的漏洞信息"""
    cve_id: Optional[str] = None
    title: str
    severity: str  # Critical, High, Medium, Low, Info
    description: str
    remediation: Optional[str] = None
    target: str
    associated_service: Optional[str] = None

class ScanRecord(BaseModel):
    """扫描工具执行记录"""
    tool_name: str
    parameters: Dict[str, Any]
    timestamp: str
    status: str  # success, failed
    raw_output_path: Optional[str] = None

# 定义 Agent 状态
class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], operator.add]
    # 结构化状态字段
    targets: List[str]
    discovered_hosts: Dict[str, HostInfo]
    vulnerabilities: List[Vulnerability]
    scan_history: List[ScanRecord]
    current_phase: Literal["recon", "scanning", "analyzing", "reporting"]
    # 身份认证信息存储库，格式: {"192.168.1.1:80": "PHPSESSID=xxx", ...}
    sessions: Dict[str, str]
    # HITL 相关
    review_approved: bool
    # Planner 任务分发: 各节点的专属任务指令
    planned_tasks: Dict[str, str]

