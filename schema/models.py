from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

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
