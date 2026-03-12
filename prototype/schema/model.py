from pydantic import BaseModel, Field
from typing import List, Optional

class CommandAction(BaseModel):
    """定义 AI 必须遵循的输出格式"""
    thought: str = Field(description="AI 对当前状况的分析过程")
    command: str = Field(description="要执行的系统命令名称，如 nmap, ping, whoami")
    args: List[str] = Field(default_factory=list, description="命令的参数列表")
    is_safe: bool = Field(description="AI 自我评估该命令是否具备破坏性")
    
class Vulnerability(BaseModel):
    """单个漏洞项的具体描述"""
    service: str = Field(description="受影响的服务名称及端口，如 Apache (80/tcp)")
    cve_id: Optional[str] = Field(description="关联的 CVE 编号，若无则填写 'N/A'")
    severity: str = Field(description="风险等级：Critical/High/Medium/Low/Info")
    description: str = Field(description="漏洞简述及潜在影响")
    remediation: str = Field(description="修复建议或加固措施")
    
class PentestReport(BaseModel):
    """AI 漏洞研判报告的标准结构"""
    thought: str = Field(description="AI 对扫描指纹的深度推理过程")
    target_os: str = Field(description="识别到的操作系统版本")
    summary: str = Field(description="本次扫描的风险概况总结")
    vulnerabilities: List[Vulnerability] = Field(default_factory=list, description="发现的漏洞列表")
    next_steps: List[str] = Field(description="建议的后续渗透测试动作，如使用特定脚本进一步验证")