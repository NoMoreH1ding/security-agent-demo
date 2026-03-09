from pydantic import BaseModel, Field
from typing import List, Optional

class CommandAction(BaseModel):
    """定义 AI 必须遵循的输出格式"""
    thought: str = Field(description="AI 对当前状况的分析过程")
    command: str = Field(description="要执行的系统命令名称，如 nmap, ping, whoami")
    args: List[str] = Field(default_factory=list, description="命令的参数列表")
    is_safe: bool = Field(description="AI 自我评估该命令是否具备破坏性")

class PentestReport(BaseModel):
    """定义最终生成的简报格式"""
    summary: str
    vulnerabilities: List[str]
    next_steps: Optional[str] = None