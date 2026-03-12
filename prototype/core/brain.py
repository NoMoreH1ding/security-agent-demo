import json
from openai import OpenAI
from schema.model import CommandAction, PentestReport
from utils.config import Config
from loguru import logger

SYSTEM_PROMPT_EXEC = """
你是一名专业的自动化渗透测试助手（AI-PTA）。
你的目标是根据用户提供的意图，将其拆解为具体、可执行的 Linux 系统命令。

### 规则：
1. **严格输出 JSON**：你必须且仅能输出一个 JSON 对象，格式必须符合：
   {"thought": "你的推理过程", "command": "命令名", "args": ["参数1", "参数2"], "is_safe": true/false}
2. **安全优先**：在执行任何具有破坏性的命令前，必须在 is_safe 字段中标记为 false。
3. **最小化输出**：不要包含任何 Markdown 格式（如 ```json），只给原始字符串。
4. **当前环境**：你运行在 Kali Linux 系统中，拥有标准的红队工具链。

### 推理逻辑 (ReAct)：
- Thought: 分析用户意图，结合当前已知的系统信息。
- Action: 选择最合适的工具（nmap, whoami, ping, ifconfig 等）。
"""
SYSTEM_PROMPT_ANALYZE = """
你是一名资深红队专家。你的任务是分析以下 Nmap 扫描结果并生成专业的漏洞研判报告。
### 分析要求：
1. **版本关联**：根据服务版本号（如 Apache 2.4.41），检索服务发布版本时至今的重大 CVE 漏洞。请优先匹配与识别到的 target_os 版本相符的漏洞，对于版本不匹配的经典漏洞，需标注‘需验证系统补丁状态’。
2. **攻击面评估**：重点关注远程代码执行 (RCE)、未授权访问和信息泄露。
3. **风险分级**：使用 [高/中/低] 标识每个发现。
4. **输出格式**：必须使用 JSON 格式且不包含任何 Markdown 格式。报告整体的格式必须符合：
{"thought","你对扫描指纹的深度推理过程","target_os":"识别到的操作系统版本","summary":"本次扫描的风险概况总结","vulnerabilities":["漏洞1","漏洞2"],"next_steps":["建议的后续渗透测试动作","如使用特定脚本进一步验证","按照不同的建议分成数个条目"]}
对于发现可能存在的漏洞，其同样需要使用JSON格式描述并在上文的报告的vulnerabilities:[]处逐个列出,格式必须符合：
{"service":"受影响的服务名称及端口，如 Apache (80/tcp)","cve_id":"关联的 CVE 编号，若无则填写 'N/A'","severity":"风险等级：Critical/High/Medium/Low/Info","description":"漏洞简述及潜在影响","remediation","修复建议或加固措施"}
"""

class PentestBrain:
    def __init__(self):
        self.client = OpenAI(
            api_key=Config.DEEPSEEK_API_KEY,
            base_url=Config.BASE_URL
        )
        self.model = "deepseek-chat"

    def think(self, user_input: str) -> CommandAction:
        """根据输入，返回结构化的指令对象"""
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT_EXEC},
                {"role": "user", "content": user_input}
            ],
            temperature=0.1  # 降低随机性，保证命令生成的稳定性
        )
        
        raw_content = response.choices[0].message.content.strip()
        # logger.info(f"Ai 返回内容: {raw_content}")
        
        
        # 核心：使用 Pydantic 的 parse_raw 确保 AI 没在胡说八道
        try:
            return CommandAction.parse_raw(raw_content)
        except Exception as e:
            print(f"[!] AI 返回格式错误: {e}")
            # 这里可以加入重试逻辑或错误处理
            raise
        
    def analyze(self, nmap_markdown: str) -> PentestReport:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT_ANALYZE},
                {"role": "user", "content": nmap_markdown}
            ],
            temperature=0.1  # 降低随机性，保证命令生成的稳定性
        )
        raw_content = response.choices[0].message.content.strip()
        logger.info(f"Ai 返回报告内容: {raw_content}")
        
        
        # 核心：使用 Pydantic 的 parse_raw 确保 AI 没在胡说八道
        try:
            return PentestReport.parse_raw(raw_content)
        except Exception as e:
            print(f"[!] AI 返回格式错误: {e}")
            # 这里可以加入重试逻辑或错误处理
            raise