import json
from openai import OpenAI
from schema.model import CommandAction
from utils.config import Config
from loguru import logger

SYSTEM_PROMPT = """
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
                {"role": "system", "content": SYSTEM_PROMPT},
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