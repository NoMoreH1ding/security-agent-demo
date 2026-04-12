import os
import time
from loguru import logger

class SimpleLogger:
    def __init__(self):
        # 1. 每次运行生成一个唯一的文件夹，按时间排序一目了然
        self.session_id = time.strftime('%Y%m%d_%H%M%S')
        self.session_path = f"logs/{self.session_id}"
        os.makedirs(self.session_path, exist_ok=True)

        # 2. 清除默认配置，重新定义
        logger.remove()
        
        # 控制台：只看重点（绿色时间戳 + 级别提示）
        logger.add(lambda msg: print(msg, end=""), level="INFO", colorize=True, 
                   format="<green>{time:HH:mm:ss}</green> | <level>{level: <7}</level> | {message}")
        
        # 系统日志文件：保存所有详细过程（包括 DEBUG 级别）
        logger.add(f"{self.session_path}/system.log", level="DEBUG", 
                   format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}")

    def log_ai_trace(self, role: str, content: str, title: str = ""):
        """
        记录 AI 交互，支持角色标识。
        role: 角色名，如 RECON, ANALYSIS, TOOL, OBSERVER
        content: 日志内容
        title: 可选标题，如工具名或提示词说明
        """
        trace_file = f"{self.session_path}/ai_trace.log"
        timestamp = time.strftime('%H:%M:%S')
        
        # 针对长内容的截断处理（可选，防止日志文件过大）
        display_content = content
        
        with open(trace_file, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] === {role} === {title}\n")
            f.write(f"{display_content}\n")
            f.write("=" * 60 + "\n\n")
            
agent_logger = SimpleLogger()
