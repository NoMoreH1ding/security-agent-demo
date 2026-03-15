import os
import time
import json
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

    def log_ai_trace(self, prompt, response):
        """记录 AI 交互，用于分析 Prompt 效果和排查幻觉"""
        trace_file = f"{self.session_path}/ai_trace.log"
        with open(trace_file, "a", encoding="utf-8") as f:
            f.write(f"--- [{'USER' if prompt else 'SYSTEM'}] @ {time.strftime('%H:%M:%S')} ---\n")
            f.write(f"PROMPT:\n{prompt}\n\n")
            f.write(f"RESPONSE:\n{response}\n")
            f.write("-" * 50 + "\n\n")
            
agent_logger = SimpleLogger()
from loguru import logger as _raw_logger