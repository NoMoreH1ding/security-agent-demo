import subprocess
import shlex
from schema.model import CommandAction
from datetime import datetime, timedelta
from threading import Timer
import sys
from loguru import logger

class CommandExecutor:
    def __init__(self):
        # 定义一个简单的黑名单，防止 AI 误操作（面试加分项）
        self.blacklist = ["rm", "chmod", "chown", "mkfs", "dd"]

    def execute(self, action: CommandAction) -> str:
        """执行 CommandAction 对象并返回结果"""
        
        # 1. 安全预检查
        if action.command in self.blacklist:
            return f"Error: 命令 '{action.command}' 被安全策略拦截。"

        if not action.is_safe:
            pass
            # 这里可以加入人工确认逻辑（Human-in-the-loop）

        # 2. 构造完整的命令字符串并安全分割
        # 使用 shlex.join 可以防止某些特殊字符导致的注入风险
        full_command = [action.command] + action.args
        
        try:
            # 3. 调用系统进程
            # 设置 timeout 防止扫描工具挂死导致程序崩溃
            process = subprocess.Popen(
                full_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            def timeout_handler():
                process.terminate()
                logger.error("执行超时。")
                return "Error: 执行超时。"

            timer = Timer(300, timeout_handler)  # 基础命令设置 30s 超时，nmap 建议更长
            timer.start()

            # 4. 组合输出
            output = ""
            for line in iter(process.stdout.readline, ''):
                output += line
                sys.stdout.write(line)
                sys.stdout.flush()
                timer.cancel()  # 重置超时计时器
                timer = Timer(300, timeout_handler)
                timer.start()

            if process.poll() is None:
                process.terminate()

            timer.cancel()

            if process.returncode == 0:
                return output
            else:
                logger.error(f"Execution Error (Code {process.returncode})")
                return f"{output}"

        except Exception as e:
            return f"Unexpected Error: {str(e)}"