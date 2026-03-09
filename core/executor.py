import subprocess
import shlex
from schema.model import CommandAction
#from utils.logger import logger  # 假设你已经配置了 loguru

class CommandExecutor:
    def __init__(self):
        # 定义一个简单的黑名单，防止 AI 误操作（面试加分项）
        self.blacklist = ["rm", "chmod", "chown", "mkfs", "dd"]

    def execute(self, action: CommandAction) -> str:
        """执行 CommandAction 对象并返回结果"""
        
        # 1. 安全预检查
        if action.command in self.blacklist:
            #logger.warning(f"检测到黑名单命令: {action.command}")
            return f"Error: 命令 '{action.command}' 被安全策略拦截。"

        if not action.is_safe:
            #logger.warning(f"AI 标记该命令具备潜在风险: {action.command}")
            pass
            # 这里可以加入人工确认逻辑（Human-in-the-loop）

        # 2. 构造完整的命令字符串并安全分割
        # 使用 shlex.join 可以防止某些特殊字符导致的注入风险
        full_command = [action.command] + action.args
        
        try:
            #logger.info(f"正在执行命令: {' '.join(full_command)}")
            
            # 3. 调用系统进程
            # 设置 timeout 防止扫描工具挂死导致程序崩溃
            result = subprocess.run(
                full_command,
                capture_output=True,
                text=True,
                timeout=30  # 基础命令设置 30s 超时，nmap 建议更长
            )

            # 4. 组合输出
            if result.returncode == 0:
                #logger.success(f"命令执行成功: {action.command}")
                return result.stdout
            else:
                #logger.error(f"命令执行报错: {result.stderr}")
                return f"Execution Error (Code {result.returncode}): {result.stderr}"

        except subprocess.TimeoutExpired:
            #logger.error("命令执行超时")
            return "Error: 执行超时。"
        except FileNotFoundError:
            #logger.error(f"找不到工具: {action.command}")
            return f"Error: 系统中未找到工具 '{action.command}'。"
        except Exception as e:
            #logger.exception("发生未知执行错误")
            return f"Unexpected Error: {str(e)}"