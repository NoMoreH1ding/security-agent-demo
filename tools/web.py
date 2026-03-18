import time
import tools
import utils.timer as timer
from langchain_core.tools import tool
from typing import Annotated
from loguru import logger
import subprocess


@tool
def waf_detection(
    target: Annotated[str, "目标IP地址或域名，例如 '192.168.1.1'"],
) -> str:
    """
    检查目标 Web 服务是否存在 WAF 保护。在进行所有 Web 测试之前，必须先运行此工具。
    """
    try:
        cmd = ["wafw00f", target]
        logger.debug(f"[EXEC] Running Command: {cmd}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        logger.debug(f"[OUTPUT] {result.stdout}")

        if "No WAF detected" in result.stdout:
            return "未检测到 WAF 保护,可以进行下一步操作"
        else:
            return "目标似乎正被 WAF 保护,执行扫描任务时务必使用安全参数"
    except Exception as e:
        logger.exception(f"[ERROR] Unexpected error during waf_detection")
        return f"探测过程中出现异常: {str(e)}"

