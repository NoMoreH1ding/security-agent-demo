import time
from langchain_core.tools import tool
from typing import Annotated
from loguru import logger
import subprocess

@tool
def host_survival_check(
    target: Annotated[str, "目标IP地址或域名，例如 '192.168.1.1'"]
) -> str:
    """
    检查目标主机是否在线。在进行深度扫描之前，必须先运行此工具。
    """
    logger.info(f"[TOOL CALL] host_survival_check started for {target}")
    start_time = time.time()
    try:
        # 使用 -sn (Ping Scan) 仅探测存活，不扫描端口，速度极快
        cmd = ["nmap", "-sn", "--host-timeout", "10s", target]
        logger.debug(f"[EXEC] Running Command: {cmd}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )
        # 记录工具用时和返回值
        duration = time.time() - start_time
        logger.info(f"[TOOL DONE] Execution finished in {duration:.2f}s with return code {result.returncode}")
        
        if result.returncode != 0:
            logger.error(f"[EXEC ERROR] Nmap failed: {result.stderr}")
        
        if "Host is up" in result.stdout:
            line = result.stdout.split("\n")
            status_info = f"目标 {target} 在线。{line[3]}"
            logger.info(f"[OUTPUT] {status_info}")
            return status_info
        else:
            status_info = f"目标 {target} 似乎不在线或禁用了 ICMP/Ping 回应。"
            logger.warning(f"[OUTPUT] {status_info}")
            return status_info
    except Exception as e:
        logger.exception(f"[Critical Error] Unexpected error during host_survival_check")
        return f"探测过程中出现异常: {str(e)}"
    