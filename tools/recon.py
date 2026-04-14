import subprocess
import time
from typing import Annotated
from langchain_core.tools import tool
from loguru import logger
import core.parsers.nmap_parser as parser

@tool
def host_survival_check(
    target: Annotated[str, "目标IP地址或域名，例如 '192.168.1.1'"],
) -> str:
    """
    检查目标主机是否在线。侦察阶段的第一步。
    """
    try:
        cmd = ["nmap", "-sn", "--host-timeout", "10s", target]
        logger.info(f"[TOOL] 执行主机存活检查: {target}")
        logger.debug(f"[EXEC] Command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        logger.debug(f"[RAW OUTPUT] {result.stdout}")

        if "Host is up" in result.stdout:
            return f"目标 {target} 在线。"
        else:
            return f"目标 {target} 似乎不在线。"
    except Exception as e:
        return f"探测异常: {str(e)}"

@tool
def quick_port_scan(
    target: Annotated[str, "目标IP/域名"],
    top_n: Annotated[int, "扫描常用的端口数量"] = 100,
    speed: Annotated[int, "扫描速度等级 (1-5)"] = 4,
) -> str:
    """
    极速确定目标的端口开放情况。侦察阶段的必备步骤。
    """
    timing_map = {1: "-T1", 2: "-T2", 3: "-T3", 4: "-T4", 5: "-T5"}
    t_param = timing_map.get(speed, "-T4")

    try:
        cmd = ["nmap", "-Pn", t_param, "--top-ports", str(top_n), "--open", "--max-retries", "1", target]
        logger.info(f"[TOOL] 执行快速端口扫描: {target}")
        logger.debug(f"[EXEC] Command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        logger.debug(f"[RAW OUTPUT] {result.stdout}")
        return parser.quick_scan_parser(result.stdout)
    except Exception as e:
        return f"扫描异常: {str(e)}"

@tool
def waf_detection(
    target: Annotated[str, "目标URL，例如 '192.168.43.150:8080'"],
) -> str:
    """
    检查目标是否存在 WAF 保护。在对 Web 服务进行深度分析前必须执行。
    """
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    
    cmd = ["wafw00f", target, "--no-colors"]
    logger.info(f"[TOOL] 执行 WAF 探测: {target}")
    logger.debug(f"[EXEC] Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = result.stdout + result.stderr
        logger.debug(f"[RAW OUTPUT] {output}")

        if "is behind" in output:
            waf_name = output.split("is behind")[1].split("\n")[0].strip()
            return f"检测到 WAF 保护: {waf_name}。"
        return "确认未检测到 WAF 保护。"
    except Exception as e:
        return f"WAF 探测异常: {str(e)}"
