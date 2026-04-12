import time
from langchain_core.tools import tool
from typing import Annotated
from loguru import logger
import subprocess
import core.parsers.nmap_parser as parser


@tool
def host_survival_check(
    target: Annotated[str, "目标IP地址或域名，例如 '192.168.1.1'"],
) -> str:
    """
    检查目标主机是否在线。在进行深度扫描之前，必须先运行此工具。
    """
    start_time = time.time()
    try:
        # 使用 -sn (Ping Scan) 仅探测存活，不扫描端口，速度极快
        cmd = ["nmap", "-sn", "--host-timeout", "10s", target]
        logger.debug(f"[EXEC] Running Command: {cmd}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            logger.error(f"[EXEC ERROR] Nmap failed: {result.stderr}")

        if "Host is up" in result.stdout:
            line = result.stdout.split("\n")
            status_info = f"目标 {target} 在线。{line[3]}"
            return status_info
        else:
            status_info = f"目标 {target} 似乎不在线或禁用了 ICMP/Ping 回应。"
            logger.debug(f"[OUTPUT] {status_info}")
            return status_info
    except Exception as e:
        logger.exception(f"[ERROR] Unexpected error during host_survival_check")
        return f"探测过程中出现异常: {str(e)}"


@tool
def quick_port_scan(
    target: Annotated[str, "目标IP/域名"],
    top_n: Annotated[int, "扫描最常用的端口数量, 默认为100, 可按需增减该数值."] = 100,
    speed: Annotated[int, "扫描速度等级 (1-5)。1最慢，5最快。默认为4。"] = 4,
) -> str:
    """
    利用 Nmap 极速确定目标的端口开放情况。
    这是初次探测的必备步骤，仅发现端口，不进行版本识别，以确保最高效率。
    """
    timing_map = {1: "-T1", 2: "-T2", 3: "-T3", 4: "-T4", 5: "-T5"}
    t_param = timing_map.get(speed, "-T4")

    try:
        # 使用 -F 或 --top-ports 配合 -Pn 和 SYN 扫描 (-sS 默认)
        cmd = [
            "nmap",
            "-Pn",
            t_param,
            "--top-ports", str(top_n),
            "--open",  # 只显示开放端口，减少解析负担
            "--max-retries", "1",
            target,
        ]
        logger.info(f"[TOOL] 执行快速端口扫描: {target} (Top {top_n})")
        logger.debug(f"[EXEC] Command: {' '.join(cmd)}")
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        logger.debug(f"[RAW OUTPUT] {result.stdout}")
        
        if result.returncode != 0:
            logger.error(f"[NMAP ERROR] {result.stderr}")

        port_report = parser.quick_scan_parser(result.stdout)
        return port_report
    except subprocess.TimeoutExpired:
        return "快速扫描超时，请尝试减少 top_n 数量或提高速度等级。"
    except Exception as e:
        return f"扫描异常: {str(e)}"


@tool
def service_detail_scan(
    target: Annotated[str, "目标IP/域名"],
    ports: Annotated[str, "需要深入识别的具体端口，例如 '22,80,445'"],
) -> str:
    """
    针对已发现的开放端口进行深度扫描。
    包含版本探测(-sV)和默认脚本扫描(-sC)，能获取服务版本、OS指纹、Web标题等核心信息。
    """
    try:
        logger.info(f"[TOOL] 执行深度服务识别: {target} (Ports: {ports})")
        # 优化组合：
        # -sV: 版本识别
        # -sC: 默认脚本扫描（获取高价值信息的核心）
        # --version-intensity 2: 轻量级识别，兼顾速度
        # --min-rate 1000: 强制发包速率，在端口少时极快
        cmd = [
            "nmap",
            "-Pn",
            "-sV",
            "-sC",
            "-T4",
            "--version-intensity", "2",
            "--min-rate", "1000",
            "-p", ports,
            "--max-retries", "1",
            target,
        ]
        logger.debug(f"[EXEC] Command: {' '.join(cmd)}")
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        logger.debug(f"[RAW OUTPUT] {result.stdout}")
        
        if result.returncode != 0:
            logger.error(f"[NMAP ERROR] {result.stderr}")

        service_report = parser.service_scan_parser(result.stdout)
        return service_report
    except subprocess.TimeoutExpired:
        return f"深度扫描超时。建议分批扫描端口: {ports}"
    except Exception as e:
        return f"扫描异常: {str(e)}"

