import time
import tools
import utils.timer as timer
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
    logger.info(f"[TOOL CALL] host_survival_check started for {target}")
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
            logger.info(f"[OUTPUT] {status_info}")
            return status_info
        else:
            status_info = f"目标 {target} 似乎不在线或禁用了 ICMP/Ping 回应。"
            logger.warning(f"[OUTPUT] {status_info}")
            return status_info
    except Exception as e:
        logger.exception(f"[ERROR] Unexpected error during host_survival_check")
        return f"探测过程中出现异常: {str(e)}"


@tool
def quick_port_scan(
    target: Annotated[str, "目标IP/域名"],
    top_n: Annotated[int, "扫描最常用的端口数量, 默认为100, 可按需增减该数值."] = 100,
    speed: Annotated[int, "扫描速度等级 (1-4)。1最慢最隐蔽，4最快。默认为3。"] = 3,
) -> str:
    """
    利用 Nmap 快速确定目标的端口开放信息, **仅探测端口,不包含版本信息**.
    仅当在确定了主机存活后执行, 且应是确定存活后的下一步动作
    """
    logger.info(f"[TOOL CALL] quick_port_scan started for {target}")
    timing_map = {1: "T1", 2: "-T2", 3: "-T3", 4: "-T4"}
    t_param = timing_map.get(speed, "-T3")
    logger.info(f"[PRE EXEC] 准备执行快速扫描, Target: {target}, Speed: {t_param}")

    try:

        cmd = [
            "nmap",
            "-Pn",
            t_param,
            "--top-ports",
            f"{top_n}",
            "--max-retries",
            "1",
            target,
        ]
        logger.debug(f"[EXEC] Command: {cmd}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        logger.debug(f"[OUTPUT] {result.stdout}")

        if result.returncode != 0:
            logger.error(f"[EXEC ERROR] Nmap failed: {result.stderr}")

        # 检测是否出现端口扫描被防火墙拒绝的情况
        if "filtered" in result.stdout:
            logger.warning(f"[WARNING] 一些端口可能受防火墙保护")

        # 正常解析
        port_report = parser.quick_scan_parser(result.stdout)
        logger.info(f"[OUTPUT] {port_report}")
        return port_report
    except subprocess.TimeoutExpired:
        logger.error(f"[ERROR] 扫描超时! ")
        return f"扫描超时。此次扫描使用的关键参数为{t_param} --top-ports {top_n},考虑更改相关参数并等待后重试?"


@tool
def service_detail_scan(
    target: Annotated[str, "目标IP/域名"],
    ports: Annotated[str, "需要深入识别的具体端口，例如 '22,80,3306'"],
) -> str:
    """
    利用 Nmap -sV确定端口开放后扫描其服务版本, **仅在探测端口开放后需要探测服务版本时执行**.
    """
    logger.info(f"[TOOL CALL] service_detail_scan started for {target}")
    try:
        cmd = ["nmap", "-Pn", "-sV", "-sC", "-p", ports, "--max-retries", "1", target]
        logger.info(f"[PRE EXEC]启动深度服务扫描: {target} 端口: {ports}")
        logger.debug(f"[EXEC] Command: {cmd}")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=360)
        logger.debug(f"[OUTPUT] {result.stdout}")

        if result.returncode != 0:
            logger.error(f"[EXEC ERROR] Nmap failed: {result.stderr}")

        service_report = parser.service_scan_parser(result.stdout)
        logger.info(f"[OUTPUT] {service_report}")
        return service_report
    except subprocess.TimeoutExpired:
        logger.error(f"[ERROR] 扫描超时! ")
        return f"扫描超时。此次扫描的目标端口为{ports},考虑减少不必要的端口扫描任务并等待后重试?"
