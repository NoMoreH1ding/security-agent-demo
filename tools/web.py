import os
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
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    # 1. 增加 --no-colors 避免乱码
    # 2. 增加 -a (Check all WAFs) 有时能强制输出更多信息
    cmd = ["wafw00f", target, "--no-colors"]

    try:
        logger.debug(f"[EXEC] Running Command: {cmd}")

        # 使用 Popen 并设置环境变量 PYTHONUNBUFFERED=1
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"

        # 增加 timeout 确保即使工具挂起也能回收
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            timeout=60,  # WAFW00F 有时探测较慢
        )

        output = result.stdout + result.stderr
        logger.debug(f"[FULL OUTPUT] {output}")

        # 逻辑判断优化
        if "is behind" in output:
            # 提取具体的 WAF 名称
            waf_name = output.split("is behind")[1].split("\n")[0].strip()
            return f"检测到 WAF 保护: {waf_name}。请使用低频模式扫描。"
        elif "No WAF detected" in output:
            return "确认未检测到 WAF 保护，可以进行下一步操作。"
        else:
            # 如果输出截断，返回原始输出的最后两行帮助 AI 进一步决策
            last_lines = "\n".join(output.splitlines()[-2:])
            return f"探测结果模糊，输出末尾为: {last_lines}"

    except subprocess.TimeoutExpired:
        return "WAF 探测超时，目标可能存在防护重定向或丢包。"
    except Exception as e:
        return f"异常: {str(e)}"


@tool
def fingerprint_whatweb(
    target: Annotated[str, "目标IP地址或域名，例如 '192.168.1.1'"],
) -> str:
    """
    利用 Whatweb 收集目标 Web 服务的相关指纹信息, 用于进一步分析 Web 服务可能存在的攻击面
    """

    try:
        cmd = ["whatweb", target, "--color=never"]
        logger.debug(f"[EXEC] Running Command: {cmd}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        logger.debug(f"[OUTPUT] {result.stdout}")

        return f"指纹嗅探的结果如下{result.stdout}"

    except Exception as e:
        logger.exception(f"[ERROR] Unexpected error during waf_detection")
        return f"探测过程中出现异常: {str(e)}"
