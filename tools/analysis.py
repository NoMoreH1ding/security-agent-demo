import subprocess
import json
import os
from typing import Annotated, Optional
from langchain_core.tools import tool
from loguru import logger
import core.parsers.nmap_parser as nmap_parser
from core.parsers.nuclei_parser import nuclei_scan_parser

@tool
def service_detail_scan(
    target: Annotated[str, "目标IP/域名"],
    ports: Annotated[str, "需要深入识别的具体端口，例如 '22,80,445'"],
) -> str:
    """
    针对已发现的开放端口进行深度扫描。获取服务版本、OS指纹、Web标题等核心信息。
    """
    try:
        cmd = ["nmap", "-Pn", "-sV", "-sC", "-T4", "--version-intensity", "2", "--min-rate", "1000", "-p", ports, "--max-retries", "1", target]
        logger.info(f"[TOOL] 执行深度服务识别: {target} (Ports: {ports})")
        logger.debug(f"[EXEC] Command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        logger.debug(f"[RAW OUTPUT] {result.stdout}")
        return nmap_parser.service_scan_parser(result.stdout)
    except Exception as e:
        return f"深度扫描异常: {str(e)}"

@tool
def sqlmap_scan(
    url: Annotated[str, "包含参数的测试 URL"],
    cookie: Annotated[Optional[str], "Session Cookie，例如 'PHPSESSID=xxx'"] = None,
) -> str:
    """
    对可疑 URL 进行初步的 SQL 注入探测。支持身份认证。
    """
    logger.info(f"[TOOL] 执行 SQLmap 探测: {url}")
    cmd = ["sqlmap", "-u", url, "--batch", "--level", "1", "--random-agent", "--threads", "5"]
    if cookie:
        cmd.extend(["--cookie", cookie])
    
    logger.debug(f"[EXEC] Command: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        from core.parsers.sqlmap_parser import sqlmap_parser
        return sqlmap_parser(result.stdout)
    except Exception as e:
        return f"SQLmap 异常: {str(e)}"

@tool
def nuclei_scan(
    target: Annotated[str, "目标URL"],
    severity: Annotated[str, "严重等级"] = "medium,high,critical",
    cookie: Annotated[Optional[str], "Session Cookie"] = None,
) -> str:
    """
    使用 Nuclei 进行高度模板化的漏洞扫描。支持携带 Cookie 绕过登录。
    """
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    cmd = ["nuclei", "-u", target, "-severity", severity, "-silent", "-jsonl"]
    if cookie:
        cmd.extend(["-H", f"Cookie: {cookie}"])
    
    logger.info(f"[TOOL] 执行 Nuclei 扫描: {target}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if not result.stdout.strip():
            return "Nuclei 扫描完成，未发现匹配的漏洞。"
        
        return nuclei_scan_parser(result.stdout)
    except Exception as e:
        return f"Nuclei 异常: {str(e)}"

@tool
def dir_search(
    target: Annotated[str, "目标 URL"],
    extensions: Annotated[str, "文件扩展名"] = "php,txt,env",
    cookie: Annotated[Optional[str], "Session Cookie"] = None,
    url: Annotated[Optional[str], "目标 URL (别名)"] = None,
) -> str:
    """
    使用 dirsearch 进行目录爆破。支持携带 Cookie 扫描授权页面。
    如果 dirsearch 未安装，自动降级使用 ffuf 执行目录扫描。
    注意：参数名 'target' 也可以接受 'url' 作为输入（兼容性）。
    """
    # 兼容性处理：如果提供了 url 参数，使用 url 作为 target
    if url:
        target = url
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    cmd = ["dirsearch", "-u", target, "-e", extensions, "--format", "plain", "--random-agent", "--quiet-mode"]
    if cookie:
        cmd.extend(["--cookie", cookie])

    logger.info(f"[TOOL] 执行目录爆破: {target}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout.strip()
        findings = [line.strip() for line in output.split('\n') if "200" in line or "301" in line]
        return "### 目录爆破发现清单\n\n" + "\n".join([f"- {f}" for f in findings[:20]])
    except FileNotFoundError:
        # dirsearch 未安装，降级到 ffuf
        logger.warning("[TOOL] dirsearch 未安装，使用 ffuf 替代")
        return _ffuf_dir_fallback(target, extensions, cookie)
    except Exception as e:
        return f"目录爆破异常: {str(e)}"


def _ffuf_dir_fallback(target: str, extensions: str, cookie: Optional[str]) -> str:
    """当 dirsearch 不可用时，使用 ffuf 执行目录扫描的降级逻辑"""
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    if not __import__('os').path.isfile(wordlist):
        wordlist = "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
    if not __import__('os').path.isfile(wordlist):
        return "目录爆破失败：dirsearch 未安装且未找到 ffuf 字典。建议 apt install dirsearch 或 apt install seclists。"

    cmd = ["ffuf", "-u", f"{target}/FUZZ", "-w", wordlist, "-c", "-json",
           "-t", "40", "-timeout", "10", "-fc", "404",
           "-mc", "200,204,301,302,307,401,403,405,500",
           "-of", "json", "-maxtime-job", "300"]

    if extensions:
        cmd.extend(["-e", extensions])
    if cookie:
        cmd.extend(["-b", cookie])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=360)
        findings = []
        for line in result.stdout.strip().split('\n'):
            if not line:
                continue
            try:
                data = __import__('json').loads(line)
                if data.get("status", 0) != 404:
                    findings.append(f"[{data['status']}] {data.get('url', '')} ({data.get('length', 0)}B)")
            except:
                continue

        if not findings:
            return "目录爆破完成（使用 ffuf 降级），未发现高价值路径。"
        return "### 目录爆破发现清单 (ffuf 降级)\n\n" + "\n".join([f"- {f}" for f in findings[:20]])
    except subprocess.TimeoutExpired:
        return "ffuf 目录扫描超时。"
    except Exception as e:
        return f"ffuf 降级异常: {str(e)}"

@tool
def fingerprint_whatweb(
    target: Annotated[str, "目标URL"],
) -> str:
    """
    利用 Whatweb 收集目标 Web 服务的相关指纹信息。
    """
    try:
        cmd = ["whatweb", target, "--color=never"]
        logger.info(f"[TOOL] 执行指纹嗅探: {target}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        return f"指纹结果: {result.stdout}"
    except Exception as e:
        return f"嗅探异常: {str(e)}"
