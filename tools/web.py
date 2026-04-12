import os
import time
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
def dir_search(
    target: Annotated[str, "目标 URL，例如 'http://192.168.43.150:8080'"],
    extensions: Annotated[str, "扫描的文件扩展名，例如 'php,txt,sql,zip'"] = "php,txt,env",
) -> str:
    """
    使用 dirsearch 对目标进行目录和隐藏文件爆破。
    适用于【发现 (Analysis)】阶段，能够找到 Nmap 扫不出的隐藏入口。
    """
    logger.info(f"[TOOL] 执行目录爆破: {target}")
    
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    # 构造命令
    # --format plain: 纯文本输出
    # --quiet: 减少干扰
    # -e: 扩展名
    # --random-agent: 随机 UA 规避简单拦截
    cmd = [
        "dirsearch",
        "-u", target,
        "-e", extensions,
        "--format", "plain",
        "--random-agent",
        "--quiet-mode"
    ]
    logger.debug(f"[EXEC] Command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        logger.debug(f"[RAW OUTPUT] {result.stdout}")
        
        # 解析输出
        # dirsearch 的 plain 格式通常是: [HH:MM:SS] 200 - 1KB - /path
        output = result.stdout.strip()
        if not output:
            return "目录爆破完成，未发现显著的隐藏目录或文件。"
            
        # 提取关键行（200 OK 或 301 重定向）
        findings = []
        for line in output.split('\n'):
            if "200" in line or "301" in line or "403" in line:
                findings.append(line.strip())
        
        if not findings:
            return "未发现高价值的路径。"
            
        summary = "### 目录爆破发现清单\n\n" + "\n".join([f"- {f}" for f in findings[:20]])
        if len(findings) > 20:
            summary += f"\n\n*注意：共发现 {len(findings)} 个路径，仅显示前 20 个。*"
            
        return summary
        
    except subprocess.TimeoutExpired:
        return "目录爆破超时。"
    except Exception as e:
        return f"执行目录爆破失败: {str(e)}"


@tool
def nuclei_scan(
    target: Annotated[str, "目标 URL 或 IP，例如 'http://192.168.43.1'"],
    severity: Annotated[str, "扫描的严重等级，可选: info, low, medium, high, critical"] = "medium,high,critical",
) -> str:
    """
    使用 Nuclei 进行高度模板化的漏洞扫描，适用于发现特定 CVE、配置错误和信息泄露。
    在发现 80/81 等 Web 端口后，建议使用此工具。
    """
    logger.info(f"[TOOL] 执行 Nuclei 扫描: {target} (等级: {severity})")
    
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    # 构造 Nuclei 命令
    cmd = [
        "nuclei",
        "-u", target,
        "-severity", severity,
        "-silent",
        "-jsonl"
    ]
    logger.debug(f"[EXEC] Command: {' '.join(cmd)}")
    
    try:
        # 执行命令，设置 5 分钟超时
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        logger.debug(f"[RAW OUTPUT] {result.stdout}")
        
        if result.returncode != 0 and not result.stdout:
            return f"Nuclei 扫描失败。错误信息: {result.stderr}"
        
        # 解析 JSONL 输出
        import json
        findings = []
        for line in result.stdout.strip().split('\n'):
            if not line:
                continue
            try:
                data = json.loads(line)
                findings.append({
                    "template_id": data.get("template-id"),
                    "name": data.get("info", {}).get("name"),
                    "severity": data.get("info", {}).get("severity"),
                    "matched": data.get("matched-at")
                })
            except json.JSONDecodeError:
                continue
        
        if not findings:
            return "Nuclei 扫描完成，未发现匹配的高风险漏洞模板。"
            
        from core.parsers.nuclei_parser import nuclei_scan_parser
        return nuclei_scan_parser(json.dumps(findings, indent=2, ensure_ascii=False))
        
    except subprocess.TimeoutExpired:
        return "Nuclei 扫描超时。"
    except Exception as e:
        return f"执行 Nuclei 时发生异常: {str(e)}"


@tool
def web_request(
    url: Annotated[str, "完整的请求 URL，例如 'http://192.168.43.150:8080/actuator/env'"],
    method: Annotated[str, "HTTP 方法: GET, POST, PUT, DELETE, HEAD"] = "GET",
    headers: Annotated[Optional[Dict[str, str]], "自定义 HTTP 请求头"] = None,
    data: Annotated[Optional[str], "POST/PUT 请求携带的数据"] = None,
    timeout: Annotated[int, "超时时间（秒）"] = 10
) -> str:
    """
    发送精准的 HTTP 请求并返回结果。
    这是【漏洞验证 (Verification)】阶段的核心工具，用于确认漏洞的存在。
    """
    logger.info(f"[TOOL] 执行 HTTP {method}: {url}")
    
    import requests
    from utils.security import validate_within_scope
    
    # 基础安全校验：从 URL 提取 Host 并校验范围
    # 注意：这里假设 targets 存在于全局配置或通过某种方式传递
    # 暂时先实现功能，后续可增强校验
    
    try:
        response = requests.request(
            method=method.upper(),
            url=url,
            headers=headers,
            data=data,
            timeout=timeout,
            verify=False # 忽略 SSL 校验，方便测试
        )
        
        # 记录原始细节到日志
        logger.debug(f"[RAW RESPONSE] Status: {response.status_code}")
        logger.debug(f"[RAW RESPONSE] Headers: {response.headers}")
        try:
            logger.debug(f"[RAW RESPONSE] Body: {response.text[:5000]}")
        except:
            logger.debug("[RAW RESPONSE] Body: (Non-text content)")
        
        # 构造精简的返回信息
        res_info = f"Status: {response.status_code}\n"
        res_info += f"Headers: {dict(response.headers)[:5]} (已截断)\n"
        
        # 处理 Body，如果是二进制或过长则截断
        content_type = response.headers.get("Content-Type", "")
        if "application/json" in content_type:
            body = response.text[:1000]
        elif "text/" in content_type:
            body = response.text[:1000]
        else:
            body = f"[Binary or Non-text content, size: {len(response.content)} bytes]"
            
        return f"{res_info}\nBody Summary:\n{body}"
        
    except Exception as e:
        return f"HTTP 请求失败: {str(e)}"


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
