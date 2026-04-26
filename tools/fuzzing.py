"""
专业 Fuzz 工具链 - 基于 Kali Linux ffuf (Fuzz Faster U Fool)

功能：
1. 目录/路径发现 (ffuf_dir_scan)
2. 参数名模糊测试 (ffuf_param_scan)
3. POST 数据 Fuzz (ffuf_post_scan)
4. VHost 虚拟主机发现 (ffuf_vhost_scan)

依赖：
- ffuf: apt install ffuf
- seclists: apt install seclists (可选，提供专业字典)
"""

import subprocess
import os
from typing import Annotated, Optional
from langchain_core.tools import tool
from loguru import logger
from core.parsers.ffuf_parser import ffuf_directory_parser, ffuf_param_parser


# ===== 内置字典路径 (Kali Linux 标准路径) =====

KALI_WORDLISTS = {
    "dir_common": "/usr/share/wordlists/dirb/common.txt",
    "dir_big": "/usr/share/wordlists/dirb/big.txt",
    "dir_small": "/usr/share/wordlists/dirb/small.txt",
    "seclists_dir": "/usr/share/seclists/Discovery/Web-Content",
    "seclists_dirs": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "seclists_params": "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
    "seclists_xss": "/usr/share/seclists/Fuzzing/XSS.fuzz",
    "seclists_sqli": "/usr/share/seclists/Fuzzing/SQLi.txt",
}


def _resolve_wordlist(name: str) -> str:
    """解析字典名称到实际路径，优先使用 SecLists"""
    # 如果是完整路径，直接使用
    if os.path.isfile(name):
        return name
    
    # 尝试从内置映射中查找
    path = KALI_WORDLISTS.get(name)
    if path and os.path.isfile(path):
        return path
    
    # 回退到 dirb common
    fallback = KALI_WORDLISTS["dir_common"]
    if os.path.isfile(fallback):
        return fallback
    
    # 最后回退：临时生成最小字典
    return _generate_minimal_wordlist()


def _generate_minimal_wordlist() -> str:
    """生成临时最小字典（当系统无 SecLists 时）"""
    minimal = [
        "admin", "login", "config", "api", "test",
        ".env", ".git", "robots.txt", "sitemap.xml",
        "wp-admin", "wp-login", "phpinfo", "phpmyadmin",
        "upload", "download", "backup", "database",
        "server-status", "actuator", "swagger",
        "css", "js", "images", "assets",
        "index.php", "index.html", "index.jsp",
        "api/v1", "api/v2", "graphql",
        "debug", "console", "manager",
    ]
    tmp_path = "/tmp/_ffuf_minimal_wordlist.txt"
    with open(tmp_path, "w") as f:
        f.write("\n".join(minimal))
    return tmp_path


def _build_ffuf_base_cmd(
    url: str,
    wordlist: str,
    mode: str = "dir",
    cookie: Optional[str] = None,
    threads: int = 40,
    timeout: int = 10,
    rate: int = 0,
    match_codes: str = "200,204,301,302,307,401,403,405,500",
    extra_args: Optional[list] = None,
) -> list:
    """构建 ffuf 基础命令"""
    cmd = [
        "ffuf",
        "-u", url,
        "-w", wordlist,
        "-c",  # 彩色输出（但我们只解析 JSON）
        "-json",  # JSON 输出便于解析
        "-t", str(threads),
        "-timeout", str(timeout),
        "-mc", match_codes,  # 匹配的状态码
        "-ac",  # 重要：启用自动校准以过滤虚假结果 (wildcard responses)
        "-of", "json",  # 输出格式
        "-maxtime-job", "300",  # 单次任务最大时间 5 分钟
        "-se",  # 遇到严重网络错误时停止
    ]
    
    if mode == "param":
        # 参数模式：FUZZ 在查询字符串中
        pass  # URL 中已包含 FUZZ 占位符
    
    if mode == "vhost":
        cmd.extend(["-mode", "clusterbomb"])
    
    if cookie:
        cmd.extend(["-b", cookie])
    
    if rate > 0:
        cmd.extend(["-rate", str(rate)])
    
    if extra_args:
        cmd.extend(extra_args)
    
    return cmd


@tool
def ffuf_dir_scan(
    target: Annotated[str, "目标 URL，例如 'http://192.168.1.1/FUZZ' 或 'http://192.168.1.1'"],
    wordlist: Annotated[str, "字典路径或名称。可选: dir_common, dir_big, seclists_dirs, 或自定义完整路径"] = "dir_common",
    cookie: Annotated[Optional[str], "Session Cookie，例如 'PHPSESSID=xxx'"] = None,
    threads: Annotated[int, "并发线程数"] = 40,
    extensions: Annotated[str, "附加文件扩展名，例如 'php,txt,html'"] = "",
    scan_intensity: Annotated[str, "扫描强度: minimal(最小字典), standard(常用字典), deep(大字典)"] = "standard",
) -> str:
    """
    使用 ffuf 进行高速目录/路径发现。
    比 dirsearch 更快，适合大规模路径枚举。
    支持携带 Cookie 绕过认证。
    使用方式：在 URL 中使用 FUZZ 占位符，如 'http://target/FUZZ'；若不包含 FUZZ，工具会自动追加。
    scan_intensity 参数控制扫描深度：minimal(最小字典，约30条), standard(常用字典), deep(大字典)
    """
    logger.info(f"[TOOL] ffuf 目录扫描: {target} (强度: {scan_intensity})")
    
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    
    # 处理 FUZZ 占位符
    if "FUZZ" not in target:
        target = target.rstrip("/") + "/FUZZ"
    
    # 根据扫描强度自动选择字典
    if scan_intensity == "minimal":
        wordlist_path = _generate_minimal_wordlist()
        logger.info(f"[TOOL] 使用最小字典 (约30个常用路径) 进行快速扫描")
    elif scan_intensity == "deep":
        # 尝试使用大字典，回退到常用字典
        if wordlist == "dir_common":
            wordlist = "seclists_dirs"  # 使用更大的字典
        wordlist_path = _resolve_wordlist(wordlist)
        logger.info(f"[TOOL] 使用深度扫描字典: {wordlist_path}")
    else:  # standard
        wordlist_path = _resolve_wordlist(wordlist)
    cmd = _build_ffuf_base_cmd(target, wordlist_path, mode="dir", cookie=cookie, threads=threads)
    
    if extensions:
        cmd.extend(["-e", extensions])
    
    logger.debug(f"[EXEC] Command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=360)
        logger.debug(f"[RAW OUTPUT] {result.stdout[:1000]}")
        
        if result.returncode != 0 and not result.stdout:
            return f"ffuf 执行异常: {result.stderr[:300]}"
        
        return ffuf_directory_parser(result.stdout)
    
    except subprocess.TimeoutExpired:
        return "ffuf 目录扫描超时（5 分钟），请考虑缩小字典范围。"
    except FileNotFoundError:
        return "ffuf 未安装。请执行: apt install ffuf"
    except Exception as e:
        return f"ffuf 执行异常: {str(e)}"


@tool
def ffuf_param_scan(
    target: Annotated[str, "目标 URL，必须包含 FUZZ 占位符作为参数名，例如 'http://192.168.1.1/page?FUZZ=value'"],
    wordlist: Annotated[str, "参数名字典。可选: seclists_params, 或自定义完整路径"] = "seclists_params",
    cookie: Annotated[Optional[str], "Session Cookie"] = None,
    threads: Annotated[int, "并发线程数"] = 40,
) -> str:
    """
    使用 ffuf 进行参数名模糊测试。
    通过在 URL 中设置 FUZZ 占位符作为参数名，快速探测后端对未知参数的响应差异。
    适用于发现隐藏的输入点、调试参数、未公开 API 等。
    """
    logger.info(f"[TOOL] ffuf 参数扫描: {target}")
    
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    
    if "FUZZ" not in target:
        target = target + "?FUZZ=test"
    
    wordlist_path = _resolve_wordlist(wordlist)
    
    # 参数扫描：使用 -fw (filter by words) 过滤一致响应
    cmd = _build_ffuf_base_cmd(target, wordlist_path, mode="param", cookie=cookie, threads=threads)
    # 添加行数/行数过滤，减少误报
    cmd.extend(["-fw", "1"])  # 过滤只有 1 个词的响应（通常是默认页面）
    
    logger.debug(f"[EXEC] Command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=360)
        logger.debug(f"[RAW OUTPUT] {result.stdout[:1000]}")
        
        if result.returncode != 0 and not result.stdout:
            return f"ffuf 执行异常: {result.stderr[:300]}"
        
        return ffuf_param_parser(result.stdout)
    
    except subprocess.TimeoutExpired:
        return "ffuf 参数扫描超时，请考虑减少字典大小。"
    except FileNotFoundError:
        return "ffuf 未安装。请执行: apt install ffuf"
    except Exception as e:
        return f"ffuf 执行异常: {str(e)}"


@tool
def ffuf_post_scan(
    target: Annotated[str, "目标 URL，例如 'http://192.168.1.1/api/endpoint'"],
    post_data: Annotated[str, "POST 数据模板，使用 FUZZ 作为爆破点，例如 'username=admin&password=FUZZ'"],
    wordlist: Annotated[str, "字典路径。可选: dir_common, seclists_sqli, seclists_xss, 或自定义路径"] = "dir_common",
    cookie: Annotated[Optional[str], "Session Cookie"] = None,
    threads: Annotated[int, "并发线程数"] = 40,
) -> str:
    """
    使用 ffuf 对 POST 端点进行数据 Fuzz。
    适用于登录爆破、注入点探测、API 参数测试等场景。
    POST 数据中的 FUZZ 会被字典中的值逐一代换。
    """
    logger.info(f"[TOOL] ffuf POST 扫描: {target}")
    
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    
    wordlist_path = _resolve_wordlist(wordlist)
    
    cmd = _build_ffuf_base_cmd(target, wordlist_path, mode="dir", cookie=cookie, threads=threads)
    cmd.extend(["-X", "POST"])
    cmd.extend(["-d", post_data])
    # 过滤常见登录失败响应大小
    cmd.extend(["-ac"])  # 自动校准，自动过滤常见响应
    
    logger.debug(f"[EXEC] POST Data: {post_data}")
    logger.debug(f"[EXEC] Command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=360)
        logger.debug(f"[RAW OUTPUT] {result.stdout[:1000]}")
        
        if result.returncode != 0 and not result.stdout:
            return f"ffuf 执行异常: {result.stderr[:300]}"
        
        return ffuf_directory_parser(result.stdout)
    
    except subprocess.TimeoutExpired:
        return "ffuf POST 扫描超时，请考虑减少字典大小。"
    except FileNotFoundError:
        return "ffuf 未安装。请执行: apt install ffuf"
    except Exception as e:
        return f"ffuf 执行异常: {str(e)}"


@tool
def ffuf_vhost_scan(
    target: Annotated[str, "目标域名或 IP，例如 'http://192.168.1.1'"],
    wordlist: Annotated[str, "虚拟主机名字典。可选: dir_common, seclists_dirs, 或自定义路径"] = "dir_common",
    cookie: Annotated[Optional[str], "Session Cookie"] = None,
    threads: Annotated[int, "并发线程数"] = 40,
) -> str:
    """
    使用 ffuf 进行虚拟主机 (VHost) 发现。
    通过枚举 Host 头，发现目标服务器上隐藏的虚拟主机。
    对于多租户环境或共享主机非常有用。
    """
    logger.info(f"[TOOL] ffuf VHost 扫描: {target}")
    
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    
    wordlist_path = _resolve_wordlist(wordlist)
    
    cmd = _build_ffuf_base_cmd(target, wordlist_path, mode="vhost", cookie=cookie, threads=threads)
    cmd.extend(["-mode", "vhost"])
    cmd.extend(["-ac"])  # 自动校准
    
    logger.debug(f"[EXEC] Command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=360)
        logger.debug(f"[RAW OUTPUT] {result.stdout[:1000]}")
        
        if result.returncode != 0 and not result.stdout:
            return f"ffuf 执行异常: {result.stderr[:300]}"
        
        return ffuf_directory_parser(result.stdout)
    
    except subprocess.TimeoutExpired:
        return "ffuf VHost 扫描超时。"
    except FileNotFoundError:
        return "ffuf 未安装。请执行: apt install ffuf"
    except Exception as e:
        return f"ffuf 执行异常: {str(e)}"
