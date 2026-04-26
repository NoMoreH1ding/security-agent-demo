import requests
import re
from typing import Annotated, Optional, Dict
from langchain_core.tools import tool
from loguru import logger

# 请求缓存，减少重复请求
_REQUEST_CACHE = {}

@tool
def web_login_analyzer(
    url: Annotated[str, "目标 URL"],
    target: Annotated[Optional[str], "目标 URL (别名)"] = None,
) -> str:
    """
    使用 BeautifulSoup 深度分析目标页面是否包含登录表单。
    注意：此工具仅分析登录表单，仅记录登录入口点信息，不进行任何登录尝试（包括弱口令测试）。
    """
    # 兼容性处理：如果提供了 target 参数，使用 target 作为 url
    if target:
        url = target
    logger.info(f"[TOOL] 执行登录需求分析: {url}")
    from bs4 import BeautifulSoup
    try:
        response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        soup = BeautifulSoup(response.text, 'lxml')
        
        auth_needed = False
        findings = []
        
        if response.status_code in [401, 403]:
            auth_needed = True
            findings.append(f"HTTP {response.status_code} 禁止访问")
            
        if "login" in response.url.lower():
            auth_needed = True
            findings.append(f"重定向至: {response.url}")
            
        # 查找所有 password 输入框
        pw_inputs = soup.find_all("input", {"type": "password"})
        if pw_inputs:
            auth_needed = True
            form = pw_inputs[0].find_parent("form")
            action = form.get("action") if form else "未知"
            findings.append(f"发现登录表单 (Action: {action})")
            
        if not auth_needed:
            return "分析完成：页面似乎不需要身份认证。"
            
        # 添加登录表单记录指令（禁止任何登录尝试）
        findings.insert(0, "🚫 **严格禁止登录尝试**: 检测到登录表单，禁止进行任何登录尝试（包括弱口令测试）。仅记录登录入口点信息，优先测试其他无需认证的漏洞模块。")
        findings.append("📋 建议：记录登录入口点，优先测试其他无需认证的漏洞模块（如目录遍历、信息泄露、参数注入等）。")
        return "### 身份认证分析结论\n\n" + "\n".join([f"- {f}" for f in findings])
        
    except Exception as e:
        return f"分析异常: {str(e)}"

@tool
def sqlmap_verify(
    url: Annotated[str, "确认可注入的 URL"],
    cookie: Annotated[Optional[str], "Session Cookie"] = None,
) -> str:
    """
    对确认存在注入的目标进行良性利用验证。支持身份认证。
    """
    logger.info(f"[TOOL] 执行 SQLmap 验证: {url}")
    cmd = ["sqlmap", "-u", url, "--batch", "--banner", "--current-user", "--random-agent", "--threads", "5"]
    if cookie:
        cmd.extend(["--cookie", cookie])
    
    import subprocess
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        from core.parsers.sqlmap_parser import sqlmap_parser
        summary = sqlmap_parser(result.stdout)
        banner_match = re.search(r"banner:\s+'(.*?)'", result.stdout, re.I)
        if banner_match:
            summary += f"\n**数据库 Banner**: `{banner_match.group(1)}`"
        return summary
    except Exception as e:
        return f"SQLmap 验证异常: {str(e)}"

@tool
def web_request(
    url: Annotated[str, "请求 URL"],
    method: Annotated[str, "HTTP 方法: GET, POST, PUT"] = "GET",
    headers: Annotated[Optional[Dict[str, str]], "自定义头"] = None,
    cookie: Annotated[Optional[str], "Session Cookie"] = None,
    data: Annotated[Optional[str], "POST 数据"] = None,
    timeout: Annotated[int, "超时"] = 10,
    allow_redirects: Annotated[bool, "是否自动跟随重定向"] = True,
) -> str:
    """
    发送精准的 HTTP 请求并返回结果。支持带 Cookie 访问及登录操作。
    支持自动跟随重定向以捕获完整 Cookie 链。
    """
    # 生成缓存键 - 智能缓存策略
    import hashlib
    import json
    # 对于GET请求，忽略cookie和headers（相同URL应该返回相同内容）
    # 对于POST请求，包含data但不包含headers和cookie（避免session差异）
    if method.upper() == "GET":
        key_data = {
            'method': method.upper(),
            'url': url,
            'allow_redirects': allow_redirects
        }
    else:
        # POST/PUT等请求，包含data但不包含headers和cookie
        key_data = {
            'method': method.upper(),
            'url': url,
            'data': data,
            'allow_redirects': allow_redirects
        }
    
    # 序列化时处理不可JSON化的对象
    key_str = json.dumps(key_data, sort_keys=True, default=str)
    cache_key = hashlib.md5(key_str.encode()).hexdigest()
    
    # 检查缓存
    if cache_key in _REQUEST_CACHE:
        logger.info(f"[TOOL] 缓存命中: {method} {url}")
        return _REQUEST_CACHE[cache_key] + "\n[缓存命中 - 此结果来自之前的请求]"
    
    logger.info(f"[TOOL] 执行验证请求: {method} {url}")
    import requests
    try:
        final_headers = headers or {}
        if cookie and "Cookie" not in final_headers:
            final_headers["Cookie"] = cookie

        session = requests.Session()
        response = session.request(
            method=method.upper(), url=url, headers=final_headers, data=data,
            timeout=timeout, verify=False, allow_redirects=allow_redirects
        )

        # 收集所有 Set-Cookie（包括中间重定向）
        set_cookies = []
        for hist in response.history:
            sc = hist.headers.get("Set-Cookie", "")
            if sc:
                set_cookies.append(sc)
        final_sc = response.headers.get("Set-Cookie", "")
        if final_sc:
            set_cookies.append(final_sc)

        body_preview = response.text[:1000]
        result = f"Status: {response.status_code}\n"
        result += f"Final URL: {response.url}\n"
        result += f"Set-Cookie: {'; '.join(set_cookies) if set_cookies else 'None'}\n"
        result += f"Location: {response.headers.get('Location', 'None')}\n"
        if response.history:
            result += f"Redirect Chain: {' -> '.join([r.url for r in response.history])}\n"
        result += f"Body Summary:\n{body_preview}"
        
        # 存入缓存
        _REQUEST_CACHE[cache_key] = result
        return result
    except Exception as e:
        error_msg = f"请求失败: {str(e)}"
        # 错误也缓存，避免重复尝试失败请求
        _REQUEST_CACHE[cache_key] = error_msg
        return error_msg
