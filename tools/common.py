"""
通用 Web 请求工具 - 全阶段可用

与 verification.py 中的 web_request 不同，此版本更轻量，适用于：
- RECON 阶段：Banner 抓取、服务探活
- Analysis 阶段：快速验证可疑端点
"""

import requests
from typing import Annotated, Optional, Dict
from langchain_core.tools import tool
from loguru import logger


@tool
def web_request(
    url: Annotated[str, "请求 URL"],
    method: Annotated[str, "HTTP 方法: GET, POST, PUT, HEAD"] = "GET",
    headers: Annotated[Optional[Dict[str, str]], "自定义头"] = None,
    cookie: Annotated[Optional[str], "Session Cookie"] = None,
    data: Annotated[Optional[str], "POST 数据"] = None,
    timeout: Annotated[int, "超时"] = 10
) -> str:
    """
    发送轻量的 HTTP 请求并返回结果。
    全阶段通用工具，适用于 Banner 抓取、服务探活、快速验证等场景。
    """
    logger.info(f"[TOOL] 通用 HTTP {method}: {url}")
    try:
        final_headers = headers or {}
        if cookie and "Cookie" not in final_headers:
            final_headers["Cookie"] = cookie

        response = requests.request(
            method=method.upper(), url=url, headers=final_headers, data=data,
            timeout=timeout, verify=False, allow_redirects=True
        )

        set_cookie = response.headers.get("Set-Cookie", "None")
        body_preview = response.text[:800]
        result = f"Status: {response.status_code}\n"
        result += f"Set-Cookie: {set_cookie}\n"
        result += f"Content-Type: {response.headers.get('Content-Type', 'Unknown')}\n"
        result += f"Body Preview:\n{body_preview}"
        return result
    except Exception as e:
        return f"请求失败: {str(e)}"
