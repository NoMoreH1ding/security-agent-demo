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

# 请求缓存，减少重复请求
_REQUEST_CACHE = {}


@tool
def web_request(
    url: Annotated[str, "请求 URL"],
    method: Annotated[str, "HTTP 方法: GET, POST, PUT, HEAD"] = "GET",
    headers: Annotated[Optional[Dict[str, str]], "自定义头"] = None,
    cookie: Annotated[Optional[str], "Session Cookie"] = None,
    data: Annotated[Optional[str], "POST 数据"] = None,
    timeout: Annotated[int, "超时"] = 20
) -> str:
    """
    发送轻量的 HTTP 请求并返回结果。
    全阶段通用工具，适用于 Banner 抓取、服务探活、快速验证等场景。
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
            'timeout': timeout  # timeout可能影响超时行为，但响应内容通常相同
        }
    else:
        # POST/PUT等请求，包含data但不包含headers和cookie
        key_data = {
            'method': method.upper(),
            'url': url,
            'data': data,
            'timeout': timeout
        }
    
    # 序列化时处理不可JSON化的对象
    key_str = json.dumps(key_data, sort_keys=True, default=str)
    cache_key = hashlib.md5(key_str.encode()).hexdigest()
    
    # 检查缓存
    if cache_key in _REQUEST_CACHE:
        logger.info(f"[TOOL] 缓存命中: {method} {url}")
        return _REQUEST_CACHE[cache_key] + "\n[缓存命中 - 此结果来自之前的请求]"
    
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
        
        # 存入缓存
        _REQUEST_CACHE[cache_key] = result
        return result
    except Exception as e:
        error_msg = f"请求失败: {str(e)}"
        # 错误也缓存，避免重复尝试失败请求
        _REQUEST_CACHE[cache_key] = error_msg
        return error_msg
