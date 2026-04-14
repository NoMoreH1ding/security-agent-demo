"""
Apache Shiro 框架检测与 RememberMe 密钥爆破工具

功能：
1. 通过响应头和 Cookie 特征识别 Shiro 框架
2. 检测 RememberMe Cookie 并使用已知密钥进行解密验证
3. 返回可用于漏洞利用的密钥信息
"""

import base64
import subprocess
from typing import Annotated, Optional
from langchain_core.tools import tool
from loguru import logger
import requests
import re


# 常见 Shiro RememberMe 默认密钥 (AES CBC, 128-bit)
SHIRO_DEFAULT_KEYS = [
    # 官方默认密钥
    "kPH+bIxk5D2deZiIxcaaaA==",
    # 常见二次开发密钥
    "Z3VucwAAAAAAAAAAAAAAAA==",
    "r0e3c1VHdkE=",
    "fCq+/xW488hMTCD+cmJ3aQ==",
    "1QWLxg+NYmxraMoxAXu/Iw==",
    "ZUdsaGJuSmxibVI2ZHc9PQ==",
    "L7RioUULEFhRyxM7a2R/Yg==",
    "rSLwPtV/A0Z2PrcZnnJh+Q==",
    "a2VlcE9uR29pbmdBbmREbw==",
    "WcfHGU25gNnTxTlmJMeSpw==",
    "ZnJlc2h6Y24xMjM0NTY3OA==",
    "5AvVhmLTUSJ4TA3KtxgAvg==",
    "6ZmI6I2j5Y+R5aSn5ZOlAA==",
    "cmVtZW1iZXJNZQ==",
    "wGiHplamyXlVB11UXWol8g==",
    "Y1JYOmhvYXN0bGF5MTIzNDU=",
]


def _check_shiro_headers(response: requests.Response) -> dict:
    """检查 HTTP 响应中的 Shiro 特征"""
    features = {
        "is_shiro": False,
        "rememberme_cookie": False,
        "rememberme_delete": False,
        "shiro_header": False,
        "details": []
    }

    # 检查 Set-Cookie 中的 rememberMe
    cookies = response.headers.get("Set-Cookie", "")
    if "rememberMe=" in cookies.lower() or "rememberme=" in cookies.lower():
        features["rememberme_cookie"] = True
        features["is_shiro"] = True
        # 提取 rememberMe 值
        match = re.search(r'(?:rememberMe|rememberme)=([^;]+)', cookies, re.IGNORECASE)
        if match:
            features["details"].append(f"发现 rememberMe Cookie: {match.group(1)[:50]}...")

    # 检查 deleteMe (Shiro 无效 Cookie 时的标记)
    if "rememberMe=deleteMe" in cookies.lower():
        features["rememberme_delete"] = True
        features["is_shiro"] = True
        features["details"].append("发现 rememberMe=deleteMe (无效 Cookie 标记)")

    # 检查特定 Header
    for header_name in response.headers:
        if "shiro" in header_name.lower():
            features["shiro_header"] = True
            features["is_shiro"] = True
            features["details"].append(f"发现 Shiro Header: {header_name}")

    return features


def _test_shiro_key(url: str, cookie_value: str, key_b64: str) -> bool:
    """
    尝试使用给定密钥解密 rememberMe Cookie
    原理：Shiro RememberMe 使用 AES-CBC 加密，如果解密后 padding 正确则密钥匹配
    """
    try:
        # 使用 Python 快速测试（避免每次调起 subprocess）
        from Crypto.Cipher import AES
        import base64
        
        key = base64.b64decode(key_b64)
        # 尝试解密
        data = base64.b64decode(cookie_value)
        if len(data) < 16:
            return False
        
        iv = data[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(data[16:])
        
        # 检查 PKCS5/PKCS7 padding
        pad_len = decrypted[-1]
        if 1 <= pad_len <= 16 and all(b == pad_len for b in decrypted[-pad_len:]):
            return True
        
        return False
    except ImportError:
        # 如果没有 pycryptodome，使用简化的长度/特征检查
        return False
    except Exception:
        return False


@tool
def shiro_detect(
    target: Annotated[str, "目标 URL，例如 'http://192.168.1.1:8081'"],
    test_keys: Annotated[bool, "是否尝试爆破 RememberMe 密钥"] = True,
) -> str:
    """
    检测目标是否使用 Apache Shiro 框架，并尝试爆破 RememberMe 加密密钥。
    Shiro RememberMe 反序列化漏洞 (CVE-2016-4437 等) 可导致 RCE。
    """
    logger.info(f"[TOOL] Shiro 检测: {target}")
    
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    
    try:
        # 发送请求获取响应
        session = requests.Session()
        response = session.get(target, timeout=10, verify=False, allow_redirects=True)
        
        features = _check_shiro_headers(response)
        
        # 也尝试带有一个伪造的 rememberMe Cookie 触发 deleteMe 响应
        session2 = requests.Session()
        fake_cookie = "rememberMe=invalid_test_value"
        response2 = session2.get(target, timeout=10, verify=False, allow_redirects=True,
                                 cookies={"rememberMe": "invalid_test_value"})
        features2 = _check_shiro_headers(response2)
        
        # 合并特征
        for key in features:
            if isinstance(features[key], bool):
                features[key] = features[key] or features2.get(key, False)
        if features2.get("details"):
            features["details"].extend(features2["details"])
        
        # 如果不确定是 Shiro，检查页面特征
        if not features["is_shiro"]:
            body = response.text.lower()
            if any(kw in body for kw in ["shiro", "org.apache.shiro", "shirofilter"]):
                features["is_shiro"] = True
                features["details"].append("页面内容中发现 Shiro 特征")
        
        result_lines = []
        
        if features["is_shiro"]:
            result_lines.append("### ✅ 检测到 Apache Shiro 框架\n")
            for detail in features["details"]:
                result_lines.append(f"- {detail}")
            
            # 提取有效的 rememberMe Cookie 值用于密钥测试
            rememberme_value = None
            for r in [response, response2]:
                cookies_str = r.headers.get("Set-Cookie", "")
                match = re.search(r'(?:rememberMe|rememberme)=([^;]+)', cookies_str, re.IGNORECASE)
                if match and "deleteMe" not in match.group(1):
                    rememberme_value = match.group(1)
                    break
            
            # 爆破密钥
            if test_keys and rememberme_value:
                result_lines.append(f"\n### 密钥爆破测试 (共 {len(SHIRO_DEFAULT_KEYS)} 个候选密钥)")
                matched_keys = []
                for key_b64 in SHIRO_DEFAULT_KEYS:
                    try:
                        from Crypto.Cipher import AES
                        key = base64.b64decode(key_b64)
                        data = base64.b64decode(rememberme_value)
                        if len(data) < 16:
                            continue
                        iv = data[:16]
                        cipher = AES.new(key, AES.MODE_CBC, iv)
                        decrypted = cipher.decrypt(data[16:])
                        pad_len = decrypted[-1]
                        if 1 <= pad_len <= 16 and all(b == pad_len for b in decrypted[-pad_len:]):
                            matched_keys.append(key_b64)
                    except:
                        continue
                
                if matched_keys:
                    result_lines.append(f"\n⚠️ **发现匹配的密钥**: `{matched_keys[0]}`")
                    result_lines.append(f"漏洞风险：Shiro RememberMe 反序列化 (RCE)")
                    result_lines.append(f"建议：立即修改 rememberMe 密钥，禁用反序列化功能")
                else:
                    result_lines.append(f"\n未发现匹配的默认密钥（已测试 {len(SHIRO_DEFAULT_KEYS)} 个）")
                    result_lines.append("建议：使用专用工具（如 shiro-exploit）进行深度爆破")
            
            elif test_keys and not rememberme_value:
                result_lines.append("\n未获取到有效的 rememberMe Cookie，无法进行密钥爆破")
        else:
            result_lines.append("### ❌ 未检测到 Apache Shiro 特征")
            result_lines.append(f"响应状态码: {response.status_code}")
            result_lines.append(f"Set-Cookie: {response.headers.get('Set-Cookie', 'None')[:100]}")
        
        return "\n".join(result_lines)
    
    except requests.exceptions.Timeout:
        return "Shiro 检测超时。"
    except Exception as e:
        return f"Shiro 检测异常: {str(e)}"
