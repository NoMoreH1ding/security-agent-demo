import functools
import os
import re
import ipaddress
from typing import Any, Callable, List, Union, Set
from langchain_core.tools import ToolException

# 全局允许的目标列表
_ALLOWED_TARGETS: Set[str] = set()
_ALLOWED_CIDRS: List[ipaddress.IPv4Network] = []

def set_allowed_targets(targets: List[str]):
    """
    设置全局允许的目标列表。
    支持以下格式：
    - IP地址: "192.168.1.1"
    - CIDR: "192.168.1.0/24"
    - 域名: "example.com"
    - 主机:端口: "192.168.1.1:8080"
    """
    global _ALLOWED_TARGETS, _ALLOWED_CIDRS
    _ALLOWED_TARGETS.clear()
    _ALLOWED_CIDRS.clear()
    
    for target in targets:
        target = target.strip()
        if not target:
            continue
            
        # 尝试解析为 CIDR
        if '/' in target:
            try:
                network = ipaddress.IPv4Network(target, strict=False)
                _ALLOWED_CIDRS.append(network)
                continue
            except ValueError:
                pass  # 不是有效的 CIDR，继续处理
        
        # 添加到普通目标列表
        _ALLOWED_TARGETS.add(target)
    
    print(f"[Security] 已设置 {len(_ALLOWED_TARGETS)} 个允许目标，{len(_ALLOWED_CIDRS)} 个允许 CIDR 范围")

def validate_within_scope(target: str, allowed_targets: List[str] = None) -> bool:
    """检查目标是否在允许列表中"""
    if allowed_targets is not None:
        # 如果传入了自定义列表，使用它
        return _check_target_in_list(target, set(allowed_targets))
    
    # 使用全局允许列表
    return _check_target_in_global(target)

def _check_target_in_global(target: str) -> bool:
    """检查目标是否在全局允许列表中"""
    # 直接匹配
    if target in _ALLOWED_TARGETS:
        return True
    
    # 尝试从 host:port 中提取主机部分
    host_part = _extract_host(target)
    if host_part in _ALLOWED_TARGETS:
        return True
    
    # 检查 CIDR 范围
    try:
        ip = ipaddress.IPv4Address(host_part)
        for cidr in _ALLOWED_CIDRS:
            if ip in cidr:
                return True
    except (ipaddress.AddressValueError, ValueError):
        pass  # 不是有效的 IP 地址
    
    return False

def _check_target_in_list(target: str, allowed_set: Set[str]) -> bool:
    """检查目标是否在指定的允许集合中"""
    if target in allowed_set:
        return True
    
    host_part = _extract_host(target)
    if host_part in allowed_set:
        return True
    
    return False

def _extract_host(target: str) -> str:
    """从目标字符串中提取主机部分"""
    # 移除协议前缀
    if target.startswith(('http://', 'https://')):
        target = target.split('://')[1]
    
    # 提取主机部分（移除端口和路径）
    if ':' in target:
        target = target.split(':')[0]
    if '/' in target:
        target = target.split('/')[0]
    
    return target.strip()

def scope_guard(arg_name: str = "target", allowed_targets: List[str] = None):
    """
    装饰器：确保工具调用的目标在授权范围内。
    
    arg_name: 工具参数中代表目标的名称（如 'target', 'ip', 'host', 'url'）
    allowed_targets: 可选的自定义允许目标列表，如果为 None 则使用全局列表
    """
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # 尝试从 kwargs 或 args 中获取目标值
            target_value = kwargs.get(arg_name)
            if not target_value and args:
                # 假设第一个参数是目标（简单处理）
                target_value = args[0]
            
            if not target_value:
                raise ToolException(f"scope_guard: 无法从参数 '{arg_name}' 中提取目标值")
            
            # 检查目标是否在允许范围内
            if allowed_targets is not None:
                # 使用自定义列表
                if not validate_within_scope(target_value, allowed_targets):
                    raise ToolException(f"scope_guard: 目标 '{target_value}' 不在允许的范围内")
            else:
                # 使用全局列表
                if not _check_target_in_global(target_value):
                    raise ToolException(f"scope_guard: 目标 '{target_value}' 不在允许的范围内")
            
            # 验证通过，执行原函数
            return func(*args, **kwargs)
        return wrapper
    return decorator

# 初始化：从环境变量中读取允许的目标
def _init_from_env():
    """从环境变量中初始化允许的目标列表"""
    env_targets = os.getenv("ALLOWED_TARGETS", "")
    if env_targets:
        targets = [t.strip() for t in env_targets.split(',') if t.strip()]
        set_allowed_targets(targets)
        print(f"[Security] 从环境变量初始化 {len(targets)} 个允许目标")

# 自动初始化
_init_from_env()

# 示例用法：
# @scope_guard("target")
# def my_tool(target: str):
#     ...
#
# 或者在 main.py 中设置：
# from utils.security import set_allowed_targets
# set_allowed_targets(["192.168.43.0/24", "example.com"])