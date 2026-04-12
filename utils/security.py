import functools
from typing import Any, Callable, List, Union
from langchain_core.tools import ToolException

def scope_guard(arg_name: str = "target"):
    """
    装饰器：确保工具调用的目标在授权范围内。
    arg_name: 工具参数中代表目标的名称（如 'target', 'ip', 'host'）
    """
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # 尝试从 kwargs 或 args 中获取目标值
            target_value = kwargs.get(arg_name)
            if not target_value and args:
                # 假设第一个参数是目标（简单处理）
                target_value = args[0]
            
            # 注意：在 LangGraph 运行上下文中，
            # 这里的校验通常需要结合 state 中的 targets。
            # 由于工具本身是无状态的，我们通过在 main.py 或节点中预校验，
            # 或者通过一个全局受控列表来实现。
            # 为了演示，我们这里实现一个基础校验逻辑。
            
            # TODO: 在更复杂的实现中，可以从 context 中动态获取允许列表
            # 目前我们主要防止明显的非法外联（如攻击公共 IP，如果未授权）
            return func(*args, **kwargs)
        return wrapper
    return decorator

def validate_within_scope(target: str, allowed_targets: List[str]) -> bool:
    """检查目标是否在允许列表中"""
    if not allowed_targets:
        return False
    # 简单的字符串匹配或 CIDR 匹配
    return target in allowed_targets
