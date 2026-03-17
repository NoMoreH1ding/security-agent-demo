import pkgutil
import importlib
from langchain_core.tools import BaseTool
from loguru import logger


def get_all_tools():
    tools = []
    # 自动遍历当前 tools 目录下的所有 .py 文件
    for loader, module_name, is_pkg in pkgutil.walk_packages(__path__):
        # 动态导入模块
        module = importlib.import_module(f".{module_name}", package=__package__)
        # 遍历模块中的所有对象
        for name in dir(module):
            obj = getattr(module, name)
            # 如果是 LangChain 的 Tool 类型，则加入列表
            if isinstance(obj, BaseTool):
                tools.append(obj)
    return tools


ALL_TOOLS = get_all_tools()
logger.info(f"[TOOL LOAD] {len(ALL_TOOLS)} tools loaded.")
