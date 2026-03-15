import xml.etree.ElementTree as ET
from loguru import logger

def host_survival_check_parser(result):
    """
    输入 Nmap 存活确认的原始结果, 将其结果精简后生成格式化的内容
    """
    lines = result.split("\n")
    if "Host is up" in result:
        