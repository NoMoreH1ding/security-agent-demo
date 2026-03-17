from loguru import logger
from langchain.tools import tool
from core.executor import CommandExecutor
from utils.parser import NmapXMLParser

# @tool
def nmap_version_scanner(target_ip: str) -> str:
    """
    使用 Nmap 进行服务版本探测和操作系统识别。
    该工具适用于发现目标主机的开放端口及其对应的软件版本、OS版本。
    参数 target_ip: 目标的 IPv4 地址 (例如 '192.168.1.1')。
    返回: 经过脱水处理的 Markdown 格式扫描报告。
    """
    # 1. 构建标准化的安全命令
    # 我们在工具层强制使用 -oX - 以确保返回 XML，并使用固定安全参数
    command = f"nmap -sS -sV -O -Pn -n --top-ports 100 -oX - {target_ip}"
    
    logger.info(f"Agent 触发了 Nmap 扫描，目标: {target_ip}")
    
    # 2. 调用你之前的执行器
    executor = CommandExecutor()
    try:
        # 执行命令并获取 XML 字符串
        xml_output = executor.execute_raw(command) 
        
        # 3. 调用你之前的解析器进行“脱水”
        parser = NmapXMLParser()
        parsed_results = parser.parse_from_string(xml_output)
        
        # 4. 转化为精简的 Markdown 喂回给 Agent
        markdown_report = parser.to_markdown(parsed_results)
        
        return markdown_report
    except Exception as e:
        logger.error(f"工具执行过程中出现异常: {e}")
        return f"扫描失败，错误原因: {str(e)}"
