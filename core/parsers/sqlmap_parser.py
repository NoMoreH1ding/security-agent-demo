import re
from loguru import logger

def sqlmap_parser(raw_output: str) -> str:
    """
    将 sqlmap 的冗长输出提炼为 Markdown 摘要。
    """
    if "is not injectable" in raw_output:
        return "Sqlmap 未发现目标存在 SQL 注入漏洞。"
    
    # 提取关键结论
    # 查找: it looks like the back-end DBMS is ...
    dbms_match = re.search(r"back-end DBMS is ([\w\s]+)", raw_output, re.I)
    dbms = dbms_match.group(1).strip() if dbms_match else "Unknown"
    
    # 提取注入点详情
    # 查找: Parameter: ...
    #      Type: ...
    #      Title: ...
    params = re.findall(r"Parameter: (.*?)\n\s+Type: (.*?)\n\s+Title: (.*?)\n", raw_output, re.S)
    
    if not params:
        if "all tested parameters appear to be not injectable" in raw_output:
            return "测试完成，未发现可注入参数。"
        return f"Sqlmap 扫描完成，但在输出中未匹配到标准漏洞特征。请查阅原始日志。"

    summary = f"### SQL 注入验证摘要\n\n"
    summary += f"**后端数据库**: {dbms}\n\n"
    summary += "| 参数 | 注入类型 | 注入标题 |\n| :--- | :--- | :--- |\n"
    
    for p_name, p_type, p_title in params:
        summary += f"| `{p_name}` | {p_type.strip()} | {p_title.strip()} |\n"
        
    return summary
