import json
from loguru import logger

def nuclei_scan_parser(raw_output: str) -> str:
    """
    将 Nuclei 的原始 JSON 输出解析为精简的 Markdown 摘要。
    """
    if not raw_output or "Nuclei 扫描完成" in raw_output or "未发现" in raw_output:
        return raw_output

    try:
        # 尝试解析 JSON (因为 tools/web.py 已经将其转为了 JSON 字符串)
        findings = json.loads(raw_output)
        if not findings:
            return "Nuclei 扫描完成，未发现匹配的高风险漏洞。"

        # 统计严重程度
        stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        table = "| ID | 漏洞名称 | 严重等级 | 匹配位置 |\n"
        table += "| :--- | :--- | :--- | :--- |\n"
        
        for f in findings:
            severity = f.get("severity", "info").lower()
            stats[severity] = stats.get(severity, 0) + 1
            
            # 缩短匹配位置，只保留核心 URL/路径
            matched = f.get("matched", "")
            if len(matched) > 60:
                matched = matched[:30] + "..." + matched[-27:]
                
            table += f"| {f.get('template_id')} | {f.get('name')} | {severity.upper()} | `{matched}` |\n"

        summary = f"### Nuclei 漏洞扫描摘要\n\n发现漏洞总数: {len(findings)} "
        summary += f"(严重: {stats['critical']}, 高危: {stats['high']}, 中危: {stats['medium']})\n\n"
        summary += table
        
        return summary

    except Exception as e:
        logger.error(f"解析 Nuclei 输出失败: {e}")
        return f"解析漏洞数据出错，原始输出片段: {raw_output[:200]}..."
