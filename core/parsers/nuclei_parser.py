import json
from loguru import logger

def nuclei_scan_parser(raw_output: str) -> str:
    """
    将 Nuclei 的原始 JSON/JSONL 输出解析为精简的 Markdown 摘要。
    支持两种格式：
    1. JSONL (每行一个 JSON 对象) — Nuclei 默认输出
    2. JSON 数组 (已被工具包装为列表)
    """
    if not raw_output or not raw_output.strip():
        return "Nuclei 扫描完成，未发现匹配的漏洞。"

    try:
        findings = []
        
        # 尝试解析 JSONL (每行一个 JSON)
        for line in raw_output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if isinstance(data, list):
                    findings.extend(data)
                elif isinstance(data, dict):
                    findings.append(data)
            except json.JSONDecodeError:
                continue
        
        # 如果 JSONL 解析失败，尝试解析为 JSON 数组
        if not findings:
            try:
                data = json.loads(raw_output)
                if isinstance(data, list):
                    findings = data
                elif isinstance(data, dict):
                    findings = [data]
            except json.JSONDecodeError:
                pass

        if not findings:
            return "Nuclei 扫描完成，未发现匹配的高风险漏洞。"

        # 统计严重程度
        stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        table = "| ID | 漏洞名称 | 严重等级 | 匹配位置 |\n"
        table += "| :--- | :--- | :--- | :--- |\n"

        for f in findings:
            # Nuclei JSON 结构: { "template-id": "xxx", "info": { "name": "xxx", "severity": "xxx" }, "matched-at": "xxx" }
            vuln_id = f.get("template-id", f.get("template_id", "Unknown"))
            info = f.get("info", {})
            name = info.get("name", f.get("name", "Unknown"))
            severity = info.get("severity", f.get("severity", "info")).lower()
            matched = f.get("matched-at", f.get("matched", ""))
            
            stats[severity] = stats.get(severity, 0) + 1

            # 缩短匹配位置
            if len(matched) > 60:
                matched = matched[:30] + "..." + matched[-27:]

            table += f"| {vuln_id} | {name} | {severity.upper()} | `{matched}` |\n"

        summary = f"### Nuclei 漏洞扫描摘要\n\n发现漏洞总数: {len(findings)} "
        summary += f"(严重: {stats['critical']}, 高危: {stats['high']}, 中危: {stats['medium']})\n\n"
        summary += table

        return summary

    except Exception as e:
        logger.error(f"解析 Nuclei 输出失败: {e}")
        return f"解析漏洞数据出错，原始输出片段: {raw_output[:200]}..."
