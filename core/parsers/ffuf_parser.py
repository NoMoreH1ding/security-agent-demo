"""
FFUF 输出解析器 - 解析 ffuf JSON 格式输出为结构化 Markdown 摘要
"""

import json
from loguru import logger


def ffuf_directory_parser(raw_output: str) -> str:
    """
    解析 ffuf 目录/路径发现的 JSON 输出
    """
    if not raw_output or not raw_output.strip():
        return "ffuf 扫描完成，未发现任何响应。"

    try:
        findings = []
        # ffuf 现在的输出可能是完整的 JSON (包含 "results" 键)，也可能是 JSONL
        try:
            full_data = json.loads(raw_output)
            if isinstance(full_data, dict) and "results" in full_data:
                raw_results = full_data["results"]
            else:
                raw_results = [full_data] if isinstance(full_data, dict) else []
        except json.JSONDecodeError:
            # 尝试按行解析 JSONL
            raw_results = []
            for line in raw_output.strip().split('\n'):
                if line.strip().startswith('{'):
                    try:
                        raw_results.append(json.loads(line))
                    except: continue

        for data in raw_results:
            status = data.get("status", 0)
            if status == 404: continue
            findings.append({
                "status": status,
                "length": data.get("length", 0),
                "url": data.get("url", ""),
                "redirect": data.get("redirectlocation", ""),
            })

        if not findings:
            return "ffuf 扫描完成，在自动校准(-ac)模式下未发现显著路径。"

        # 去重：同一 URL 只保留一个结果
        unique_findings = {}
        for f in findings:
            unique_findings[f["url"]] = f
        findings = list(unique_findings.values())

        # 按状态码排序，并只取前 20 个最有价值的结果
        findings.sort(key=lambda x: (x["status"] == 200, -x["length"]), reverse=True)
        display_findings = findings[:20]

        # 统计
        stats = {}
        for f in findings:
            s = f["status"]
            stats[s] = stats.get(s, 0) + 1

        table = "| 状态码 | 路径 | 长度 | 重定向 |\n"
        table += "| :--- | :--- | :--- | :--- |\n"

        for f in display_findings:
            url = f["url"]
            for prefix in ["http://", "https://"]:
                if url.startswith(prefix):
                    parts = url[len(prefix):].split('/', 1)
                    url = '/' + parts[1] if len(parts) > 1 else '/'
                    break
            redirect = f.get("redirect", "") or "-"
            table += f"| {f['status']} | `{url}` | {f['length']}B | {redirect} |\n"

        summary = "### ffuf 目录/路径发现摘要\n\n"
        summary += f"共发现 {len(findings)} 个有效路径 (显示前 {len(display_findings)} 个)\n"
        summary += f"状态码分布: " + ", ".join([f"{k}: {v}" for k, v in sorted(stats.items())]) + "\n\n"
        summary += table
        return summary

    except Exception as e:
        logger.error(f"解析 ffuf 目录输出失败: {e}")
        return f"解析 ffuf 输出出错: {str(e)}\n原始输出片段: {raw_output[:200]}"


def ffuf_param_parser(raw_output: str) -> str:
    """
    解析 ffuf 参数名发现的 JSONL 输出
    
    Args:
        raw_output: ffuf 的 JSONL 格式输出
    
    Returns:
        结构化的参数发现摘要
    """
    if not raw_output or not raw_output.strip():
        return "ffuf 参数扫描完成，未发现差异响应。"

    try:
        findings = []
        for line in raw_output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                status = data.get("status", 0)
                length = data.get("length", 0)
                # 参数名从 URL 中提取
                url = data.get("url", "")
                findings.append({
                    "status": status,
                    "length": length,
                    "url": url,
                })
            except json.JSONDecodeError:
                continue

        if not findings:
            return "ffuf 参数扫描完成，所有参数名的响应一致，未发现可疑差异。"

        # 按长度差异排序（差异越大越可疑）
        if findings:
            lengths = [f["length"] for f in findings]
            avg_len = sum(lengths) / len(lengths)
            anomalies = [f for f in findings if abs(f["length"] - avg_len) > avg_len * 0.3]
        else:
            anomalies = []

        table = "| 状态码 | URL | 长度 | 备注 |\n"
        table += "| :--- | :--- | :--- | :--- |\n"

        for f in findings[:30]:
            is_anomaly = any(a["url"] == f["url"] for a in anomalies)
            note = "⚠️ 异常响应" if is_anomaly else "正常"
            table += f"| {f['status']} | `{f['url']}` | {f['length']}B | {note} |\n"

        summary = "### ffuf 参数 Fuzz 扫描摘要\n\n"
        summary += f"共测试发现 {len(findings)} 个差异响应"
        if anomalies:
            summary += f"，其中 {len(anomalies)} 个存在异常响应\n\n"
        else:
            summary += "，未发现显著的异常差异\n\n"
        summary += table

        return summary

    except Exception as e:
        logger.error(f"解析 ffuf 参数输出失败: {e}")
        return f"解析 ffuf 输出出错: {str(e)}\n原始输出片段: {raw_output[:200]}"
