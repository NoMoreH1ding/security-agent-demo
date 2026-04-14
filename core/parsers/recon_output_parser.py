"""
RECON 节点输出解析器 - 强制职责边界约束

功能：
1. 拦截 RECON 节点的报告生成行为（如漏洞研判、修复建议等）
2. 提取标准化的资产清单（IP、端口、服务、WAF 状态）
3. 确保 RECON 节点仅输出发现，不输出分析结论
"""

import re
from typing import Dict, List, Any
from loguru import logger


# 禁止 RECON 节点输出的关键词模式（命中即视为越界）
REPORT_INDICATORS = [
    r"(修复建议|Remediation|修复方案|加固建议)",
    r"(风险评估|Risk Assessment|风险等级|危险程度|Severity)",
    r"(攻击路径|Attack Path|利用链|漏洞链)",
    r"(CVSS|评分|严重性评级|优先级)",
    r"(审计结论|Audit Conclusion|总结报告|最终报告)",
    r"(漏洞详情|Vulnerability Detail|漏洞描述|存在漏洞|发现漏洞|疑似漏洞)",
    r"(PoC|Proof of Concept|利用代码|payload|Payload)",
    r"(鉴权绕过|认证突破|突破口)",
    r"(建议采取|下一步建议|为了安全)",
]

REPORT_PATTERN = re.compile("|".join(REPORT_INDICATORS), re.IGNORECASE)


def validate_recon_output(content: str) -> Dict[str, Any]:
    """
    验证 RECON 节点输出是否越界（尝试生成报告或进行分析）
    
    Returns:
        {"valid": bool, "violations": List[str], "sanitized_content": str}
    """
    violations = []
    
    # 检查是否包含报告生成特征
    if REPORT_PATTERN.search(content):
        matches = REPORT_PATTERN.findall(content)
        # findall 返回的是 tuple（因为 pattern 有 group），展平为字符串
        flat_matches = set()
        for m in matches:
            if isinstance(m, tuple):
                flat_matches.update(x for x in m if x)
            else:
                flat_matches.add(m)
        violations.append(f"检测到报告生成行为，命中模式: {', '.join(flat_matches)}")
    
    # 检查是否包含过长的分析（超过 500 字的纯文本总结视为越界）
    # 提取非表格/非结构的纯文本段落
    paragraphs = [p.strip() for p in content.split('\n\n') if p.strip()]
    long_paragraphs = [p for p in paragraphs if len(p) > 500 and '|' not in p and '---' not in p]
    if long_paragraphs:
        violations.append(f"检测到冗长分析段落 ({len(long_paragraphs)} 个)，RECON 节点应仅输出资产清单")
    
    is_valid = len(violations) == 0
    
    if not is_valid:
        logger.warning(f"[RECON Parser] 职责越界检测: {violations}")
        # 对内容进行净化：移除越界段落
        sanitized = _sanitize_recon_content(content)
    else:
        sanitized = content
    
    return {
        "valid": is_valid,
        "violations": violations,
        "sanitized_content": sanitized
    }


def _sanitize_recon_content(content: str) -> str:
    """
    净化 RECON 输出：移除分析性段落，保留资产清单
    """
    # 移除包含报告特征的段落
    paragraphs = content.split('\n\n')
    kept = []
    
    for para in paragraphs:
        if REPORT_PATTERN.search(para):
            logger.debug(f"[RECON Parser] 移除报告段落: {para[:50]}...")
            continue
        if len(para.strip()) > 500 and '|' not in para and '---' not in para:
            # 过长段落截断为摘要
            kept.append(para[:200] + "\n... (已截断，RECON 节点不应输出详细分析)")
            logger.debug(f"[RECON Parser] 截断冗长分析段落")
            continue
        kept.append(para)
    
    return '\n\n'.join(kept)


def extract_asset_summary(content: str) -> Dict[str, Any]:
    """
    从 RECON 输出中提取结构化资产信息
    
    Returns:
        {
            "targets_alive": List[str],
            "open_ports": List[Dict],
            "waf_status": Dict[str, str],
        }
    """
    result = {
        "targets_alive": [],
        "open_ports": [],
        "waf_status": {},
    }
    
    # 提取存活目标
    alive_matches = re.findall(r"目标\s+([\d.]+)\s+在线", content)
    result["targets_alive"].extend(alive_matches)
    
    # 提取开放端口
    port_matches = re.findall(r"(\d+)/(\w+)\s+\((.*?)\)", content)
    for port, proto, service in port_matches:
        result["open_ports"].append({
            "port": int(port),
            "protocol": proto,
            "service": service
        })
    
    # 提取 WAF 状态
    waf_matches = re.findall(r"WAF\s*(?:保护|检测)[：:]\s*(.+?)(?:\n|$)", content)
    if waf_matches:
        result["waf_status"]["detected"] = waf_matches[0].strip()
    elif "未检测到 WAF" in content or "No WAF detected" in content:
        result["waf_status"]["detected"] = "None"
    
    return result
