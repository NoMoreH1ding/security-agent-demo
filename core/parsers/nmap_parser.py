from unittest import result
import xml.etree.ElementTree as ET
import re
from loguru import logger

def quick_scan_parser(result):
    """
    将 Nmap 快速扫描的结果脱水并提取关键信息
    """
    if "Host is up" not in result:
        logger.warning(f"目标不在线!检查目标是否存活!")
        return "目标似乎已下线, 也许等待后重新确认存活情况?"
    else:
        # 1. 寻找开放端口行，格式通常为: 80/tcp open http
        open_ports = re.findall(r"(\d+)/(\w+)\s+open\s+([\w-]+)", result)
        
        if not open_ports:
            # 检查是否全是 filtered
            if "filtered" in result:
                return "扫描结束：未发现开放端口，所有探测端口均显示为 'filtered' (可能被防火墙拦截)。"
            return "扫描结束：未发现任何开放端口。"

        # 2. 格式化为 AI 易读的列表
        result_list = [f"{p[0]}/{p[1]} ({p[2]})" for p in open_ports]
        output = "发现开放端口: " + ", ".join(result_list)
        
        # 3. 记录日志，但不把这个噪音传给 AI (节省 Token)
        if "filtered" in result:
            logger.debug("Parser 注意到目标存在被过滤的端口。")
            
        return output

def service_scan_parser(result):
    """解析 -sV 的详细输出，转化为 Markdown 表格"""
    # 1. 提取端口、状态、服务、版本
    # 匹配示例: 80/tcp open http Apache httpd 2.4.41 ((Ubuntu))
    # 改进后的正则：
    # 1. (\d+/\w+) 匹配端口/协议
    # 2. \s+open\s+ 匹配状态
    # 3. ([\w-]+) 匹配服务名
    # 4. \s*(.*)$ 匹配剩余的所有内容（直到行尾），使用 re.MULTILINE 确保 $ 匹配每行结尾
    pattern = r"^(\d+/\w+)\s+open\s+([\w-]+)\s*(.*)$"
    matches = re.findall(pattern, result, re.MULTILINE)
        
    if not matches:
        return "深度扫描未发现详细的服务版本信息。"

    table = "| Port/Proto | Service | Version/Info |\n| :--- | :--- | :--- |\n"
        
    for m in matches:
        port_proto = m[0]
        service = m[1]
        # 清洗 version 部分：
        # 如果为空，则显示 'Unknown'
        # 如果包含换行符或多余空格，进行截断处理
        version = m[2].strip() if m[2].strip() else "Unknown"
            
        # 关键修复：防止版本信息里包含下一行的端口（针对 53 端口那样的异常）
        if "/" in version and "tcp" in version: # 简单启发式判断，防止误吞下一行
            version = "Unknown (Check Raw Log)"

        table += f"| {port_proto} | {service} | {version} |\n"
            
    return f"### 服务版本探测结果\n\n{table}\n\n*提示：请根据版本号检索是否存在已知漏洞。*"
    


# result = 
"""
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-17 09:23 -0400
Nmap scan report for 192.168.43.1
Host is up (0.00068s latency).

Bug in http-generator: no string output.
PORT     STATE SERVICE       VERSION
53/tcp   open  tcpwrapped
80/tcp   open  http          Apache httpd 2.4.39 ((Win64) OpenSSL/1.1.1b mod_fcgid/2.3.9a mod_log_rotate/1.02)
|_http-server-header: Apache/2.4.39 (Win64) OpenSSL/1.1.1b mod_fcgid/2.3.9a mod_log_rotate/1.02
|_http-title: \xe7\xab\x99\xe7\x82\xb9\xe5\x88\x9b\xe5\xbb\xba\xe6\x88\x90\xe5\x8a\x9f-phpstudy for windows
| http-methods: 
|_  Potentially risky methods: TRACE
81/tcp   open  http          Apache httpd 2.4.39 ((Win64) OpenSSL/1.1.1b mod_fcgid/2.3.9a mod_log_rotate/1.02)
|_http-server-header: Apache/2.4.39 (Win64) OpenSSL/1.1.1b mod_fcgid/2.3.9a mod_log_rotate/1.02
|_http-title: \xe6\x88\x91\xe7\x9a\x84\xe7\xbd\x91\xe7\xab\x99-\xe9\x94\x99\xe8\xaf\xaf
88/tcp   open  http          Apache httpd 2.4.39 ((Win64) OpenSSL/1.1.1b mod_fcgid/2.3.9a mod_log_rotate/1.02)
| http-git: 
|   192.168.43.1:88/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Remotes:
|_      https://github.com/binwind8/tncode.git
|_http-title: TnCode
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.39 (Win64) OpenSSL/1.1.1b mod_fcgid/2.3.9a mod_log_rotate/1.02
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3306/tcp open  mysql         MySQL (unauthorized)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=LAPTOP-AL8TSP9D
| Not valid before: 2026-02-09T01:28:13
|_Not valid after:  2026-08-11T01:28:13
| rdp-ntlm-info: 
|   Target_Name: LAPTOP-AL8TSP9D
|   NetBIOS_Domain_Name: LAPTOP-AL8TSP9D
|   NetBIOS_Computer_Name: LAPTOP-AL8TSP9D
|   DNS_Domain_Name: LAPTOP-AL8TSP9D
|   DNS_Computer_Name: LAPTOP-AL8TSP9D
|   Product_Version: 10.0.22621
|_  System_Time: 2026-03-17T13:23:07+00:00
|_ssl-date: TLS randomness does not represent time
5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Service Unavailable
|_http-server-header: Microsoft-HTTPAPI/2.0
MAC Address: 00:50:56:C0:00:08 (VMware)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-03-17T13:23:06
|_  start_date: N/A
|_clock-skew: mean: -7s, deviation: 0s, median: -8s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: LAPTOP-AL8TSP9D, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:c0:00:08 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 54.41 seconds
"""
