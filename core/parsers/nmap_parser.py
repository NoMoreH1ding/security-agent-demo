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
    """
    解析 -sV -sC 的详细输出，转化为 Markdown 表格并附加关键脚本结果。
    """
    if "Host is up" not in result:
        return "深度探测结束：目标不在线。"

    # 1. 提取所有服务行和紧随其后的脚本结果
    # 逻辑：先切分出端口段
    port_sections = re.split(r"^\s*(\d+/\w+)\s+open\s+", result, flags=re.MULTILINE)[1:]
    
    if not port_sections:
        return "深度探测结束：未发现详细服务信息。"

    table = "| Port/Proto | Service | Version/Info | Interesting Details |\n"
    table += "| :--- | :--- | :--- | :--- |\n"

    # re.split 之后，port_sections 的内容是 [port1, info1, port2, info2, ...]
    for i in range(0, len(port_sections), 2):
        port_proto = port_sections[i]
        info = port_sections[i+1]
        
        # 提取服务名和版本 (第一行)
        first_line = info.split('\n')[0].strip()
        parts = re.split(r"\s{2,}", first_line, maxsplit=1)  # 用多个空格分割，更准确
        service = parts[0] if parts else "Unknown"
        version = parts[1].strip() if len(parts) > 1 else "Unknown"
        
        # 提取高价值的脚本结果 (如 http-title, ssl-cert, smb-security-mode)
        scripts = []
        script_matches = re.findall(r"^\|_?\s*([\w\-]+):\s+(.*)$", info, re.MULTILINE)
        for s_name, s_val in script_matches:
            # 过滤掉一些过于冗长的、对 LLM 无意义的信息
            if s_name in ["http-title", "http-server-header", "ssl-cert", "rdp-ntlm-info", "smb-security-mode", "mysql-info"]:
                clean_val = s_val.strip()
                if len(clean_val) > 40:
                    clean_val = clean_val[:37] + "..."
                scripts.append(f"{s_name}: {clean_val}")
        
        details = ", ".join(scripts) if scripts else "-"
        table += f"| {port_proto} | {service} | {version} | {details} |\n"
            
    return f"### 深度服务与配置探测结果\n\n{table}\n\n*提示：请综合版本号与配置信息进行漏洞研判。*"
    


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
