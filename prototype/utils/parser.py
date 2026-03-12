import xml.etree.ElementTree as ET
from loguru import logger

class NmapXMLParser:
    @staticmethod
    def parse_from_string(xml_content):
        """
        解析字符串形式的XML内容，适用于Nmap扫描结果
        返回精简后的内容
        :param xml_content: XML字符串
        """
        try:
            root = ET.fromstring(xml_content)
            results = []
            
            # 1.遍历主机，寻找ipv4地址
            for host in root.findall('host'):
                ip = host.find("address[@addrtype='ipv4']").get('addr')
                status = host.find('status').get('state')
            
            # 2.提取os信息
            os_name = "Unknown"
            os_match = host.find('os/osmatch')
            if os_match is not None:
                os_name = os_match.get('name')
                
            # 3.提取端口和服务信息
            ports_data = []
            for port in host.findall('ports/port'):
                port_id = port.get('portid')
                state = port.find('state').get('state')
                    
                service = port.find('service')
                service_name = service.get('name') if service is not None else "unknown"
                product = service.get('product') if service is not None else ""
                version = service.get('version') if service is not None else ""
                    
                # 组合成易读的描述
                service_detail = f"{service_name} ({product} {version})".strip()
                    
                ports_data.append({
                    "port": port_id,
                    "state": state,
                    "service": service_detail
                })
                
            results.append({
                "ip": ip,
                "status": status,
                "os": os_name,
                "ports": ports_data
            })
            logger.info(f"精简扫描结果如下：\n{results}")
            return results
        except Exception as e:
            logger.error(f"XML 解析失败: {e}")
            return None
        
    @staticmethod
    def to_markdown(parsed_results):
        """
        将解析结果转换为精简的 Markdown，节省 Token
        """
        if not parsed_results:
            logger.error("未发现开放端口或解析失败。")
            return "未发现开放端口或解析失败。"
            
        md = ""
        for host in parsed_results:
            md += f"### Host: {host['ip']} ({host['os']})\n"
            md += "| Port | Service/Product |\n"
            md += "| :--- | :--- |\n"
            for p in host['ports']:
                md += f"| {p['port']} | {p['service']} |\n"
            md += "\n"
        logger.info(f"转换后的markdown格式信息如下：\n{md}")
        return md