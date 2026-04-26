# Zabbix 指纹与利用矩阵

## 组件特征
- 名称: Zabbix
- 典型端口: 8080 (Web), 10051 (Trapper)

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2016-10134 | SQL 注入 | High | latest.php / jsrpc.php 参数过滤不当 |
| CVE-2017-2824 | RCE | Critical | Trapper 功能配置注入 |
| CVE-2020-11800 | RCE | Critical | Trapper 功能配置注入 (IPv6 绕过) |
