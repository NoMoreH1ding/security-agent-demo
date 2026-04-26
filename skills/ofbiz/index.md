# OFBiz 指纹与利用矩阵

## 组件特征
- 名称: Apache OFBiz
- 端口: 8443 (HTTPS)
- 类型: 企业资源规划 (ERP) 系统

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2020-9496 | RCE | Critical | XMLRPC 接口反序列化漏洞 |
| CVE-2023-49070 | 认证绕过 + RCE | Critical | XMLRPC 接口鉴权绕过 |
| CVE-2023-51467 | RCE | Critical | ProgramExport 接口 Groovy 注入 |
| CVE-2024-38856 | RCE | Critical | ProgramExport 接口 Groovy 注入绕过 |
| CVE-2024-45195 | 任意文件写入 | Critical | DataFile 接口路径遍历 |
| CVE-2024-45507 | SSRF / RCE | Critical | StatsSinceStart SSRF 注入 |
