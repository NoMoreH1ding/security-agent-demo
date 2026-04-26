# WebLogic 指纹与利用矩阵

## 组件特征
- 名称: Oracle WebLogic Server
- 典型端口: 7001 (HTTP/T3)
- 类型: 企业级 Java 应用服务器

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2017-10271 | RCE | Critical | XMLDecoder 反序列化漏洞 |
| CVE-2018-2628 | RCE | Critical | T3 协议反序列化漏洞 |
| CVE-2018-2894 | RCE | Critical | Web Service 测试页面任意文件上传 |
| CVE-2020-14882 | 认证绕过/RCE | Critical | Console 认证绕过 + 结合 CVE-2020-14883 |
| CVE-2023-21839 | RCE | Critical | T3/IIOP 协议 JNDI 注入 |
| ssrf | SSRF | High | UDDI Explorer SSRF |
| weak_password | RCE/读取 | High | 弱口令 + 任意文件读取 |
