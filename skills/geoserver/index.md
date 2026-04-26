# GeoServer 指纹与利用矩阵

## 组件特征
- 名称: GeoServer
- 典型端口: 8080 (HTTP)
- 语言: Java (Jetty/Tomcat)
- 类型: 地理空间数据服务器

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2021-40822 | SSRF | High | (待提取) |
| CVE-2022-24816 | RCE | Critical | (待提取) |
| CVE-2023-25157 | SQL Injection | High | OGC Filter 注入 (需连接数据库) |
| CVE-2024-36401 | RCE | Critical | XPath 表达式注入 (GetPropertyValue 等接口) |
