# Joomla 指纹与利用矩阵

## 组件特征
- 名称: Joomla
- 典型端口: 8080 (HTTP)
- 语言: PHP

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2015-8562 | RCE | Critical | 伪造 User-Agent 反序列化 (需特定 PHP 环境) |
| CVE-2017-8917 | SQL 注入 | High | com_fields 组件注入 |
| CVE-2023-23752 | 未授权访问 | Medium | public=true 参数绕过鉴权 |
