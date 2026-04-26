# Confluence 指纹与利用矩阵

## 组件特征
- 名称: Atlassian Confluence
- 端口: 8090 (默认端口)

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2019-3396 | Path Traversal / SSTI | Critical | Widget 宏预览 `_template` 参数 |
| CVE-2021-26084 | OGNL Injection | Critical | `queryString` 参数注入 (Pre-Auth) |
| CVE-2022-26134 | OGNL Injection | Critical | URL 路径注入 (Pre-Auth) |
| CVE-2023-22515 | Broken Access Control | Critical | `/setup/setup-administrator` 提权 |
| CVE-2023-22527 | SSTI | Critical | 模板引擎 RCE (待提取) |
