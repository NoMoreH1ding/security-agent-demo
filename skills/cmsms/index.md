# CMS Made Simple (CMSMS) 指纹与利用矩阵

## 组件特征
- 名称: CMS Made Simple
- 端口: 80 (HTTP)

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2019-9053 | SQL Injection | Critical | 无需认证，利用 News 模块 |
| CVE-2021-26120 | SSTI | Critical | 需 Designer 权限，Smarty 模板引擎漏洞 |
