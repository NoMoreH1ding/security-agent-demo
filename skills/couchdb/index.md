# CouchDB 指纹与利用矩阵

## 组件特征
- 名称: Apache CouchDB
- 典型端口: 5984 (API)
- 语言: Erlang

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2017-12635 | 越权 (提权) | Critical | 创建用户时 JSON 重复键绕过 |
| CVE-2017-12636 | RCE | Critical | 修改 `query_servers` 配置 (需管理权限) |
| CVE-2022-24706 | RCE | Critical | Erlang 分布式端口 (2369/2370) 认证绕过 (待提取) |
