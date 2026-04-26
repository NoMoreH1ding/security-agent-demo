# HugeGraph 指纹与利用矩阵

## 组件特征
- 名称: Apache HugeGraph
- 典型端口: 8080 (REST API)
- 类型: 图数据库

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2024-27348 | RCE | Critical | Gremlin API 查询注入 + 线程名沙箱绕过 |
| CVE-2024-43441 | 认证绕过 | Critical | JWT Secret 硬编码 (默认值) |
