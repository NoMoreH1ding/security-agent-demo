# Superset 指纹与利用矩阵

## 组件特征
- 名称: Apache Superset
- 端口: 8088
- 类型: 数据探索与可视化平台

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2023-27524 | 认证绕过 | Critical | 默认 Secret Key 导致 Session 伪造 |
| CVE-2023-37941 | 反序列化 RCE | Critical | Pickle 存储数据反序列化 |
