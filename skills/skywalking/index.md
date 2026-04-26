# Skywalking 指纹与利用矩阵

## 组件特征
- 名称: Apache Skywalking
- 典型端口: 8080 (Dashboard)
- 类型: 分布式 APM 工具

## 漏洞利用矩阵
| ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| 8.3.0-sqli | SQL 注入 | High | GraphQL metricName 参数注入 |
