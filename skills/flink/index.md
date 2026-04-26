# Apache Flink 指纹与利用矩阵

## 组件特征
- 名称: Apache Flink
- 端口: 8081 (Web UI)
- 类型: 分布式流处理框架

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2020-17518 | 任意文件写入 (路径遍历) | High | `/jars/upload` 接口未过滤文件名 |
| CVE-2020-17519 | 任意文件读取 (路径遍历) | High | `/jobmanager/logs` 接口未过滤路径 |
| CVE-2019-11358 | RCE | Critical | (待确认是否包含在 Vulhub) |
