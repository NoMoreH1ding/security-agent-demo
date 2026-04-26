# RocketMQ 指纹与利用矩阵

## 组件特征
- 名称: Apache RocketMQ
- 典型端口: 9876 (NameServer), 10911 (Broker)
- 类型: 分布式消息队列

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2023-33246 | RCE | Critical | Broker 配置更新接口注入 |
| CVE-2023-37582 | 任意文件写入 | Critical | NameServer configStorePath 配置注入 |
