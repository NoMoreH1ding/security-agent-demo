# ActiveMQ 指纹与利用矩阵

## 组件特征
- 名称: Apache ActiveMQ
- 典型端口: 61616 (JMS), 8161 (Web UI)
- 常见协议: OpenWire

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2015-5254 | 反序列化 | Critical | Web UI 点击/消息消费 |
