# XStream 指纹与利用矩阵

## 组件特征
- 名称: XStream
- 类型: XML 序列化库

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2021-21351 | 反序列化 JNDI RCE | Critical | XML 解析 + JNDI 注入 |
| CVE-2021-29505 | 反序列化 RMI RCE | Critical | XML 解析 + RMI 远程调用 |
