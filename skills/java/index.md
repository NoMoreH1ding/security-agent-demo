# Java 相关组件指纹与利用矩阵

## 组件特征
- 名称: Java Application
- 场景: 序列化处理、RMI 服务

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| rmi-codebase | RCE | Critical | RMI Registry 配置不当 (允许远程加载) |
| CVE-2017-12149 | 反序列化 RCE | Critical | JBoss AS 5.x/6.x HttpInvoker |
| CVE-2017-7504 | 反序列化 RCE | Critical | JBossMQ JMS over HTTP |
