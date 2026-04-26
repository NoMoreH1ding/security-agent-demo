# Kibana 指纹与利用矩阵

## 组件特征
- 名称: Kibana
- 典型端口: 5601 (HTTP)
- 语言: Node.js (Backend)

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2018-17246 | 目录遍历 | High | Console 插件输入过滤不当 |
| CVE-2019-7609 | 原型链污染 RCE | Critical | Timelion 组件注入 |
| CVE-2020-7012 | 原型链污染 RCE | Critical | Upgrade Assistant telemetry 机制 |
