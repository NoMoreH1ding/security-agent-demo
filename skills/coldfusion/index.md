# Adobe ColdFusion 指纹与利用矩阵

## 组件特征
- 名称: Adobe ColdFusion
- 端口: 8500 (Web)

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2010-2861 | Directory Traversal | High | `/CFIDE/administrator/enter.cfm` 处 locale 参数 |
| CVE-2017-3066 | AMF Deserialization | Critical | `/flex2gateway/amf` 处处理恶意 AMF 数据 |
