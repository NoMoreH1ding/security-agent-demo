# Mongo Express 指纹与利用矩阵

## 组件特征
- 名称: Mongo Express
- 端口: 8081 (默认)
- 类型: MongoDB 管理 UI
- 语言: Node.js

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2019-10758 | RCE | Critical | 已认证状态 + `checkValid` 接口代码注入 |
