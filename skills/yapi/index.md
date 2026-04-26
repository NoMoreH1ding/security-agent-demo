# YApi 指纹与利用矩阵

## 组件特征
- 名称: YApi
- 端口: 3000
- 类型: API 管理平台
- 语言: Node.js

## 漏洞利用矩阵
| ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| mongodb-inj | NoSQL 注入/RCE | Critical | Token 枚举绕过鉴权 + Mock 接口代码执行 |
| unacc | RCE | Critical | 注册账户 + Mock 功能 JS 代码执行 |
