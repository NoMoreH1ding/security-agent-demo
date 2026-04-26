# Apereo CAS 指纹与利用矩阵

## 组件特征
- 名称: Apereo CAS
- 端口: 8080

## 漏洞利用矩阵
| ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| 4.1-rce | 反序列化 | Critical | 登录接口 `execution` 参数 (默认 Key: changeit) |
