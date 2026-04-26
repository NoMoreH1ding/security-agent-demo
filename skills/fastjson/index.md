# Fastjson 指纹与利用矩阵

## 组件特征
- 名称: Fastjson
- 语言: Java
- 类型: JSON Parser

## 漏洞利用矩阵
| CVE/ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| 1.2.24-rce | 反序列化 RCE | Critical | `autoType` 开启 + 脆弱 Gadget (如 JdbcRowSetImpl) |
| 1.2.47-rce | 反序列化 RCE | Critical | `java.lang.Class` 缓存绕过白名单 |
