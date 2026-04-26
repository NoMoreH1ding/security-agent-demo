# Mojarra 指纹与利用矩阵

## 组件特征
- 名称: Mojarra (JavaServer Faces)
- 类型: Java Web 框架

## 漏洞利用矩阵
| CVE/ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| jsf-viewstate-deserialization | 反序列化 RCE | Critical | ViewState 未加密 + 可控反序列化点 |
