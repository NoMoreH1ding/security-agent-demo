# Gogs 指纹与利用矩阵

## 组件特征
- 名称: Gogs
- 端口: 3000 (HTTP), 22 (SSH)
- 语言: Go

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2018-18925 | Session 伪造 | Critical | 文件 session provider + `..` 路径遍历 |
