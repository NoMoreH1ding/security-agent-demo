# Jira 指纹与利用矩阵

## 组件特征
- 名称: Atlassian Jira
- 典型端口: 8080 (HTTP)
- 语言: Java

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2019-11581 | 模板注入 RCE | Critical | ContactAdministrators 接口 + Velocity 模板引擎 |
