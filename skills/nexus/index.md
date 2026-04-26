# Nexus Repository Manager 3 指纹与利用矩阵

## 组件特征
- 名称: Sonatype Nexus Repository Manager 3
- 端口: 8081 (HTTP)
- 语言: Java

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2019-7238 | RCE | Critical | JEXL 表达式注入 (无需认证) |
| CVE-2020-10199 | RCE | Critical | EL 表达式注入 (需任意用户账号) |
| CVE-2020-10204 | RCE | Critical | EL 表达式注入 (需管理员权限) |
| CVE-2024-4956 | 目录遍历 | High | URL 路径遍历 |
