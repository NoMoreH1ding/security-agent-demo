# GoAhead 指纹与利用矩阵

## 组件特征
- 名称: GoAhead Web Server
- 典型端口: 8080 (HTTP)
- 语言: C
- 类型: 嵌入式 Web 服务器

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2017-17562 | RCE (LD_PRELOAD) | Critical | GoAhead < 3.6.5 + 启用动态链接 CGI |
| CVE-2021-42342 | RCE (LD_PRELOAD) | Critical | (待提取) |
