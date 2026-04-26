# Grafana 指纹与利用矩阵

## 组件特征
- 名称: Grafana
- 典型端口: 3000 (HTTP)
- 语言: Go (Backend) + TypeScript (Frontend)

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2021-43798 | 目录遍历 | High | Grafana 8.x + 任意插件已安装 |
| CVE-2024-9264 | RCE | Critical | (待提取) |
| admin-ssrf | SSRF | Medium | (待提取) |
