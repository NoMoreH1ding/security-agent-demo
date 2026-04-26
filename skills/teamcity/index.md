# TeamCity 指纹与利用矩阵

## 组件特征
- 名称: JetBrains TeamCity
- 典型端口: 8111
- 类型: CI/CD 平台

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2023-42793 | 认证绕过/RCE | Critical | RPC 接口绕过 + 调试模式启用 RCE |
| CVE-2024-27198 | 认证绕过 | Critical | `BaseController` 路径参数绕过鉴权 |
