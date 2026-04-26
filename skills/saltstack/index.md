# SaltStack 指纹与利用矩阵

## 组件特征
- 名称: SaltStack
- 端口: 4505/4506, 8000
- 类型: 配置管理工具

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2020-11651 | 认证绕过 RCE | Critical | ClearFuncs 函数未授权调用 |
| CVE-2020-11652 | 任意文件读写 | High | Wheel 模块路径遍历 |
| CVE-2020-16846 | RCE | Critical | Netapi SSH 模块参数注入 |
