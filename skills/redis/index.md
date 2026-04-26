# Redis 指纹与利用矩阵

## 组件特征
- 名称: Redis
- 端口: 6379 (默认)
- 类型: Key-Value 数据库

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| 4-unacc | 未授权访问 | High | 无认证 + 保护模式关闭 |
| CVE-2022-0543 | RCE | Critical | Debian 包 Lua 库沙箱漏洞 |
