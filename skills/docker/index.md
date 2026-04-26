# Docker 指纹与利用矩阵

## 组件特征
- 名称: Docker
- 端口: 2375, 2376

## 漏洞利用矩阵
| ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| unauthorized-rce | 未授权访问 / RCE | Critical | Docker Remote API 暴露且无认证 |
