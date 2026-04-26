# Gitea 指纹与利用矩阵

## 组件特征
- 名称: Gitea
- 典型端口: 3000 (HTTP), 22 (SSH)
- 语言: Go

## 漏洞利用矩阵
| CVE/ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| 1.4-rce | 目录遍历 / RCE | Critical | Gitea 1.4.0 + Git LFS 开启 |
