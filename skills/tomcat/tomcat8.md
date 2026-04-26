# Tomcat 弱口令 RCE (tomcat8)

## 指纹特征
- 服务: Apache Tomcat
- 端口: 8080 (Manager App)
- 条件: 使用弱口令 (如 `tomcat:tomcat`) 登录后台

## 利用矩阵
| 触发方式 | 路径 | 权限要求 |
| :--- | :--- | :--- |
| WAR 包上传 | `/manager/html` | 管理员 (Weak Password) |

## PoC 指令

1. 登录 `http://{{TARGET}}:8080/manager/html`。
2. 上传包含 JSP Webshell 的 WAR 包。
3. 访问 `/{{APP_NAME}}/shell.jsp`。

## Success Signal
- **状态验证**: Webshell 成功上传并在服务器执行命令。
