# PHP 指纹与利用矩阵

## 组件特征
- 名称: PHP (SAPI: CGI/FPM)
- 语言: PHP

## 漏洞利用矩阵
| CVE/ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| 8.1-backdoor | RCE | Critical | User-Agentt 头部注入 |
| CVE-2012-1823 | RCE | Critical | CGI 参数注入 (`-d`, `-s`) |
| CVE-2018-19518 | RCE | Critical | imap_open 注入 ProxyCommand |
| CVE-2019-11043 | RCE | Critical | PHP-FPM 缓冲溢出 |
| CVE-2024-2961 | RCE | Critical | iconv 缓冲区溢出 |
