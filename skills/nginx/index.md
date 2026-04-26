# Nginx 指纹与利用矩阵

## 组件特征
- 名称: Nginx
- 端口: 80, 8080

## 漏洞利用矩阵
| ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2013-4547 | RCE | High | URI 结尾畸形字符匹配 bypass |
| CVE-2017-7529 | 目录遍历/读取 | High | Range 头整数溢出 (利用缓存文件) |
| insecure-configuration | 各种 | Medium/High | (配置审计相关) |
| nginx_parsing_vulnerability | 解析漏洞 | Critical | 伪造路径后缀 `/foo.png/.php` |
