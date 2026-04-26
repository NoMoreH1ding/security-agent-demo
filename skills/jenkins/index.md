# Jenkins 指纹与利用矩阵

## 组件特征
- 名称: Jenkins
- 典型端口: 8080 (HTTP)
- 类型: 自动化服务器

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2017-1000353 | RCE | Critical | CLI 协议反序列化漏洞 |
| CVE-2018-1000861 | RCE | Critical | Stapler 动态路由参数注入 |
| CVE-2024-23897 | 任意文件读取 | Critical | CLI 参数解析中的 expandAtFiles 特性 |
