# Apache Shiro 指纹与利用矩阵

## 组件特征
- 名称: Apache Shiro
- 端口: 8080 (典型)
- 类型: Java 安全框架

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2010-3863 | 认证绕过 | High | URI 规范化不足 (`/./`) |
| CVE-2016-4437 | 反序列化 RCE | Critical | rememberMe 加密 Cookie 处理漏洞 |
| CVE-2020-1957 | 认证绕过 | High | 特殊路径匹配绕过 (`..;`) |
