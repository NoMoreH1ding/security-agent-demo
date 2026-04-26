# Tomcat 指纹与利用矩阵

## 组件特征
- 名称: Apache Tomcat
- 端口: 8080 (HTTP), 8009 (AJP)
- 类型: Java Servlet 容器

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2017-12615 | RCE | High | readonly 设置不当 + PUT 写入 |
| CVE-2020-1938 | 任意文件读取 | Critical | AJP 协议幽灵猫漏洞 |
| CVE-2025-24813 | RCE | Critical | Session 持久化反序列化 |
| tomcat8 | RCE | High | 管理后台弱口令上传 WAR 包 |
