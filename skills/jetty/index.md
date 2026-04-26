# Jetty 指纹与利用矩阵

## 组件特征
- 名称: Eclipse Jetty
- 典型端口: 8080 (HTTP)
- 类型: Java Servlet 容器

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2021-28164 | 路径遍历 | High | 使用 %2e 绕过规范化 |
| CVE-2021-28169 | 路径遍历 | High | ConcatServlet 双重解码漏洞 |
| CVE-2021-34429 | 路径遍历 | High | Unicode 编码 %u002e 绕过 |
