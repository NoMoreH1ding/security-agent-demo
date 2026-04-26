# Log4j 指纹与利用矩阵

## 组件特征
- 名称: Apache Log4j
- 类型: Java 日志框架

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2017-5645 | 反序列化 RCE | Critical | TCP Socket 传输序列化对象 |
| CVE-2021-44228 | JNDI 注入 RCE | Critical | JNDI Lookup 功能被注入恶意协议 |
