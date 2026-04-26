# Apache Dubbo 指纹与利用矩阵

## 组件特征
- 名称: Apache Dubbo
- 典型端口: 20880 (Dubbo), 8080 (HTTP), 2181 (Zookeeper)
- 语言: Java

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2019-17564 | 反序列化 | Critical | HTTP 协议开启 + 已知服务接口 |
