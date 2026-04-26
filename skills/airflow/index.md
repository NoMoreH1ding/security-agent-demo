# Airflow 指纹与利用矩阵

## 组件特征
- 名称: Apache Airflow
- 端口: 8080 (Web UI), 6379 (Redis)

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2020-11978 | RCE | Critical | DAG 触发界面输入 |
| CVE-2020-11981 | RCE | Critical | Redis Broker 权限 |
| CVE-2020-17526 | 认证绕过 | Critical | Session 密钥破解 |
