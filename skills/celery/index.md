# Celery 指纹与利用矩阵

## 组件特征
- 名称: Celery
- 端口: 6379 (Redis Broker)

## 漏洞利用矩阵
| ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| celery3_redis_unauth | 反序列化 (Pickle) | Critical | Redis 未授权访问 + Celery < 4.0 |
