# Hadoop 指纹与利用矩阵

## 组件特征
- 名称: Hadoop YARN
- 典型端口: 8088 (ResourceManager REST API)

## 漏洞利用矩阵
| ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| unauthorized-yarn | 未授权 RCE | Critical | ResourceManager REST API 未鉴权 |
