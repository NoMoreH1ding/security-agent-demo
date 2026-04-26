# ThinkPHP 指纹与利用矩阵

## 组件特征
- 名称: ThinkPHP
- 类型: PHP Web 框架

## 漏洞利用矩阵
| ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| 2-rce | RCE | Critical | preg_replace /e 修正符路由注入 |
| 5-rce | RCE | Critical | 控制器方法名不当解析 |
| 5.0.23-rce | RCE | Critical | Request 类构造方法伪造 |
| in-sqlinjection | SQL 注入 | High | 数组参数未过滤 |
| lang-rce | 路径遍历/RCE | Critical | 多语言配置开启 + pearcmd 写入 |
