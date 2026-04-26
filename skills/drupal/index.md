# Drupal 指纹与利用矩阵

## 组件特征
- 名称: Drupal
- 典型端口: 80, 8080
- 类型: 内容管理系统 (CMS)

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2014-3704 | SQL 注入 | Critical | 数组参数输入过滤不当 |
| CVE-2017-6920 | 反序列化 RCE | Critical | PECL YAML 解析器注入 |
| CVE-2018-7600 | RCE (Drupalgeddon 2) | Critical | Form API 渲染注入 |
| CVE-2018-7602 | RCE (Drupalgeddon 3) | Critical | Form API 渲染注入 (需登录) |
| CVE-2019-6339 | 反序列化 RCE | Critical | Phar 反序列化 |
| CVE-2019-6341 | XSS | Medium | 文件上传名注入 |
