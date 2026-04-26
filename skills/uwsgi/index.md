# uWSGI 指纹与利用矩阵

## 组件特征
- 名称: uWSGI
- 类型: Web 应用服务器

## 漏洞利用矩阵
| CVE/ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2018-7490 | 目录遍历 | High | PHP 插件 `DOCUMENT_ROOT` 校验漏洞 |
| unacc | RCE | Critical | uwsgi 端口暴露且配置不当 |
