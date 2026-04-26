# Flask 指纹与利用矩阵

## 组件特征
- 名称: Flask
- 模板引擎: Jinja2
- 端口: 8000 (典型)

## 漏洞利用矩阵
| CVE/ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| ssti | SSTI RCE | Critical | 用户输入直接传入 `render_template_string` |
