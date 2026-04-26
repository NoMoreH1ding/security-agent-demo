# YApi NoSQL 注入与 RCE (mongodb-inj)

## 指纹特征
- 服务: YApi < v1.12.0
- 端口: 3000
- 场景: NoSQL 注入获取项目 Token，进而利用 Mock 功能执行任意命令

## 利用矩阵
| 触发方式 | 路径 | 权限要求 |
| :--- | :--- | :--- |
| NoSQL 注入 (Token 获取) | `/api/user/list` | 无 |
| Mock 脚本 RCE | `/api/plugin/runscript` | 需 Token |

## PoC 指令

通过 NoSQL 注入获取项目 Token，利用 Mock 功能执行 Node.js 代码：

**1. 自动化探测与利用**
使用自动化脚本提取 token 并触发 RCE：

```bash
python poc.py --debug one4all -u http://{{TARGET}}:3000/
```

## Success Signal
- **状态验证**: 成功获取目标项目的 API Token。
- **物理验证**: 执行预期的命令 (如 `id`, `uname`) 并获得回显。
| 关键点 | 说明 |
| :--- | :--- |
| `Mock Script` | 允许执行任意 JS 代码 |
