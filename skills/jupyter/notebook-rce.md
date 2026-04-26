# Jupyter Notebook RCE (notebook-rce)

## 指纹特征
- 服务: Jupyter Notebook
- 端口: 8888 (默认)

## 利用矩阵
| 触发方式 | 路径 | 权限要求 |
| :--- | :--- | :--- |
| 未授权访问终端 | `/tree`, `/notebooks` | 无 (若未设置密码) |

## PoC 指令

**1. 创建新终端**
访问管理界面，点击 "New" -> "Terminal" 创建一个系统终端。

**2. 执行命令**
在终端窗口中输入任意命令：
```bash
id
ls /
```

## Success Signal
- **状态验证**: 在 Web 终端中能够成功执行系统命令并获得回显。
| 关键接口 | 说明 |
| :--- | :--- |
| `/terminals` | 用于创建和管理 Web 终端接口 |
