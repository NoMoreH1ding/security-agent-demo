# Java RMI Codebase RCE

## 指纹特征
- 服务: Java RMI Registry
- 端口: 1099
- 条件: 目标服务端运行 RMI 注册表且允许远程加载 codebase

## 利用矩阵
| 触发方式 | 路径 | 权限要求 |
| :--- | :--- | :--- |
| RMI 绑定/查找触发 | `rmi://{{TARGET}}:1099/` | 无 |

## PoC 指令

通过配置 `java.rmi.server.codebase` 加载恶意 Java 类。

**1. 部署恶意类**
在 HTTP 服务器上部署 `{{REMOTE_CLASS}}.class`。

**2. 启动恶意 RMI 注册表/对象绑定**
使用工具（如 `ysoserial` 或自定义 RMI 绑定脚本）诱导目标服务器从指定的 codebase 加载并实例化类。

## Success Signal
- **状态验证**: 命令执行成功（例如：目标服务器加载恶意类并执行静态初始化块逻辑）。
| 关键参数 | 说明 |
| :--- | :--- |
| `codebase` | 恶意 Java 类所在的 URL 地址 |
