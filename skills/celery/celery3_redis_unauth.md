# Celery Redis + Pickle Deserialization RCE

## 指纹特征
- 服务: Celery < 4.0
- 端口: 6379 (Redis)
- 条件: Redis 未授权访问，且 Celery 默认开启 Pickle 序列化

## PoC 指令

通过向 Redis 任务队列注入包含恶意 Pickle 序列化对象的任务：

```bash
# 安装依赖
pip install redis
# 执行利用脚本 (向 Redis 写入恶意 task)
python exploit.py {{TARGET}}
```

**Payload 特征 (Pickle)**:
- 包含 `__reduce__` 方法调用的字节码。
- 典型的利用链涉及 `os.system` 或 `subprocess.Popen`。

## Success Signal
- Celery worker 日志输出任务执行失败或异常。
- **验证文件**: `docker exec {{CONTAINER}} ls /tmp/celery_success` 存在。
