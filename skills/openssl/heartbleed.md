# OpenSSL 心脏滴血 (Heartbleed / CVE-2014-0160)

## 指纹特征
- 服务: 使用受影响版本 OpenSSL 的 TLS 服务
- 版本: 1.0.1 到 1.0.1f

## 利用矩阵
| 触发方式 | 路径 | 权限要求 |
| :--- | :--- | :--- |
| Heartbeat TLS 请求 | TLS 握手/会话 | 无 |

## PoC 指令

通过构造特制的 TLS 心跳包请求触发内存泄露：

```bash
# 使用 python 脚本触发
python ssltest.py {{TARGET}}
```

## Success Signal
- **信息泄露**: 从内存中读取到包含私钥、Cookie、账号密码等敏感信息的数据片段。
表达。
