# uWSGI 未授权 RCE (unacc)

## 指纹特征
- 服务: uWSGI
- 端口: 8000 (uwsgi 协议)
- 场景: uwsgi 端口直接暴露且未设置限制

## 利用矩阵
| 触发方式 | 依赖条件 | 权限要求 |
| :--- | :--- | :--- |
| UWSGI 协议数据包注入 | uwsgi 端口 (如 8000) | 无 |

## PoC 指令

通过构造 uwsgi 数据包并设置 `UWSGI_FILE` 触发命令执行：

```bash
# 使用 poc.py 发送恶意 uwsgi 包
python poc.py -u {{TARGET_IP}}:8000 -c "touch /tmp/success"
```

## Success Signal
- **物理验证**: 检查系统是否执行了预期命令 (如 `touch /tmp/success`)。
- **验证回显**: 命令执行成功。
