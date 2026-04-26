# ComfyUI 指纹与利用矩阵

## 组件特征
- 名称: ComfyUI (带有 ComfyUI-Manager 扩展)
- 端口: 8188

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2025-67303 | RCE | Critical | `/userdata/` 未授权访问配置并覆盖 |
| CVE-2026-22777 | RCE | Critical | `/api/manager/db_mode` CRLF 注入导致安全降级 |
