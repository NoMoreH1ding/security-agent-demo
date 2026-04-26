# GhostScript 指纹与利用矩阵

## 组件特征
- 名称: GhostScript
- 类型: PostScript & PDF 解释器
- 场景: 图像处理后端 (ImageMagick, GraphicsMagick, Python PIL/Pillow 等)

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2018-16509 | RCE (Sandbox Bypass) | Critical | GhostScript <= 9.23 + 处理恶意 PS 脚本 |
| CVE-2018-19475 | RCE (Sandbox Bypass) | Critical | (待提取) |
| CVE-2019-6116 | RCE (Sandbox Bypass) | Critical | GhostScript <= 9.26 + 不完整修复绕过 |
