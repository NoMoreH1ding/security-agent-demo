# MeterSphere 指纹与利用矩阵

## 组件特征
- 名称: MeterSphere
- 类型: 测试平台
- 语言: Java

## 漏洞利用矩阵
| CVE/ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2021-45788 | SQL 注入 | High | 已认证用户 + 订单列表接口参数 |
| plugin-rce | RCE | Critical | 插件 API 未鉴权上传与调用 |
