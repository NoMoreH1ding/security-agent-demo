# Struts2 指纹与利用矩阵

## 组件特征
- 名称: Apache Struts2
- 类型: Java Web 框架

## 漏洞利用矩阵
| ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| S2-001 | RCE | Critical | OGNL 解析表单数据 |
| S2-005 | RCE | Critical | OGNL 表达式绕过过滤 |
| S2-007 | RCE | Critical | 字段类型转换注入 |
| S2-008 | RCE | Critical | devMode 调试接口注入 |
| S2-009 | RCE | Critical | 参数注入绕过 |
| S2-012 | RCE | Critical | Redirect 结果类型注入 |
| S2-013 | RCE | Critical | `<s:a>` / `<s:url>` includeParams 注入 |
| S2-015 | RCE | Critical | 通配符解析漏洞 |
| S2-016 | RCE | Critical | redirect 触发注入 |
| S2-032 | RCE | Critical | DMI 方法调用注入 |
