# Python 指纹与利用矩阵

## 组件特征
- 名称: Python
- 语言: Python

## 漏洞利用矩阵
| CVE/ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2024-23334 | 路径遍历 | High | aiohttp 开启 `follow_symlinks` |
| PIL-CVE-2017-8291 | RCE | Critical | 处理恶意 EPS 图片 |
| PIL-CVE-2018-16509 | RCE | Critical | 处理恶意 PostScript 图片 |
| unpickle | 反序列化 RCE | Critical | `pickle.loads` 不安全反序列化 |
