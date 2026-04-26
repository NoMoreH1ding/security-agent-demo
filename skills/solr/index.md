# Apache Solr 指纹与利用矩阵

## 组件特征
- 名称: Apache Solr
- 端口: 8983
- 类型: 搜索引擎

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2017-12629 | RCE | Critical | RunExecutableListener 监听器配置注入 |
| CVE-2017-12629 | XXE | High | XML 解析器实体注入 |
| CVE-2019-0193 | RCE | Critical | DataImportHandler 配置注入 |
| CVE-2019-17558 | RCE | Critical | Velocity 模板注入 |
| Remote-Streaming-Fileread | 任意文件读取/SSRF | High | RemoteStreaming 接口过滤缺失 |
