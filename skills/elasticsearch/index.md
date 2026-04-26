# ElasticSearch 指纹与利用矩阵

## 组件特征
- 名称: ElasticSearch
- 典型端口: 9200 (HTTP API), 9300 (Nodes Discovery)
- 语言: Java

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2014-3120 | RCE | Critical | 动态脚本开启 (MVEL) + 索引不为空 |
| CVE-2015-1427 | RCE | Critical | 动态脚本开启 (Groovy) + 沙箱绕过 |
| CVE-2015-3337 | 目录遍历 | High | 任意插件安装 |
| CVE-2015-5531 | 目录遍历 | High | 快照路径构造 |
| WooYun-2015-110216 | 任意文件写入 | High | 快照备份功能 (可配合 Tomcat 写入 Webshell) |
