# Scrapy/Scrapyd 指纹与利用矩阵

## 组件特征
- 名称: Scrapy/Scrapyd
- 端口: 6800 (JSON API)
- 类型: 爬虫框架/任务部署平台

## 漏洞利用矩阵
| ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| scrapyd-unacc | RCE | Critical | API 未鉴权上传部署恶意 Egg 包 |
