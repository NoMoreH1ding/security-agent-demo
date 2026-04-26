# PHPUnit 指纹与利用矩阵

## 组件特征
- 名称: PHPUnit
- 类型: PHP 测试框架

## 漏洞利用矩阵
| CVE ID | 类型 | 严重性 | 触发条件 |
| :--- | :--- | :--- | :--- |
| CVE-2017-9841 | RCE | Critical | `eval-stdin.php` 接口暴露 + 可执行 POST 数据 |
