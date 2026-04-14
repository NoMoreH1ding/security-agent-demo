# 项目待办事项与改进路线图 🚀

本文件概述了安全代理 (AI-PTA) 的后续开发方向。项目已具备良好的模块化基础，接下来的重点是**职责边界的硬约束**、**启发式探测逻辑**以及**工具链的泛化能力**。

---

## ✅ 已完成 (Completed)
- [x] **发现-验证-报告三段式架构**：实现了 Analysis, Verification, Reporting 的解耦。
- [x] **身份认证支持 (Auth-Aware)**：Observer 自动同步 Session Cookie，支持多域隔离。
- [x] **Web 工具链全覆盖**：集成了 `Nuclei`, `Dirsearch`, `Sqlmap`, `Web Request`, `Login Analyzer`。
- [x] **Token 极致压缩**：基于 Observer 的阶段性总结与消息合法性过滤。

---

## 1. 核心逻辑与工作流优化 (Core Logic & Workflow) 🧠
**目标：** 解决节点职责塌缩问题，提升探测的精准度。

- [x] **强化节点职责硬约束**：通过 Prompt 工程 + Output Parser 强制拦截 RECON 节点的报告生成行为，确保其仅输出资产清单，将研判压力留给后续节点。
- [x] **通用工具权限重构**：将 `web_request` 从验证专用释放为全阶段通用工具（`tools/common.py`），允许 RECON 节点进行 Banner 抓取，Analysis 节点快速验证端点。
- [x] **启发式探测与模糊测试 (Fuzzing)**：
    - 基于 Kali Linux `ffuf` (Fuzz Faster U Fool) 构建专业 Fuzz 工具链。
    - `ffuf_dir_scan`：高速目录/路径发现，支持 SecLists 字典与 Cookie 认证。
    - `ffuf_param_scan`：参数名模糊测试，探测隐藏后端参数与调试入口。
    - `ffuf_post_scan`：POST 数据 Fuzz，适用于登录爆破、API 注入测试。
    - `ffuf_vhost_scan`：虚拟主机发现，枚举 Host 头发现隐藏站点。
    - 配套 `ffuf_parser.py` 解析 JSON 输出为结构化 Markdown。

## 2. 自动化与智能登录增强 🔐
**目标：** 实现完全无人值守的身份突破。

- [ ] **多会话并行管理**：完善 `sessions` 字典，支持在单次任务中维护多个独立目标的复杂认证状态。
- [ ] **登录失败自愈**：当 `web_request` 提示 Cookie 过期时，触发自动重登录逻辑。

## 3. 专业报告与证据链持久化 📝
**目标：** 将审计成果转化为标准交付物。

- [ ] **结构化报告生成工具**：将目前控制台输出的报告自动保存为 `reports/task_id/report.md`。
- [ ] **证据证据链归档**：Observer 自动截取验证成功的原始 HTTP 回显并存储为独立文件。

## 4. 安全合规与边界控制 (Scope Guard) 🛡️
**目标：** 确保 Agent 的行为严格限制在授权范围内。

- [ ] **目标范围校验增强**：修复 RECON 阶段可能出现的地址判断偏移，确保 `targets` 校验覆盖所有工具链。
- [ ] **高风险操作二次确认**：对可能导致服务中断的操作增加 HITL (人工审核) 强校验。

## 5. 可观测性与工程化 📈
**目标：** 提升系统的调试效率和成本可控性。

- [ ] **Token 成本统计**：在 `AgentState` 中记录各阶段消耗，并在报告末尾给出成本分析。
- [ ] **状态快照 Diff**：实现工具执行前后结构化状态的差异对比功能。

---
*由 Gemini CLI 更新 - 2026-04-12*
                                                                    