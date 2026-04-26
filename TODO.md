# 项目待办事项与改进路线图 🚀

本文件概述了安全代理 (AI-PTA) 的后续开发方向。项目已具备良好的模块化基础，接下来的重点是**职责边界的硬约束**、**启发式探测逻辑**以及**工具链的泛化能力**。

---

## ✅ 已完成 (Completed)
- [x] **发现-验证-报告三段式架构**：实现了 Analysis, Verification, Reporting 的解耦。
- [x] **身份认证支持 (Auth-Aware)**：Observer 自动同步 Session Cookie，支持多域隔离。
- [x] **Web 工具链全覆盖**：集成了 `Nuclei`, `Dirsearch`, `Sqlmap`, `Web Request`, `Login Analyzer`。
- [x] **Token 极致压缩**：基于 Observer 的阶段性总结与消息合法性过滤。
- [x] **阶段跳转逻辑修复**：通过 `should_continue` 识别 `[VERIFY]` 和 `[DONE]` 标签，彻底打通了从 Analysis 到 Verification 的闭环。
- [x] **死循环深度治理**：引入“全站受限判定”与“三击止损”规则，解决了模型在 404 或重定向页面无意义徘徊的问题。
- [x] **工具物理拦截守卫**：为 `dir_search` 和 `nuclei_scan` 增加了内部状态缓存，强制防止同目标重复扫描。
- [x] **多端口漏洞精确归属**：优化 `Vulnerability` 模型，支持 `IP:Port` 级别的漏洞追踪，消除了同 IP 多端口审计时的上下文污染。

---

## 1. 核心逻辑与工作流优化 (Core Logic & Workflow) 🧠
**目标：** 解决节点职责塌缩问题，提升探测的精准度。

- [x] **强化节点职责硬约束**：通过 Prompt 工程强制拦截 RECON 节点的报告生成行为。
- [x] **通用工具权限重构**：将 `web_request` 释放为全阶段通用工具。
- [ ] **多端口横向记忆 (Cross-Port Correlation)**：允许 Agent 在审计新端口前，“复习”同 IP 下其他端口已发现的 OS、组件版本和指纹信息。
- [ ] **决策树工具降级**：当重型工具（如 nuclei）失败时，引导 Agent 自动降级到轻量级 Fuzz，而不是回退到盲目的 web_request。
- [ ] **相位反馈回路 (Phase Feedback Loop)**：验证阶段发现的新资产（子域名、隐藏接口）应回灌到侦察阶段重新入队，而非线性推进到报告。
- [ ] **文本标签协议双保险**：`[VERIFY]` / `[DONE]` 标签可能被 LLM 遗漏或幻觉产生。加入 observer 安全计数器（同一工具连续调用超过 N 次强制推进），以及 Token 预算用尽时优雅降级到报告。
- [ ] **工具执行超时机制**：网络工具（nmap、sqlmap 等）无超时限制，卡住会阻塞整个工作流。需在 LangChain 工具层统一设置 timeout + 硬超时。
- [ ] **独立操作并行化**：Recon 阶段多 IP 存活检测、多端口扫描等无依赖操作应使用线程池并行执行。
- [ ] **CLI 参数化入口**：将 `main.py` 中硬编码的 IP、端口范围、任务描述改为 `argparse` 驱动（`python main.py --target 192.168.1.0/24 --depth deep`）。

## 2. 自动化与智能登录增强 🔐
**目标：** 实现完全无人值守的身份突破。

- [ ] **共享凭证池**：将 8080 端口发现的有效 Session/Token 自动尝试同步到 8081 等其他同域端口。
- [ ] **登录失败自愈**：当提示 Cookie 过期时，触发自动重登录逻辑。
- [ ] **通用 LLM Provider 抽象**：当前硬编码 `ChatDeepSeek`。提取 `create_llm(provider, model_name)` 工厂函数，通过环境变量切换 provider（支持 OpenAI / Anthropic 兼容接口）。

## 3. 专业报告与证据链持久化 📝
**目标：** 将审计成果转化为标准交付物。

- [ ] **结构化报告生成工具**：将目前控制台输出的报告自动保存为 `reports/{task_id}/report.md`。
- [ ] **证据证据链自动归档**：在验证成功时，由 Observer 自动将原始 HTTP 回执保存为独立文件。

## 4. 安全合规与边界控制 (Scope Guard) 🛡️
**目标：** 确保 Agent 的行为严格限制在授权范围内。

- [ ] **高风险操作二次确认**：对删除、重置类操作（如 setup.php）增加 HITL (人工审核) 强校验。
- [ ] **激活作用域守卫**：`utils/security.py` 已定义完整的 `@scope_guard` 及 `validate_within_scope`，但未挂载到任何工具。优先为 `recon.py` 全部工具加装，防止 prompt injection 导致的外溢扫描。
- [ ] **命令注入防护加固**：`tools/` 层多处使用 f-string 拼接 Shell 命令，缺乏参数转义。统一改用 `shlex.quote()` 或 `subprocess` 列表传参。

## 5. 漏洞验证体系 🎯
**目标：** 建立统一的、可程序化判定的漏洞验证协议。

- [ ] **分层验证协议 (Verification Level)**：定义并实现 L0(指纹) → L1(无损逻辑) → L2(命令回显) → L3(OOB 回调) → L4(文件写入·手动) → L5(反弹 Shell·手动) 六级验证体系。在 Verification 阶段按 L1 → L2 → L3 逐级降级执行。
- [ ] **Nuclei 定位为筛选层 (L0.5)**：Nuclei 输出作为候选漏洞列表，不直接作为漏洞存在判据。需在 [VERIFY] 阶段对 Nuclei 匹配结果执行实际 PoC 验证后才能入库。
- [ ] **OOB Callback Server**：提供一个内置 HTTP listener 用于 L3 带外验证，自动捕获回调并记录唯一标识（目标+端口+CVE ID），支持超时清理。
- [ ] **PoC Success Signal 标准化**：所有 skills PoC 文件的 `## Success Signal` 节改为标注 L1/L2/L3 三级检测信号，并存放在数据模型中供 agent 自动调度。

## 6. 工具链与外部依赖 🔧
**目标：** 补齐 PoC 执行所需的外部工具，覆盖 Java/PHP 两大生态。

- [ ] **引入 ysoserial**：跨组件通用 Java 反序列化 payload 生成器，涉及 shiro、struts2、fastjson、jackson、xstream、weblogic、jboss、dubbo、activemq 等 15+ 组件。
- [ ] **引入 JNDIExploit / java-chains**：为 Log4Shell (CVE-2021-44228) 等 JNDI 注入场景提供 LDAP 服务端。
- [ ] **引入 marshalsec**：fastjson 1.2.24/1.2.47 等特定 JNDI 利用场景必需。
- [ ] **引入 PHPGGC**：为 Drupal、Magento、Joomla、Laravel 等 15 个 PHP 组件提供 PHP 反序列化 gadget。
- [ ] **组件专用攻击 JAR 管理策略**：jmet (ActiveMQ)、apereo-cas-attack、rocketmq-attack、jenkins-exp 等专用 JAR 在遇到具体组件时按需下载/编译。
- [ ] **统一工具层路径**：将外部工具路径集中管理，支持环境变量/配置文件覆盖。

## 7. Skills 知识库质量 🧠
**目标：** 确保 PoC 可被 Agent 可靠执行，减少静默失败。

- [ ] **全部 PoC 增加 L1 无损验证路径**：对现有 skills 文件逐条审查，确保每个 PoC 至少标注一个可用的验证级别，优先提供 L1 方法。
- [ ] **补全索引缺失**：struts2 index.md 补上 S2-045~S2-067；weblogic、kafka、jackson、jumpserver、openssh、rocketchat 新建 index.md。
- [ ] **修复 S2-046**：`\x00` 不应以文本形式放入 HTTP 头，改为 Python socket PoC。
- [ ] **修复 S2-059**：补充 OGNL 沙箱清除步骤（`setExcludedClasses` / `setExcludedPackageNames`）。
- [ ] **修复 CVE-2021-44228**：补充 JDK 8u191 版本限制和 LDAP 服务端搭建说明。
- [ ] **修复 CVE-2017-4971**：补充 Spring WebFlow 多步操作的完整上下文（登录→订酒店→拦请求→注入）。
- [ ] **补全 spring 组件 6 个待提取 CVE**：CVE-2018-1270、CVE-2018-1273、CVE-2022-22947、CVE-2022-22963、CVE-2022-22965(Spring4Shell)、CVE-2022-22978。

## 8. 可观测性与工程化 📈
**目标：** 提升系统的调试效率和成本可控性。

- [ ] **Token 成本熔断器**：在 `AgentState` 中实时累加消耗，单个任务超过阈值时强制收网产出报告。
- [ ] **状态快照 Diff**：仅向 LLM 发送工具执行后发生变化的状态增量，大幅节省 Input Token。
- [ ] **Observer 策略模式重构**：`observer_node` 当前在一个函数内集中处理 nmap / nuclei / WAF / sqlmap / ffuf 全部解析。应拆为策略模式，每个 parser 注册 `can_handle(tool_name)` + `extract(state, tool_output)`，observer 遍历匹配，新增工具无需修改 observer 主体。

---
## 9. 工程质量与测试 🧪
**目标：** 建立可回归验证的质量基线，减少手动调试成本。

- [ ] **核心解析器单元测试**：`core/parsers/` 下的 nmap / nuclei / ffuf / sqlmap 解析器是纯函数，最易测试且出错影响最大，优先建立 fixture 驱动的单元测试。
- [ ] **路由决策回归测试**：`should_continue` 函数控制整个状态机流向，需覆盖 `[VERIFY]` / `[DONE]` / `[REPORT]` 标签识别、工具调用循环、及边界情况（空消息、畸形输出）。
- [ ] **命令注入安全测试**：为 `tools/` 层添加参数注入用例（如 targets 中包含 `; cat /etc/passwd`），验证转义后无命令执行。

---
*最后更新：2026-04-26 (补充验证层级协议、外部工具链和 Skills 知识库质量清单)*
