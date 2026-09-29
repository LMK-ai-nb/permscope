# permscope：2026 MoonBit 9 月黑客松项目申报书

- 参赛人：李明坤
- GitHub：LMK-ai-nb
- 联系邮箱：1416377553@qq.com
- 项目仓库：https://github.com/LMK-ai-nb/permscope
- 赛道：社区维护项目（8 月黑客松已有初版，不作为 9 月新项目申报）
- 许可证：Apache-2.0

## 项目用途与现有基础

`permscope` 是 MoonBit 浏览器能力边界审计库，面向需要审查 Web 响应头的开发者、网关维护者和 CI 流程。8 月版本已公开实现 Permissions-Policy 解析、旧版 Feature-Policy 迁移、能力契约、访问矩阵，以及若干安全响应头的辅助检查，并发布 `LMK-ai-nb/permscope@0.1.1`。库只分析调用者提供的响应头文本，不发起网络请求。

## 本期维护内容

9 月重点是把能力契约从“检查手工构造的 Policy”推进到“检查路由实际收集到的响应头”。新增响应样本与契约的联合审计，识别现代策略头缺失、策略格式异常和文档 origin 不一致；增加多路由清单核对，查出漏采样、没有契约和重复名称；修复严格契约可能放过未声明能力、缺失指令可能被误判为满足边界的问题。针对 `curl -I -L` 多次重定向输出，只审计最终响应，避免前一跳的安全头造成误判。配套增加可运行示例、边界与错误路径测试，并完善 README、设计、来源与发布记录。

## 技术路线与交付

核心逻辑继续由 MoonBit 实现，保持纯函数 API：解析响应头、比对能力需求、返回结构化发现和稳定文本报告。运行 `moon run examples/route_contract` 可看到 `/video` 路由的契约审计；`moon check --deny-warn`、`moon build`、`moon test --deny-warn`、`moon fmt --check`、`moon info` 和 GitHub Actions 用于复现质量检查。提交、CI、发布状态以公开仓库和 Mooncakes 页面为准。

## 独立价值、边界与维护

同类 MoonBit Web 框架可设置通用安全头，本项目聚焦“某条路由声明的浏览器能力与观察到的 Permissions-Policy 是否一致”，不是框架中间件，也不冒充浏览器最终授权判断。后续可扩展真实站点采样适配器与跨路由报告；第三方代码或素材若引入将逐项登记原项目、链接、许可证与使用范围。本期改动有 AI 辅助，见 `docs/PROVENANCE_AND_AI.md`。
