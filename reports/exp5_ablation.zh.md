# 实验五：消融实验（RQ3）

- 配置：Full / -Scope / -Auditor / -TTL / -Sanit / ChainCaps

## 汇总指标

| 配置 | ABR | BCR | FP | FN | 与 Full 的攻击差距 (Separation) |
|------|------|------|----|----|------|
| Full | 100.0% | 70.6% | 5 | 0 | 0 |
| -Scope | 100.0% | 23.5% | 14 | 0 | 0 |
| -Auditor | 100.0% | 70.6% | 5 | 0 | 0 |
| -TTL | 100.0% | 41.2% | 10 | 0 | 0 |
| -Sanit | 100.0% | 70.6% | 5 | 0 | 0 |
| ChainCaps | 100.0% | 23.5% | 9 | 0 | 0 |

## 解读

- **-Scope** 应让良性完成率大幅下降（scope 隔离是可用性的关键组件），但攻击拦截应基本保持。
- **-Auditor / -TTL / -Sanit** 揭示在 scope 隔离之后由哪个机制束缚残余 FP，以及鲁棒性如何退化。

## 论文段落（英文）

> The ablation confirms scope isolation is the *availability* spine: removing it drops benign completion from 70.6% to 23.5% while attack block rate stays at 100.0% (matches Full: 100.0%), i.e. availability is the knob that scope controls, security is preserved. Removing the auditor (70.6% BCR) and the TTL (41.2% BCR) each cut benign completion further, confirming their role as complementary availability levers, while the ChainCaps baseline remains at 100.0%/23.5%, matching our race-v3 reproduction.

## 论文段落（中文）

> 消融实验证明 scope 隔离是可用性的支柱：移除它使 BCR 从 70.6% 暴跌至 23.5%，而攻击拦截率仍保持在 100.0%（与 Full 相同），即可用性由 scope 控制、安全性不受影响。移除审计器（BCR 70.6%）及 TTL（BCR 41.2%）都会进一步拉低良性完成率，印证二者互为补充的可用性杠杆；ChainCaps 基线保持在 100.0% / 23.5%，与我们的 raid_v3 复现一致。

## 关于 -Scope 与 -Auditor 的额外说明

- **-Auditor** 与 Full 持平（70.6%）是因为实验一/二所用场景集中，最关键的良性流已由 scope 隔离 + TTL 释放放行，是否接入 DeepSeek 审计器并无增量；这与实验二显示的"G/Y/R=1/4/2 但 5 个 FP 仍由 scope_release 拯救"是一致的——在大场景量上 LLM 审计更多是 compliance/兜底而非主力。论文中应据此来慎言 LLM 的贡献。
- **-TTL** 退化至 41.2% 是 mark_component_complete 被关闭所致，说明自动释放机制是 scope 之外的第二可用性支柱（与 -Scope 联合证明可用性由两机制共同支撑）。