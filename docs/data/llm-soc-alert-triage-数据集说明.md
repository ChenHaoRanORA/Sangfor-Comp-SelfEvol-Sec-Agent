# LLM-SOC-Alert-Triage 数据集说明

> 本地路径：`data/llm-soc-alert-triage-main/`
> 用途：为"自进化多维度服务器安全智能体"提供带监督标签的告警研判（TP/FP 分类 + 优先级）评测集与复现基线
> 来源仓库：https://github.com/c0deing/llm-soc-alert-triage （MIT License）
> 更新日期：2026-09-06

---

## 1. 来源与背景

该仓库是研究论文 *"Possibilities and Limitations of Using Large Language Models (LLMs) for Alert Classification and Prioritisation in Security Operations Centers (SOCs)"*（Expert Systems with Applications, DOI: [10.1016/j.eswa.2026.133194](https://doi.org/10.1016/j.eswa.2026.133194)）的可复现工件，包含脚本、数据集、8 个 LLM 模型的评测结果与可视化。

**实验环境（模拟 SOC）**：
- Wazuh (SIEM)
- Suricata（IDS，接入 Wazuh）
- Windows Server 2019（域控 AD）
- Windows 11 Pro（入域终端，采集 **Sysmon** 事件）
- Linux 服务器（运行靶场 DVWA、Mutillidae）
- Kali Linux（手动攻击机）

**告警产生方式**：TP 主要由 **Atomic Red Team** 技术触发，另有 Kali 手工攻击；FP 来自日常/统计类误报。所有告警以 Wazuh（Elasticsearch 文档）JSON 格式导出。

**核心结论（论文）**：
- LLM 在 TP/FP 二分类上有潜力，但**优先级（Prioritisation）四分类普遍表现差**；
- 传统机器学习（TF-IDF + 线性 SVM 等）在二分类上仍是强基线。

---

## 2. 数据构成与目录结构

共 **178 条**告警（原始 TP 106 行 → 去重后 104 条；FP 74 条）。

### 2.1 文件清单（本地实测行数/大小）

| 文件 | 行数 | 说明 |
|---|---|---|
| `Data/0_Raw/TP_alerts_raw.jsonl` | 106 | 原始 TP 告警（Wazuh JSON，含重复） |
| `Data/0_Raw/FP_alerts_raw.jsonl` | 74 | 原始 FP 告警 |
| `Data/1_Preprocessed/1_TP_alerts_preprocessed_*.jsonl` | 104 | TP 预处理+打标（去重后） |
| `Data/1_Preprocessed/1_FP_alerts_preprocessed_*.jsonl` | 74 | FP 预处理+打标 |
| `Data/2_Merged/2_alerts_preprocessed_merged_*.jsonl` | 178 | 合并+随机打乱（**喂给所有 LLM 的最终输入**） |
| `Scripts/ML_baseline_scripts/2_alerts_preprocessed_merged_*.jsonl` | 178 | ML 基线用输入副本 |
| `Scripts/ML_baseline_scripts/prepared_alert_dataset.csv` | 4464 | ML 基线特征文本集（message 多行展开），列：`text,label,label_name`（TP=1/FP=0） |
| `Results/<Run_x_模型>/3_alerts_classified_prioritised_*.jsonl` | 178/run | 各 LLM 输出 |
| `Results/<Run_x_模型>/4_..._postprocessed.jsonl` | 178/run | 后处理（归一化+清洗 justification） |
| `Results/<Run_x_模型>/5_..._evaluation_report.xlsx` | - | 评估报告 |
| `Results/<Run_x_模型>/6_..._postprocessed.xlsx` | - | 人工检视用 Excel |
| `Results/20260509_ML_baseline_results/ml_baseline_results.csv` | 4 | ML 基线指标 |

目录内另有 `GA.drawio.png` / `Methodology.drawio.png`（图形摘要/流程图）、`LICENSE`（MIT）。

### 2.2 标签分布

| 维度 | 分布 |
|---|---|
| 分类（TP/FP） | TP=104，FP=74 |
| 优先级（ground truth 来自 Wazuh rule.level 映射） | Low=136，Medium=12，High=25，Critical=5（类极度不平衡） |

---

## 3. 数据结构与字段字典

### 3.1 原始告警（`0_Raw/*.jsonl`）
每行一个完整 Wazuh/ES 告警文档（含 Sysmon/AD/Suricata 结构化内容）：

| 字段 | 含义 |
|---|---|
| `_index` | ES 索引名，如 `wazuh-alerts-4.x-2025.07.04` |
| `_id` / `_score` | ES 文档 ID / 评分 |
| `_source.input.type` | `log` |
| `_source.agent.id/name/ip` | 受监控主机（如 `003` / `Win11Client` / `10.0.2.14`） |
| `_source.manager.name` | Wazuh 管理器名（`wazuh-server`） |
| `_source.decoder.name` | 解码器：`windows_eventchannel`、`suricata`、`json` 等 |
| `_source.rule.id/description/groups/firedtimes/mail/mitre` | 命中规则：ID（如 `92005`）、描述、分组、MITRE（如 `T1059/Command and Scripting Interpreter/Execution`） |
| `_source.rule.level` | Wazuh 规则级别（预处理时被移除，见 3.2） |
| `_source.data.win.system` | Windows 事件头：`eventID/task/providerName/channel/systemTime/message/severityValue/processID/computer` |
| `_source.data.win.eventdata` | Sysmon 事件细节：`image/processId/processGuid/commandLine/parentCommandLine/user/hashes(含SHA1,MD5,SHA256,IMPHASH)/targetFilename/...` |
| `_source.location` | `EventChannel` 等 |
| `_source.timestamp` / `fields.timestamp` / `sort` | 时间（ISO / ES 排序时间戳） |
| `_source.id` | Wazuh 告警 ID（如 `1751656136.54917443`） |

> Windows Sysmon 事件常见 `eventID`：1=进程创建、3=网络连接、11=文件创建、15=文件流创建、22=DNS 等；`system.message` 内含事件原文，非常适合直接做 LLM 研判输入。

### 3.2 预处理/合并后（`1_Preprocessed`、`2_Merged`）——标准行结构
由 `1_alert_preprocessing.py` 生成，每行：

| 字段 | 含义 |
|---|---|
| `id` | 告警唯一 ID（= `_id`，预处理按此去重） |
| `description` | `rule.description`（缺失则为 `"MISSING"`） |
| `label` | **Ground truth：`TP` 或 `FP`** |
| `rule_level` | Wazuh 规则级别（数值） |
| `rule_priority` | 由 `rule_level` 映射的参考优先级：`Critical(≥15)/High(≥12)/Medium(≥7)/Low(≥0)` |
| `alert` | 清洗后的完整告警 JSON（已去掉 `rule.level`，避免把"答案"直接泄露给模型） |

`2_alert_random_merging.py` 再把两文件合并并 `random.shuffle`，产出 178 条打乱顺序的最终语料。

### 3.3 LLM 运行输出（`Results/*/3_*.jsonl`）——在 3.2 结构上追加字段
| 字段 | 含义 |
|---|---|
| `chatgpt_response` | LLM 结构化返回：`{alert_id, classification, priority, justification}` |
| `chatgpt_classification` | 归一化分类：`TP` / `FP` |
| `chatgpt_priority` | 归一化优先级：`Low/Medium/High/Critical` |
| `chatgpt_justification` | 研判理由（后处理去除控制字符、上限 3 万字符） |
| `classification_match` | 分类是否正确（bool） |
| `priority_match` | 优先级是否与 `rule_priority` 一致（bool） |

---

## 4. 标签设计要点（使用前必读）

1. **两个标签含义不同**：
   - `label`（TP/FP）= 真实分类，来源是"确实由攻击触发 / 确属正常误报"，与 Wazuh 规则级别无关；
   - `rule_priority` = **只是 `rule.level` 的粗粒度映射**，而非人工研判的严重度。因此做"优先级评测"时真正的信号（level）已从 `alert` 中移除，模型须从告警内容自行推断。
2. **公平性处理**：预处理时通过 `clean_alert()` 删除 `alert._source.rule.level`，防止模型直接"抄答案"。
3. **去重**：原始 TP 106 行含重复 `_id`，预处理去重后 104 条；合并集 178 条无重复。
4. **不均衡**：优先级四类极度不均衡（Low 占 76%），论文也用 macro 指标避免被多数类主导。
5. `description` 可能为 `"MISSING"`（如 rule id `11` 的 `stats` 规则），提示词与特征工程需处理缺失。

---

## 5. 官方复现流水线（`Scripts/`）

```text
1_alert_preprocessing.py           原始 JSONL → 打标+去重+移除 rule.level
2_alert_random_merging.py          TP/FP 合并 → 随机打乱 → merged JSONL
3_alert_classification_prioritisation.py        LLM 推理（JSON-Schema 强约束输出，
                                         system: 分类 TP/FP + 定级 Low/Medium/High/Critical）
3_alert_classification_prioritisation_deepseek-specific.py    DeepSeek 适配版
4_alert_postprocessing.py          输出归一化（TRUE POSITIVE→TP 等）+ 清洗 justification
5_result_evaluation.py             分类 report/混淆矩阵/TPR/FPR/FNR + 优先级评估 → xlsx
6_jsonl_result_to_excel.py         转 Excel 人工检视
ML_baseline_scripts/
  prepare_data.py                  抽取嵌套字段拼接文本 → prepared_alert_dataset.csv
  run_baselines.py                 Logistic Regression / Random Forest / Linear SVM，
                                   TF-IDF + Stratified 5-Fold CV（random_state=42）
```

> 提示词见 `3_alert_classification_prioritisation.py`：system prompt 要求 "Classify the security alert as TP (True Positive) or FP (False Positive) and assign a Priority: Low, Medium, High or Critical"，输出用 `json_schema`（strict）约束为 `{alert_id, classification, priority, justification}`。

---

## 6. 已有结果摘要（可直接作为对照基线）

**LLM（论文 README）**：分类任务 Olmo 3 召回率最高 96.15% 但 FPR 高达 90.54%；优先级任务普遍差，GPT-4.1 最佳 macro recall 仅 34.59%（acc 49.44%）。

**传统 ML（`ml_baseline_results.csv`，5 折 CV）**：

| 模型 | Accuracy | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|
| Logistic Regression | 83.8% | 85.1% | 88.5% | 86.2% | 23.0% |
| Random Forest | 83.2% | 89.4% | 80.7% | 84.6% | 13.5% |
| Linear SVM | **88.2%** | **90.5%** | **89.4%** | **89.6%** | 13.5% |

→ 二分类任务上"规则+ML 基线"远强于通用 LLM，可作为智能体研判模块的**性价比对照**；LLM 的价值在解释/推理链而非原始分类精度。

---

## 7. 在本项目智能体中的应用建议

与《docs/data/linux-APT-Dataset-2024-数据集说明.md》形成互补：**linux-APT 侧重 Linux 告警流的量、MITRE TTP 覆盖与流式回放；本数据集提供带人工语义标签的 Windows/Sysmon 侧告警研判基准**。

1. **LLM 告警研判模块的离线评测集（最直接用途）**
   直接把 `2_Merged/*.jsonl` 的 178 条作为"输入告警 + 期望输出"：
   - 分类目标：`TP/FP`；
   - 优先级目标：`Low/Medium/High/Critical`；
   - 输出格式沿用仓库的 JSON-Schema（`classification+priority+justification`），便于与论文 8 个模型结果对照。
2. **复现并替换为你的基线**：先跑 `ML_baseline_scripts` 拿到 ML 基线，再用你智能体的"规则引擎→LLM 研判"链路跑同一语料，用同一评估口径（classification_report、混淆矩阵、TPR/FPR、macro 指标）对比；同时记录推理耗时/成本（论文也考察了这两个运维指标）。
3. **模型选型与提示词设计素材**：178 条的 `alert` 含完整 Sysmon 进程树（`commandLine/parentCommandLine/image/hashes`）与 MITRE 标签，适合：
   - 做你的"模式认知/知识图谱"输入样例（进程→用户→文件→技术链）；
   - 构造 few-shot 示例与预期 justification，沉淀为记忆库初始经验。
4. **与 linux-APT 数据组合使用**：从 linux-APT 清洗流中抽取候选告警 → 用本数据集训练/校准的研判提示词与阈值做在线分流（规则→低/中危；LLM→高/危急复核）；两数据一起做跨源（Linux vs Windows）去重与关联测试。
5. **注意小样本与类不平衡**：做监督训练/评测请用分层 5 折（沿用仓库 `random_state=42`），不要切单一 train/test 后过度解读；优先级四分类建议同时报告 macro 指标。

---

## 8. 局限与注意事项

- **规模小**：仅 178 条，难以单独支撑大模型微调/泛化结论，适合做**评测集/基准**而非训练集。
- **环境单一**：Windows AD + Sysmon 为主，含少量 Suricata/Linux 靶场告警；与"多维度服务器安全智能体"的主场景（Linux 集群）需用 linux-APT 数据补足。
- **优先级标签粗糙**：`rule_priority` 是规则级别的硬编码映射，不代表真实威胁影响面；用作"期望输出"时会低估 LLM 语义定级的合理性。
- **时间与版本**：告警日期为 2025-07 前后，模型结果对应 2025 年的 OpenAI/DeepSeek/Ai2 快照；新版本模型不可直接沿用其绝对数值。

---

## 9. 参考链接

- GitHub 仓库：https://github.com/c0deing/llm-soc-alert-triage
- 论文 DOI：https://doi.org/10.1016/j.eswa.2026.133194
- Wazuh（SIEM/告警结构）：https://documentation.wazuh.com/
- Atomic Red Team（TP 触发技术库）：https://github.com/redcanaryco/atomic-red-team
