# Linux-APT-Dataset-2024 数据集说明

> 本地文件：`data/linux-APT-Dataset-2024.csv`（198.7 MB）
> 用途：为"自进化多维度服务器安全智能体"提供流式告警数据模拟与测试语料
> 更新日期：2026-09-06

---

## 1. 数据集来龙去脉

**Linux-APT-Dataset-2024** 是巴基斯坦 NUST 等团队发布的公开数据集，配套论文发表于 *Data in Brief* 54 (2024) 110290。

| 项 | 内容 |
|---|---|
| 官方地址 | [Mendeley V2](https://data.mendeley.com/datasets/5x68fv63sh/2)（Combine-CSV + Processed-XLSX）、[Zenodo](https://zenodo.org/records/10685642)（17 个日期文件） |
| DOI | 10.17632/5x68fv63sh.2 / 10.5281/zenodo.10685642 |
| 采集方式 | 由 **Wazuh SIEM**（Elastic Stack/Kibana）集中采集导出 |
| 时间窗 | **2023-10-01 ~ 2024-01-07**，共 17 个日期文件 |
| 采集对象 | 多台 Ubuntu Linux 虚拟机（hostname：`ubuntu`/`machine-1`/`machine-3`/`Machine-1-New`；IP：`192.168.204.x`、`192.168.217.x`） |
| 模拟内容 | Linux 提权 payload、近期 CVE 利用、键盘记录器，以及 **APT41 / APT28 / APT29 / Turla** 等活动；同时含正常/常规运维日志（正负样本混合） |
| 关键特征 | 每条告警按 **MITRE ATT&CK** 标注 TTP（规则级），可作为"正常 vs 恶意"的判定依据 |

数据分为两个版本：
- **combine.csv / Processed Version.xlsx（原始）**：纯 Wazuh 告警字段，TTP 已按列拆出；Processed 版额外带 `General/Malicious` 标签（1=恶意/可疑，0=正常）。
- 论文建议："若记录带规则级 TTP 标签（`rule.mitre.*` 非空）即视为恶意/可疑，否则视为正常。"

### 本地文件的构成
本地这份 CSV 是 **17 个日期导出的直接拼接**，因此存在**多次重复表头、各段列子集不同**的问题（详见第 3 节"数据结构体检"），任何程序化读取都必须先做分块清洗。

---

## 2. 常见问题定位（字段归属速查）

列名本质是 **Elasticsearch 中 `_source`（Wazuh 告警 JSON 文档）的扁平化路径**：`a.b.c` = `{"a":{"b":{"c":…}}}`。典型告警 JSON 结构如下（示例为 PAM 登录会话，节选自本文件）：

```json
{
  "_source": {
    "agent":    { "id": "004", "name": "ubuntu", "ip": "192.168.204.130" },
    "manager":  { "name": "ubuntu" },
    "predecoder": { "hostname": "sohaib-virtual-machine", "program_name": "sudo", "timestamp": "01/10/2005 22:29" },
    "decoder":  { "name": "pam" },
    "rule": {
      "id": "5501", "level": 3,
      "description": "PAM: Login session opened.",
      "groups": ["pam", "syslog", "authentication_success"],
      "firedtimes": 18, "mail": false,
      "pci_dss": ["10.2.5"], "hipaa": ["164.312.b"],
      "mitre": { "id": "T1078", "technique": "Valid Accounts", "tactic": "Defense Evasion" }
    },
    "full_log": "Oct  5 22:29:05 sohaib-virtual-machine sudo: pam_unix(sudo:session): session opened for user root(uid=0) by sohaib(uid=1000)",
    "input": { "type": "log" },
    "timestamp": "Oct 5, 2023 @ 17:29:05.393",
    "location": "/var/log/auth.log",
    "id": "1696526946",
    "data": { "dstuser": "root(uid=0)", "srcuser": "sohaib", "uid": "1000" }
  }
}
```

> 注意：CSV 中时间/日期字段的**格式在各导出段并不一致**（epoch 整数 / 微秒浮点 / Kibana 格式化字符串 `Oct 1, 2023 @ 00:49:18.889` 并存）；数组字段以 JSON 字符串存放且双引号被转义（如 `["ossec","rootcheck"]`），还原需 `json.loads`。

---

## 3. 字段字典

### 3.0 导出信封字段（非告警内容）
| 字段 | 含义 |
|---|---|
| `_index` | ES 索引名 = `wazuh-alerts-4.x-<日期>`，可作时间分桶 |
| `_id` / `_version` / `_score` | ES 文档 ID / 版本 / 评分，无安全语义 |

### 3.1 告警元信息与时间
| 字段 | 含义 |
|---|---|
| `_source.id` | Wazuh 告警 ID（一般是事件时间戳 epoch） |
| `_source.timestamp` / `_source.@timestamp` | 事件/入库时间（不同导出段格式不一） |
| `_source.location` | 原始日志来源，如 `/var/log/audit/audit.log`、`/var/log/dpkg.log`、`/var/log/auth.log`、`rootcheck` |
| `_source.full_log` | **原始日志全文**（命令、payload、参数都在此，是正则/LLM 解析主体） |
| `_source.input.type` | 采集类型：`log` / `command` |
| `_source.previous_log` / `previous_output` | 前一条关联日志/输出（上下文联动） |
| `_source.extra_data` | 解码器额外数据 |

### 3.2 资产与上下文
| 字段 | 含义 |
|---|---|
| `agent.id` / `agent.name` / `agent.ip` | 被监控主机 ID / 名称 / IP |
| `manager.name` | Wazuh 管理器名称 |
| `predecoder.hostname` / `program_name` / `timestamp` | 预解码日志头三元组：主机名、程序名（`sshd`/`sudo`/`systemd` 等）、原始时间 |
| `decoder.name` / `decoder.parent` | 命中的解码器/父解码器：`auditd`、`sca`、`rootcheck`、`pam`、`dpkg-decoder`、`web-accesslog`、`syscheck_integrity_changed` 等 |

### 3.3 规则引擎字段 `rule.*`（告警研判核心）
| 字段 | 含义 |
|---|---|
| `rule.id` | 规则号，如 `19007`(CIS/SCA)、`510`(rootcheck)、`2902`(dpkg)、`5501`(PAM)、`80792`(自定义审计) |
| `rule.level` | **严重级别 0~15**，越高越严重（SCA 配置多为 7，命令审计/正常 PAM 多为 3） |
| `rule.description` | 规则一句话描述（可作告警标题） |
| `rule.groups` | 分组数组，如 `["sca"]`、`["audit","audit_command"]`、`["syslog","dpkg","config_changed"]` |
| `rule.firedtimes` / `rule.mail` | 触发次数 / 是否邮件 |
| `rule.mitre_tactics` / `mitre_techniques` / `mitre_mitigations` / `rule.mitre.id` / `mitre.technique` / `mitre.tactic` | **MITRE ATT&CK 映射**。规则级 TTP 非空 ≈ 恶意/可疑（如 `Valid Accounts`/`T1078`） |
| `rule.pci_dss` / `hipaa` / `gdpr` / `nist_800_53` / `nist_sp_800-53` / `tsc` / `soc_2` / `cis_csc_v7` / `cis_csc_v8` / `cis` / `gpg13` | 合规框架映射标签（数组字符串） |

### 3.4 解码器动态字段 `data.*`（按事件族分组）
- **通用账号/进程**：`data.uid`、`dstuser`、`srcuser`、`tty`、`pwd`、`command`、`srcip`、`srcport`、`shell`、`home`、`gid`
- **dpkg 软件变更**：`data.status`（`status installed` / `install` / `status half-configured`）、`package`、`arch`、`version`
- **Web 访问/攻击**：`data.id`、`url`、`protocol`、`status`、`file`、`title`
- **SCA 安全配置审计**：
  - 顶层：`data.sca.scan_id`、`type`（`check`/`policy`）、`policy`、`passed/failed/invalid/score/total_checks`、`file`、`description`
  - 检查项：`data.sca.check.id/title/description/rationale/remediation/command/result/references/directory/file`
  - 合规映射：`data.sca.check.compliance.*`（PCI DSS / CIS CSC / SOC2 / HIPAA / NIST / **mitre_tactics / mitre_techniques** 等。注意：这里的 MITRE 属于**合规映射**，不是攻击 TTP，勿用于恶意判定）
- **auditd 命令审计**：`data.audit.type`（`SYSCALL`/`EXECVE`/`CWD`/`PATH`…）、`syscall`（59=execve）、`success`/`exit`、`pid`/`ppid`、`auid`/`uid`/`euid`/`suid`/`fsuid`/`gid`/`egid`/`sgid`/`fsgid`（`4294967295`=unset）、`exe`、`comm`、`command`、`cwd`、`tty`、`key`（如 `audit-wazuh-c`）、`session`、`arch`、`execve.a0..a7`、`file.inode/mode/name`
- **syscheck 文件完整性 FIM**：`syscheck.event`（`added`/`modified`/`deleted`）、`path`、`mode`/`perm`、`uid`/`gid`/`uname`/`gname`、`size`/`mtime`/`md5`/`sha1`/`sha256`（before/after）、`changed_attributes`、`inode_before`/`inode_after`

> 由于是分块拼接导出，**并非每个告警都带以上全部字段**——SCA 告警带 `data.sca.*`，auditd 告警带 `data.audit.*`。代码读取时须判存在性。

---

## 4. 数据结构体检与质量告警（本地实测）

| 项 | 实测值 | 说明 |
|---|---|---|
| 文件大小 | 198.7 MB | |
| CSV 记录数 | 约 12.2 万行（含重复表头） | |
| 表头 | **文件内多次重复**，各段列数 34~254 不等 | 多段 Kibana 导出直接拼接 |
| 索引名覆盖 | `wazuh-alerts-4.x-2023.10.01 ~ 2024.01.0x` | 与论文时间窗一致 |
| 事件族（已核对样本） | `sca`（19007 等）、`rootcheck`（510）、`dpkg`（2901/2902/2904）、`pam`（5501/5502/5402）、auditd 命令审计（80792，自定义规则）、web accesslog、syscheck(FIM) | |
| 标签列 | **无** General/Malicious 列 | 本文件是原始 combine 版，非 Processed 版 |

**最大风险：直接整表 `pandas.read_csv` 会列错位。**
实测证据：按首段 123 列表头解析全文件后，`rule.level` 列出现大量 `4294967295`（实为 audit 事件 `auid` 值）、`decoder.name` 列出现 `/usr/bin/dash` 等命令路径——不同导出段（不同表头、不同字段子集）被顺序拼接所致。因此程序化使用必须先清洗。

### 已识别的字段值编码/格式坑
1. 数组字段为 JSON 字符串且双引号转义，如 `["syslog","dpkg","config_changed"]` → 需 `json.loads`。
2. 时间字段三态并存：epoch 整数（`1696121358`）、微秒浮点（`1704304027.4286179`）、Kibana 格式化串（`Oct 1, 2023 @ 00:49:18.889`）。
3. 合规字段存在多版本并存（如 `compliance.pci_dss_v4.0` 与 `compliance.pci_dss_4.0`），清洗时建议归一化。
4. 恶意判定只能依赖**规则级** `rule.mitre.*`；`data.sca.check.compliance.mitre_*` 是合规映射，不可用作恶意标签。

---

## 5. 在本项目智能体中的应用建议

对应《docs/dev-plan/开发计划.md》的"流式数据模拟 / 数据集构建"阶段：

1. **先建"分块清洗/规范化"模块**（建议入 `src/`）：
   按重复表头分段 → 每段按自身表头把扁平列还原为 Wazuh 告警 JSON → 统一保留核心字段（`@timestamp/agent/rule.*/full_log/location/decoder/predecoder/data.*`）→ 数组字段 `json.loads` → 时间统一为 epoch/ISO。
2. **恶意/正常标签**：论文口径 = "规则级 `rule.mitre.*` 非空即可疑"。需高质量监督标签时可下载 Mendeley **Processed Version.xlsx**（含 General/Malicious 列）交叉对齐。
3. **流式告警模拟**：清洗后按原始时间排序，用时间压缩回放（WebSocket / 文件尾读）灌给智能体，无需真实打靶即可联调"感知 → 研判 → 预警 → 处置"链路。
4. **规则底座回归**：`rule.id/level/description/groups` 即规则引擎输出，可用于离线评估三级研判（规则 → 大模型 → 处置）的准确率与误报率。
5. **模式认知/知识图谱（数据溯源）**：auditd 行（`data.audit.*` + `execve.a0..a7`）可重组"用户→进程→命令参数→文件→时间"行为链；从 `full_log` 抽取实体（进程/用户/IP/文件/哈希）构建主机侧时序图，契合"分层记忆/模式挖掘"规划。
6. **评测集构造**：按事件族（sca/auditd/pam/dpkg/web/FIM/rootcheck）× 正常/恶意分层抽样；可与仓库 `data/llm-soc-alert-triage-main`（多源攻击告警 + 人工研判标签）合并做跨源告警去重/聚类评测。

---

## 6. 参考链接

- Mendeley Data（Combine-CSV + Processed XLSX）：https://data.mendeley.com/datasets/5x68fv63sh/2
- Zenodo（17 个日期文件）：https://zenodo.org/records/10685642
- 论文（Data in Brief, 2024）：https://pmc.ncbi.nlm.nih.gov/articles/PMC11220842/pdf/main.pdf
- Wazuh 告警/解码器处理流程文档：https://documentation.wazuh.com/4.9/user-manual/capabilities/command-monitoring/command-output-analysis.html
