# -*- coding: utf-8 -*-
"""联合决策证据检索：把"多层记忆 + 知识图谱"转成可注入 LLM 研判的紧凑证据。

供消融评测（scripts/eval_joint_decision.py）与后续处置流 gather_evidence 节点复用。
防泄漏：流式切分——对"当前 seq"的告警，只允许引用 seq 更早的片段与其归纳出的可疑模式
（严格限制在相同 dataset；模式全部支撑片段均早于当前才可作证据）。

证据三块：
- memory：历史相似片段（Chroma 语义召回 + SQLite 回取，截断摘要/判定）；
- patterns：由过往片段归纳出的可疑模式（含 hits/置信/kind/衍生规则命中提示）；
- kb：ATT&CK 知识图谱多跳（Technique → Tactic / 使用团伙数）。
"""
from __future__ import annotations

from collections import Counter
from typing import Optional

from src.core.knowledge.graph import KnowledgeKB
from src.core.memory.store import MemoryStore

_PREFIX = "frag-llm-soc-"  # 流式切分限定数据集（llm-soc 评测语料）


class EvidenceBuilder:
    def __init__(self, store: MemoryStore, kb: Optional[KnowledgeKB] = None):
        self.store = store
        self.kb = kb
        self._seq_map: Optional[dict[str, int]] = None
        self._patterns: Optional[list[dict]] = None
        self._rule_cache: dict[str, Optional[dict]] = {}

    # ---------------------------------------------------------- 记忆
    def _seq_of(self, fragment_id: str) -> Optional[int]:
        if self._seq_map is None:
            self._seq_map = self.store.fragment_seqs()
        return self._seq_map.get(fragment_id)

    def similar_past_fragments(self, query: str, dataset: str, seq_now: int, k: int = 8) -> list[dict]:
        """语义召回相似片段，只保留 seq < seq_now 的（流式、防泄漏）。"""
        cands = self.store.search_fragments(query, k=30, dataset=dataset)
        past = [f for f in cands if (f.get("seq") or 0) < seq_now]
        return past[:k]

    def _past_patterns_all(self, dataset: str, seq_now: int) -> list[dict]:
        """由全早于当前 seq 的片段归纳出的全部可疑模式（防未来数据泄漏）。"""
        out = []
        for p in self.store.patterns(dataset=dataset):
            sids = p.get("supporting_fragment_ids") or []
            if not sids:
                continue
            # 全部支撑片段必须在当前数据集、且早于当前（防未来数据泄漏）；
            # 片段 id 前缀兼容 miner 主链 frag-* 与复核反馈回流 fb-*
            seqs = [self._seq_of(fid) for fid in sids
                    if fid.startswith(f"frag-{dataset}-") or fid.startswith(f"fb-{dataset}-")]
            if len(seqs) != len(sids):
                continue
            if any(s is None or s >= seq_now for s in seqs):
                continue
            out.append(p)
        out.sort(key=lambda p: -(p.get("hits") or 0))
        return out

    def past_patterns(self, dataset: str, seq_now: int, k: int = 4) -> list[dict]:
        """由全早于当前 seq 的片段归纳出的可疑模式（含衍生规则命中提示），按命中数取 top-k。"""
        return self._past_patterns_all(dataset, seq_now)[:k]

    def active_patterns_covering_rule(self, dataset: str, rule_id: str, seq_now: int) -> list[dict]:
        """是否命中『过去已成型』的可疑模式：rule_id 被某 active 模式的覆盖规则集包含。

        仅返回支撑片段全早于当前（可作证据、防泄漏）的 active 模式；v3 处置分流用它
        判定『命中可疑模式 → 需显意识(LLM) 推理处置』。
        """
        if not rule_id:
            return []
        return [p for p in self._past_patterns_all(dataset, seq_now)
                if p.get("state") == "active" and rule_id in (p.get("rule_ids") or [])]

    def _derived_rule_hint(self, pattern: dict) -> Optional[dict]:
        rid = pattern.get("derived_rule_id")
        if not rid:
            return None
        if rid not in self._rule_cache:
            self._rule_cache[rid] = self.store.rule_by_id(rid)
        r = self._rule_cache[rid]
        if r is None or not r.get("enabled") or r.get("state") != "active":
            return None
        return {"rule_id": rid, "name": r.get("name"), "severity": r.get("severity"),
                "fired_times": r.get("fired_times")}

    # ---------------------------------------------------------- 图谱
    def kb_lines(self, techniques: list) -> list[str]:
        """ATT&CK 多跳：Technique 名 → Tactic / 使用团伙计数。"""
        if self.kb is None or not techniques:
            return []
        try:
            g = self.kb.alert_graph(techniques)
        except Exception:  # noqa: BLE001  图谱查询失败不应阻断研判
            return []
        lines = []
        for t in g.get("techniques") or []:
            tac = ", ".join(x["name"] for x in t.get("tactics") or []) or "-"
            actor = f"，{t['actors']} 个已知团伙使用" if t.get("actors") else ""
            lines.append(f"- {t['name']}（{t['attack_id']}）→ 战术: {tac}{actor}")
        return lines

    # ---------------------------------------------------------- 汇总
    def collect(self, dataset: str, query: str, techniques: list,
                seq_now: int, with_memory: bool = True, with_kb: bool = True,
                k_frag: int = 8, k_pat: int = 4) -> dict:
        """返回 {"evidence_text": str, "counts": {frags, patterns, kb}}。"""
        blocks: list[str] = []
        counts: dict[str, int] = {"frags": 0, "patterns": 0, "kb": 0}

        if with_memory:
            frags = self.similar_past_fragments(query, dataset, seq_now, k=k_frag)
            pats = self.past_patterns(dataset, seq_now, k=k_pat)
            counts["frags"] = len(frags)
            counts["patterns"] = len(pats)
            if frags or pats:
                parts = []
                if frags:
                    cls = Counter((f.get("classification") or "未判") for f in frags)
                    parts.append(f"[历史相似片段 {len(frags)} 条 · 判定分布 {dict(cls)}]")
                    for f in frags:
                        summ = (f.get("summary") or "")[:160].replace("\n", " ")
                        head = (f"{f.get('rule_id')}" if f.get("rule_id") else "?")
                        parts.append(
                            f"· #{f.get('seq')} rule {head} 判定={f.get('classification') or '未判'}"
                            f"（{f.get('method')}）: {summ}")
                if pats:
                    for p in pats:
                        hint = self._derived_rule_hint(p)
                        dline = (p.get("description") or "")[:200].replace("\n", " ")
                        tag = f"状态={p.get('state')} 置信={p.get('confidence')}"
                        extra = (f"，命中率证据→衍生规则 {hint['rule_id']}[{hint['name']} "
                                 f"severity={hint['severity']} fired={hint['fired_times']}]"
                                 if hint else "")
                        parts.append(f"· 模式 {p.get('pattern_id')} kind={p.get('kind')} "
                                     f"hits={p.get('hits')} {tag}{extra}: {dline}")
                blocks.append("[参考·多层记忆（以下均为当前告警之前的相似经验，供判断是否重演误报/威胁）]\n"
                              + "\n".join(parts))

        if with_kb:
            lines = self.kb_lines(techniques)
            counts["kb"] = len(lines)
            if lines:
                blocks.append("[参考·ATT&CK 知识图谱]\n" + "\n".join(lines))

        return {"evidence_text": "\n\n".join(blocks), "counts": counts}
