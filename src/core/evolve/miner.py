# -*- coding: utf-8 -*-
"""模式挖掘器 v1：从历史片段产出可疑模式（draft→active）。

输入：同一数据集的 Fragment 列表（含 host/ts/rule_id/classification/summary）。
候选：
  - behavior 链：同主机短时间窗内 >=min_distinct 条不同规则共现（攻击链/行为族）；
  - fp_noise 高误报：同一 rule_id 片段中 FP 占比高（Agent 反馈回传 → 降噪提议）。
有界 LLM 归纳：对支撑最大的一批 behavior 候选走真实 DeepSeek（可 --no-llm 启发式），
LLM 判定 meaningful=false 的不成模式；其余按启发式/统计直接成模式（全部记审计）。
"""
from __future__ import annotations

import datetime
from typing import Iterable, Optional

from src.core.evolve.common import SYSTEM_INDUCE, level_sev, now_ms
from src.core.memory.models import Pattern
from src.core.memory.store import MemoryStore

WINDOW_MS = 180_000            # 行为链时间窗 3 分钟
MIN_DISTINCT_RULES = 3
MIN_EVENTS = 4
MAX_SPAN_EVENTS = 240          # 单窗内最多评估事件数，防同主机长流拖慢


def _frag_seq(f: dict) -> int:
    return int(f.get("seq") or 0)


def chain_candidates(frags: Iterable[dict]) -> list[dict]:
    """同主机滑动时间窗找规则共现行为链（非重叠、支撑最大者优先）。"""
    by_host: dict[str, list[dict]] = {}
    for f in frags:
        if not f.get("rule_id") or f.get("ts_ms") is None:
            continue
        by_host.setdefault(str(f.get("host") or "-"), []).append(f)
    out: list[dict] = []
    seen_sig: set[tuple] = set()
    for host, arr in by_host.items():
        arr.sort(key=lambda x: (x["ts_ms"] or 0, _frag_seq(x)))
        n = len(arr)
        i = 0
        while i < n:
            rules: set[str] = set()
            best_j, best_cnt = None, -1
            t0 = arr[i]["ts_ms"]
            j = i
            while j < n and j - i < MAX_SPAN_EVENTS and (arr[j]["ts_ms"] - t0) <= WINDOW_MS:
                rid = str(arr[j]["rule_id"])
                rules.add(rid)
                cnt = j - i + 1
                if len(rules) >= MIN_DISTINCT_RULES and cnt >= MIN_EVENTS:
                    best_j, best_cnt = j, cnt
                j += 1
            if best_j is not None:
                sig = tuple(sorted(rules))
                if sig not in seen_sig:
                    seen_sig.add(sig)
                    members = arr[i:best_j + 1]
                    out.append({
                        "kind": "behavior",
                        "dataset": members[0].get("dataset"),
                        "host": host,
                        "ts_from": min(m["ts_ms"] for m in members),
                        "ts_to": max(m["ts_ms"] for m in members),
                        "rule_ids": sorted(rules),
                        "support": len(members),
                        "fragment_ids": [m["fragment_id"] for m in members],
                        "members": members,
                    })
                i = best_j + 1
            else:
                i += 1
    out.sort(key=lambda c: (-c["support"], -len(c["rule_ids"])))
    return out


def fp_noise_candidates(frags: Iterable[dict], min_size: int = 3, fp_ratio: float = 0.6) -> list[dict]:
    """同规则重复且 FP 占比高 → 降噪提议（依赖 Agent/人工判定回传）。"""
    grp: dict[str, dict] = {}
    for f in frags:
        cls = (f.get("classification") or "").upper()
        if cls not in ("TP", "FP"):
            continue
        rid = str(f.get("rule_id") or "-")
        g = grp.setdefault(rid, {"rule_id": rid, "tp": 0, "fp": 0,
                                 "fragment_ids": [], "hosts": set()})
        if cls == "TP":
            g["tp"] += 1
        else:
            g["fp"] += 1
        g["fragment_ids"].append(f["fragment_id"])
        g["hosts"].add(str(f.get("host") or "-"))
    out = []
    for rid, g in grp.items():
        total = g["tp"] + g["fp"]
        if total >= min_size and g["fp"] / total >= fp_ratio:
            out.append({
                "kind": "fp_noise",
                "rule_id": rid,
                "rule_desc": "",
                "fp_ratio": round(g["fp"] / total, 3),
                "support": total,
                "fragment_ids": g["fragment_ids"],
                "hosts": sorted(g["hosts"]),
            })
    out.sort(key=lambda c: -c["support"])
    return out


class PatternMiner:
    """模式挖掘器：跑一次 → 将候选落库为可疑模式（含审计），返回新模式列表。"""

    def __init__(self, store: MemoryStore, llm=None, kb=None,
                 max_llm: int = 8, min_noise: int = 3):
        self.store = store
        self.llm = llm                       # LLMClient or None(启发式)
        self.kb = kb                         # KnowledgeKB or None
        self.max_llm = max_llm
        self.min_noise = min_noise

    # ---------------------------------------------------------- LLM 归纳
    def _induce(self, cand: dict) -> Optional[dict]:
        """对 behavior 候选做 LLM 归纳；失败/不可用返回 None（调用方启发式）。"""
        if self.llm is None or not getattr(self.llm, "available", False):
            return None
        frag_text = []
        for m in cand["members"][:8]:
            s = m.get("summary") or ""
            frag_text.append(f"- [{m.get('host')} rule{m.get('rule_id')}] {s[:240]}")
        user = (
            f"[数据集] {cand['dataset']}\n"
            f"[主机] {cand['host']}\n"
            f"[时间跨度] {int((cand['ts_to'] - cand['ts_from']) / 1000)} 秒，共 {cand['support']} 条告警，"
            f"涉及规则: {', '.join(map(str, cand['rule_ids']))}\n"
            f"[片段摘要]\n" + "\n".join(frag_text)
        )
        try:
            return self.llm.complete(system=SYSTEM_INDUCE, user=user)
        except Exception as exc:  # noqa: BLE001  LLM 失败走启发式，不阻塞基线
            print(f"[miner] LLM 归纳失败（启发式兜底）: {type(exc).__name__}: {exc}")
            return None

    # ---------------------------------------------------------- 启发式兜底
    @staticmethod
    def _fallback(cand: dict) -> dict:
        descs = []
        levels = []
        mitre = set()
        for m in cand["members"]:
            d = (m.get("source") or {}).get("rule_hits") or []
            if d:
                descs.append(d[0].get("description") or "")
                lv = d[0].get("level")
                if lv:
                    levels.append(int(lv))
            for tech in ((m.get("mitre") or {}).get("technique") or []) + \
                        ((m.get("mitre") or {}).get("techniques") or []):
                mitre.add(str(tech))
        descs = list(dict.fromkeys(x for x in descs if x))
        lv = max(levels) if levels else None
        return {
            "title": f"行为链：{cand['host']} 短时 {len(cand['rule_ids'])} 条规则共现",
            "description": ("主机 {host} 在 {span} 秒内连续触发 {n} 条不同规则（{rules}），"
                            "呈现多步可疑行为特征。涉及规则描述：{descs}").format(
                host=cand["host"], span=(cand["ts_to"] - cand["ts_from"]) // 1000,
                n=len(cand["rule_ids"]), rules="/".join(cand["rule_ids"]),
                descs="；".join(descs[:3]) or "-"),
            "mitre_techniques": sorted(mitre)[:8],
            "mitre_tactics": [],
            "severity": level_sev(lv) if lv else "medium",
            "confidence": round(min(0.99, 0.5 + 0.05 * len(cand["rule_ids"])), 2),
            "llm": False,
        }

    # ---------------------------------------------------------- 幂等辅助
    @staticmethod
    def _fp(kind: str, rule_ids) -> str:
        """指纹序列化（可 JSON 持久化）。"""
        return f"{kind}|" + ",".join(sorted(str(r) for r in rule_ids))

    def _is_rejected(self, existing: set, rejected: set, kind: str, rule_ids) -> bool:
        fp = self._fp(kind, rule_ids)
        return fp in rejected or (kind, frozenset(rule_ids)) in existing

    def _remember_reject(self, key: str, rejected: set, kind: str, rule_ids) -> None:
        """把 LLM 判否的候选指纹持久化，避免后续启发式跑批"复活"噪声候选。"""
        fp = self._fp(kind, rule_ids)
        rejected.add(fp)
        self.store.evo_set(key, sorted(rejected))

    # ---------------------------------------------------------- 主入口
    def mine(self, dataset: str) -> list[dict]:
        frags = self.store.fragments(dataset=dataset, limit=10_000_000)
        if not frags:
            return []
        created: list[dict] = []
        budget = self.max_llm
        date = datetime.datetime.now().strftime("%Y%m%d")
        n_seq = len(self.store.patterns(dataset=dataset))
        # 已有模式指纹 + 历史拒绝指纹（幂等：同特征不重复挖掘/不复活 LLM 判否候选）
        existing = set()
        for p in self.store.patterns(dataset=dataset):
            if p.get("state") == "superseded":
                continue
            existing.add((p.get("kind"), frozenset(p.get("rule_ids") or [])))
        skip_key = f"miner.reject.{dataset}"
        rejected = set(self.store.evo_get(skip_key, []) or [])

        # 1) behavior 行为链（LLM 优先用于支撑最大的候选）
        chains = chain_candidates(frags)
        for cand in chains:
            if self._is_rejected(existing, rejected, "behavior", cand["rule_ids"]):
                continue
            n_seq += 1
            induced = None
            if budget > 0:
                induced = self._induce(cand)
                if induced is not None:
                    budget -= 1          # 有界：每次真实 LLM 调用都扣预算（无论是否采纳）
            if induced is None:
                induced = self._fallback(cand)
                induced["llm"] = False
            else:
                if not induced.get("meaningful", True):
                    self.store.audit("pattern", "-", "miner.skip", "system",
                                     f"LLM 判定候选无意义：{cand['host']} {cand['rule_ids']}")
                    self._remember_reject(skip_key, rejected, "behavior", cand["rule_ids"])
                    continue
                induced["llm"] = True
            # 图谱解析：候选内 MITRE 技术 → 补全 Tactic
            tactics = []
            kb_tech = induced.get("mitre_techniques") or []
            if self.kb is not None:
                resolved = self.kb.resolve_mitre(kb_tech)
                tac_set = set()
                for t in resolved["techniques"][:5]:
                    for node in self.kb.alert_graph([t["attack_id"]])["techniques"]:
                        for tac in node["tactics"]:
                            tac_set.add(tac["attack_id"])
                tactics = sorted(tac_set)
            pid = f"pat-{dataset}-{date}-{n_seq:04d}"
            p = Pattern(
                pattern_id=pid, dataset=dataset,
                title=induced.get("title", "可疑模式"),
                description=induced.get("description", ""),
                kind="behavior", state="active",
                confidence=float(induced.get("confidence", 0.8)),
                hits=cand["support"],
                supporting_fragment_ids=cand["fragment_ids"],
                rule_ids=cand["rule_ids"],
                mitre_techniques=list(dict.fromkeys(induced.get("mitre_techniques") or [])),
                mitre_tactics=tactics or list(dict.fromkeys(induced.get("mitre_tactics") or [])),
                meta={"llm": bool(induced.get("llm")), "mined_by": "miner.v1",
                      "host": cand.get("host"), "ts_from": cand.get("ts_from"),
                      "ts_to": cand.get("ts_to"), "llm_meta": induced.get("_llm_meta")},
            )
            self.store.add_pattern(p)
            self.store.audit("pattern", pid, "miner.create", "system",
                             f"行为链模式：{p.title}（{p.hits} 片段 / {len(p.rule_ids)} 规则）"
                             + ("，LLM 归纳" if induced.get("llm") else "，启发式归纳"))
            created.append(p.model_dump())

        # 2) fp_noise 高误报降噪提议
        for cand in fp_noise_candidates(frags, min_size=self.min_noise):
            if self._is_rejected(existing, rejected, "fp_noise", [cand["rule_id"]]):
                continue
            n_seq += 1
            pid = f"pat-{dataset}-{date}-{n_seq:04d}"
            p = Pattern(
                pattern_id=pid, dataset=dataset,
                title=f"高误报：规则 {cand['rule_id']} 告警多为 FP",
                description=f"规则 {cand['rule_id']} 在 {cand['support']} 次片段中 FP 占比 "
                            f"{cand['fp_ratio']:.0%}（主机 {', '.join(cand['hosts'][:5])}），"
                            f"建议降噪：调低衍生匹配严重度或抑制。",
                kind="fp_noise", state="active",
                confidence=round(cand["fp_ratio"], 3), hits=cand["support"],
                supporting_fragment_ids=cand["fragment_ids"],
                rule_ids=[cand["rule_id"]],
                meta={"mined_by": "miner.v1", "fp_ratio": cand["fp_ratio"]},
            )
            self.store.add_pattern(p)
            self.store.audit("pattern", pid, "miner.create", "system", f"降噪模式：{p.title}")
            created.append(p.model_dump())
        return created
