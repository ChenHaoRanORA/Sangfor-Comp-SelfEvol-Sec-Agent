# -*- coding: utf-8 -*-
"""演示数据层：Agent 事件 JSONL(处置结果) + 源告警 JSONL(原始细节) 的加载、合并、前端映射与聚合。

前端（Vue3/大屏）当前为纯 Mock 数据，本模块按前端 src/api/types.ts 契约产出 JSON，
供 FastAPI REST 与 WebSocket 消费：dashboard / alert / rule 三种形状 + 复核/规则编辑的内存 overlay。
"""
from __future__ import annotations

import io
import json
import math
import os
from collections import Counter, defaultdict
from typing import Any, Optional

PROCESSED = os.path.join("data", "processed")

# 演示可用数据源：事件文件 + 源告警文件（用于补齐文本/主机/MITRE 等原始细节）
SOURCES = {
    "llm-soc": {
        "label": "llm-soc 178 · DeepSeek 实判",
        "events": os.path.join("log", "agent_v1_llm_soc_full_178.jsonl"),
        "alerts": os.path.join(PROCESSED, "llm_soc_alerts.jsonl"),
    },
    "linux": {
        "label": "linux 9,357 · 规则回退(offline)",
        "events": os.path.join("log", "agent_v1_linux_full_offline.jsonl"),
        "alerts": os.path.join(PROCESSED, "linux_apt_alerts.jsonl"),
    },
}

_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
SEV_CAPS = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}


def _cap(s: Any) -> str:
    return SEV_CAPS.get(str(s or "").strip().lower(), "Low")


def _lst(v: Any) -> list:
    if v is None:
        return []
    if isinstance(v, list):
        return [x for x in v if x is not None]
    return [v]


def _mitre_parts(m: Optional[dict]) -> tuple[list, list]:
    """统一 mitre 三种键位写法 → (techniques, tactics)。"""
    if not m:
        return [], []
    tech = m.get("technique", m.get("techniques")) or ([] if "id" not in m else [m["id"]])
    tact = m.get("tactic", m.get("tactics"))
    return _lst(tech), _lst(tact)


def _num_id(v: Any):
    if v is None:
        return ""
    try:
        return int(v)
    except (TypeError, ValueError):
        return str(v)


def _sev_from_level(level: Optional[int]) -> str:
    lv = int(level or 0)
    if lv >= 12:
        return "Critical"
    if lv >= 7:
        return "High"
    if lv >= 4:
        return "Medium"
    return "Low"


def _load_jsonl(path: str) -> list[dict]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"缺失数据文件: {path}")
    out = []
    with io.open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def _utc_hour(ms: Optional[int]) -> int:
    if not ms:
        return -1
    return int(ms // 3600_000) % 24


class DemoSource:
    """一份数据源：合并事件与源告警，产出『前端告警行』及全量聚合。"""

    def __init__(self, name: str):
        conf = SOURCES[name]
        self.name = name
        self.label = conf["label"]
        self._sev_cache: dict[int, str] = {}
        events = _load_jsonl(conf["events"])
        base = _load_jsonl(conf["alerts"])
        # 事件与源告警按 seq(1 基) 对齐；不一致时回退 (dataset, alert_id)
        if len(events) == len(base):
            base_by_seq = {i + 1: b for i, b in enumerate(base)}
            self.rows = [self._merge(ev, base_by_seq.get(ev.get("seq"))) for ev in events]
        else:
            bmap: dict[str, dict] = {}
            for b in base:
                bmap[(b.get("dataset"), str(b.get("alert_id")))] = b
            self.rows = [self._merge(ev, bmap.get((ev.get("dataset"), str(ev.get("alert_id"))))) for ev in events]

        self._severity_counts: Counter = Counter()
        self._rule_agg: dict[str, dict] = {}
        self._decoder_counts: Counter = Counter()
        self._host_agg: dict[str, dict] = {}
        self._hour_counts: Counter = Counter()
        self._cls: Counter = Counter()
        self._summarize()

    # ---------- 行结构 ----------
    def _merge(self, ev: dict, b: Optional[dict]) -> dict:
        ev = ev or {}
        b = b or {}
        r: dict[str, Any] = dict(ev)
        r["base"] = b
        agent = b.get("agent") or {}
        name = (ev.get("agent_name")) or agent.get("name") or "-"
        r["agent_name"] = name
        r["agent_ip"] = agent.get("ip") or agent.get("id") or ""
        r["agent_os"] = agent.get("os") or (b.get("os") or "linux")
        rule = b.get("rule") or {}
        r["rule_id"] = _num_id(rule.get("id"))
        r["rule_level"] = rule.get("level")
        r["rule_desc"] = rule.get("description") or ""
        r["rule_groups"] = _lst(rule.get("groups"))
        r["mitre"] = b.get("mitre") or None
        r["text"] = b.get("text") or ""
        dec = b.get("decoder") or {}
        r["decoder"] = (dec.get("name") if isinstance(dec, dict) else None) or b.get("location") or ev.get("index") or "unknown"
        r["program"] = b.get("program") or ""
        r["ts"] = ev.get("ts_ms") or (b.get("time") or {}).get("ms")
        return r

    @property
    def rows_asc(self) -> list[dict]:
        return sorted([r for r in self.rows if r.get("ts")], key=lambda x: x["ts"])

    # ---------- 聚合（全量文件快照） ----------
    def _summarize(self) -> None:
        cls = Counter()
        dec = Counter()
        hour = Counter()
        hosts: dict[str, dict] = {}
        rule_agg: dict[str, dict] = {}
        for r in self.rows:
            sev = self.severity_of(r)
            self._severity_counts[sev] += 1
            v = r.get("verdict") or {}
            cls[str(v.get("classification") or "None")] += 1
            dec[r.get("decoder") or "-"] += 1
            hour[_utc_hour(r.get("ts"))] += 1
            hn = r.get("agent_name") or "-"
            h = hosts.setdefault(hn, {"name": hn, "os": r.get("agent_os") or "", "ip": r.get("agent_ip") or "",
                                      "last": r.get("ts") or 0, "alerts": 0})
            h["alerts"] += 1
            h["last"] = max(h["last"], r.get("ts") or 0)
            hits = r.get("rule_hits") or []
            for hit in hits:
                rid = str(hit.get("rule_id") or "?")
                g = rule_agg.setdefault(rid, {
                    "rule_id": rid, "name": "", "description": "", "level": None,
                    "groups": [], "fired": 0, "last": None, "first": None, "hours": Counter(),
                })
                g["fired"] += 1
                if g["level"] is None:
                    g["level"] = hit.get("level")
                g["name"] = g["name"] or (hit.get("description") or "")
                g["description"] = g["description"] or (hit.get("description") or "")
                g["groups"] = g["groups"] or _lst(hit.get("groups"))
                g["last"] = max(g["last"], r.get("ts") or 0) if g["last"] is not None else (r.get("ts") or 0)
                g["first"] = min(g["first"], r.get("ts") or 0) if g["first"] is not None else (r.get("ts") or 0)
                g["hours"][_utc_hour(r.get("ts"))] += 1
            if not hits:  # 未命中规则也计一次伪命中，保证规则面板可看到来源
                self._unmatched = self._unmatched + 1 if hasattr(self, "_unmatched") else 1
        self._cls = cls
        self._decoder_counts = dec
        self._hour_counts = hour
        self._host_agg = hosts
        # 规则命中聚合的名称回填：命中条目可能无描述，用源告警规则描述补
        row_desc: dict[str, str] = {}
        for r in self.rows:
            if r.get("rule_desc") and r.get("rule_id") not in ("", None):
                row_desc.setdefault(str(r["rule_id"]), r["rule_desc"])
        for rid, g in rule_agg.items():
            if not g["name"] and rid in row_desc:
                g["name"] = g["description"] = row_desc[rid]
        self._rule_agg = {rid: {**g, "hours": dict(g["hours"])} for rid, g in rule_agg.items()}
        self._fired_total = sum(g["fired"] for g in self._rule_agg.values())

    # 告警级别：LLM 判定优先；规则回退/无判定按 rule.level 映射
    def severity_of(self, r: dict) -> str:
        key = id(r)
        if key not in self._sev_cache:
            v = r.get("verdict") or {}
            prio = v.get("priority")
            if prio:
                sev = _cap(prio)
            elif r.get("rule_level") is not None:
                sev = _sev_from_level(r["rule_level"])
            else:
                sev = "Low"
            self._sev_cache[key] = sev
        return self._sev_cache[key]

    # ---------- 前端映射 ----------
    def to_front_alert(self, r: dict) -> dict:
        v = r.get("verdict") or {}
        classification = v.get("classification")
        llm_used = bool(v.get("method") == "llm")
        sev = self.severity_of(r)
        techs, tactics = _mitre_parts(r.get("mitre"))
        rule_desc = r.get("rule_desc") or next((h.get("description") for h in (r.get("rule_hits") or []) if h.get("description")), None)
        rid = r.get("rule_id")
        if rid in ("", None) and (r.get("rule_hits") or []):
            rid = r["rule_hits"][0].get("rule_id")
        hit_rules = [{
            "ruleId": str(h.get("rule_id")),
            "ruleType": "manual",
            "name": (h.get("description") or f"规则 {h.get('rule_id')}"),
            "firedTimes": (self._rule_agg.get(str(h.get("rule_id"))) or {}).get("fired", 0),
            "severity": _sev_from_level(h.get("level")),
            "maxTier": "A0",
        } for h in (r.get("rule_hits") or [])]
        if not hit_rules:
            hit_rules = [{
                "ruleId": str(rid or "-"), "ruleType": "manual",
                "name": rule_desc or f"规则 {rid}", "firedTimes": 0,
                "severity": sev, "maxTier": "A0",
            }]
        alert = {
            "id": str(r.get("alert_id") or r.get("seq")),
            "ts": r.get("ts"),
            "source": "eval" if self.name == "llm-soc" else "replay",
            "agent": {"name": r.get("agent_name"), "ip": r.get("agent_ip"), "os": r.get("agent_os")},
            "decoder": r.get("decoder") or "-",
            "family": (r.get("program") or (r.get("rule_groups") or ["-"])[0]),
            "severity": sev,
            "raw": (r.get("text") or "")[:4000],
            "rule": {
                "id": rid,
                "level": r.get("rule_level"),
                "groups": _lst(r.get("rule_groups")),
                "description": rule_desc or f"规则 {rid}" or "-",
                "mitreTechniques": techs,
                "mitreTactics": tactics,
            },
            "rule_hits": r.get("rule_hits") or [],
            "verdict": None,
            "status": "open",
            "hitRules": hit_rules,
            "relatedPatterns": [],
            "relatedFragments": [],
            "actionIds": [],
        }
        # 已复核 overlay 或 LLM 结论 → 输出 verdict
        rev = self.reviews.get(str(r.get("alert_id")))
        if classification in ("TP", "FP") or rev:
            cls_out = (rev or {}).get("cls", classification)
            just = v.get("justification") or ""
            if rev:
                just = (just + " ") if just else ""
                just += f"（人工复核：{cls_out}，{rev.get('by', 'analyst')}"
                if rev.get("reason"):
                    just += f"：{rev['reason']}"
                just += "）"
            alert["verdict"] = {
                "classification": cls_out,
                "priority": _cap((rev or {}).get("prio") or v.get("priority") or "low"),
                "justification": just,
                "model": (v.get("_llm_meta") or {}).get("model") if llm_used else "规则结论",
                "reviewedBy": (rev or {}).get("by"),
            }
            if rev:
                alert["status"] = "reviewed"
        return alert

    # 复核内存 overlay
    reviews: dict[str, dict] = {}

    # ---------- 对外查询 ----------
    def query_alerts(self, keyword="", severity="", verdict="", source="", status="",
                     page=1, size=20) -> dict:
        rows = sorted(self.rows, key=lambda r: -(r.get("ts") or 0))
        if severity:
            rows = [r for r in rows if self.severity_of(r) == severity]
        if source:
            rows = [r for r in rows if ("eval" if self.name == "llm-soc" else "replay") == source]
        if verdict:
            def vcls(r):
                return (r.get("verdict") or {}).get("classification")
            if verdict == "unknown":
                rows = [r for r in rows if vcls(r) not in ("TP", "FP")]
            else:
                rows = [r for r in rows if vcls(r) == verdict]
        if status:
            rows = [r for r in rows if ("reviewed" if str(r.get("alert_id")) in self.reviews else "open") == status]
        if keyword:
            kw = keyword.lower()
            def hit_kw(r):
                base = " ".join([
                    str(r.get("alert_id")), str(r.get("agent_name")),
                    r.get("agent_ip"), r.get("text"), r.get("rule_desc"),
                    " ".join(r.get("rule_groups") or []), " ".join(_mitre_parts(r.get("mitre"))[0]),
                ]).lower()
                return kw in base
            rows = [r for r in rows if hit_kw(r)]
        total = len(rows)
        items = [self.to_front_alert(r) for r in rows[(page - 1) * size: page * size]]
        return {"total": total, "items": items}

    def alert_row(self, alert_id: str) -> Optional[dict]:
        """定位合并后的原始行（供复核写回记忆 / 证据检索等使用）。"""
        for r in self.rows:
            if str(r.get("alert_id")) == alert_id or str(r.get("seq")) == alert_id:
                return r
        return None

    def alert_detail(self, alert_id: str) -> Optional[dict]:
        for r in self.rows:
            if str(r.get("alert_id")) == alert_id or str(r.get("seq")) == alert_id:
                return self.to_front_alert(r)
        return None

    def review(self, alert_id: str, cls: str, by: str = "analyst",
               reason: str = "", priority: str = "") -> Optional[dict]:
        """人工复核：写内存 overlay（含理由/优先级）；记忆写回由服务端 memory_api 负责。"""
        if self.alert_row(alert_id) is None:
            return None
        self.reviews[str(alert_id)] = {"cls": cls, "by": by, "reason": reason or "",
                                       "prio": priority or "", "ts": _now_ms()}
        return self.alert_detail(alert_id)

    # ---------- dashboard ----------
    def dashboard(self) -> dict:
        n = len(self.rows)
        c = self._severity_counts
        rules = self.rule_items()
        hosts = sorted(self._host_agg.values(), key=lambda h: -h["alerts"])
        recent = sorted(self.rows, key=lambda r: -(r.get("ts") or 0))[:30]
        fe_rules = self.rule_items()
        hourly = [{
            "label": f"{h:02d}:00",
            "cur": self._hour_counts.get(h, 0),
            "prev": 0,
        } for h in range(24)]
        return {
            "overview": {
                "todayTotal": n,
                "critical": c.get("Critical", 0), "high": c.get("High", 0),
                "medium": c.get("Medium", 0), "low": c.get("Low", 0),
                "openReview": len(self.reviews),
                "pendingApprovals": 0,
                "hostsTotal": len(hosts), "hostsOnline": len(hosts),
                "rulesActive": len(rules),
                "firedToday": self._fired_total,
                "tpToday": self._cls.get("TP", 0), "fpToday": self._cls.get("FP", 0),
            },
            "hourly": hourly,
            "sevDist": [{"severity": s, "count": c.get(s, 0)} for s in ("Critical", "High", "Medium", "Low")],
            "decoderDist": [{"name": k, "count": v} for k, v in self._decoder_counts.most_common(8)],
            "topRules": fe_rules[:10],
            "hosts": [{
                "name": h["name"], "ip": h["ip"], "os": h["os"],
                "role": h["os"], "status": "online",
                "lastSeen": h["last"], "alertToday": h["alerts"],
            } for h in hosts],
            "recentAlerts": [self.to_front_alert(r) for r in recent],
        }

    # ---------- 规则 overlay（内存，人工 CUD 均留存审计） ----------
    def _rule_to_fe(self, g: dict, window: int = 0) -> dict:
        hours = g.get("hours") or {}
        series = [hours.get(h, 0) for h in range(24)]
        if window:
            series = series[-window:] + [0] * max(0, window - len(series))
        sev = _sev_from_level(g.get("level"))
        return {
            "ruleId": g["rule_id"],
            "ruleType": "manual",
            "name": (g.get("name") or f"规则 {g['rule_id']}")[:120],
            "description": (g.get("description") or "")[:400],
            "enabled": self.rule_enabled.get(g["rule_id"], True),
            "state": "paused" if self.rule_enabled.get(g["rule_id"], True) is False else "active",
            "severity": sev,
            "expression": json.dumps({"field": "rule.id", "op": "eq", "value": g["rule_id"]}, ensure_ascii=False),
            "actionPolicy": {"maxTier": "A0", "allow": []},
            "firedTimes": g["fired"],
            "hits24": g["fired"],
            "series": series,
            "lastTriggeredAt": g.get("last"),
            "owner": "system(数据集规则)",
            "createdAt": g.get("first"),
            "updatedAt": g.get("last"),
            "revision": 1,
            "audit": [{"ts": g.get("first") or 0, "op": "dataset.import", "by": "system",
                       "note": f"由数据集按 rule_id 自动导入（{self.label}），仅人工可修改。"}],
            "auto": False,
            "hits": g["fired"],
        }

    rule_enabled: dict[str, bool] = {}

    def rule_items(self) -> list[dict]:
        items = [self._rule_to_fe(g) for g in self._rule_agg.values()]
        overlay = self.rule_overlay.get(self.name, {})
        for rid, over in overlay.items():
            for it in items:
                if it["ruleId"] == rid:
                    it.update(over)
                    break
            else:
                # 纯 overlay 条目（人工新建 / 由自进化规则升格）也要在人工规则池可见
                items.append(dict(over))
        items.sort(key=lambda x: -x["firedTimes"])
        return items

    rule_overlay: dict[str, dict[str, dict]] = defaultdict(dict)

    def rule_get(self, rule_id: str) -> Optional[dict]:
        for it in self.rule_items():
            if it["ruleId"] == rule_id:
                return it
        return None

    def rule_set(self, rule_id: str, **fields) -> Optional[dict]:
        cur = self.rule_get(rule_id)
        if cur is None:
            return None
        rev = cur.get("revision", 1) + 1
        audit = list(cur.get("audit") or [])
        patch: dict = {}
        if "enabled" in fields:
            patch["enabled"] = bool(fields["enabled"])
            patch["state"] = "active" if patch["enabled"] else "paused"
            audit.append({"ts": _now_ms(), "op": "manual." + ("enable" if patch["enabled"] else "disable"),
                          "by": "analyst", "note": f"启用状态 → {patch['enabled']}"})
        if fields.get("name") is not None:
            patch["name"] = fields["name"]
        if fields.get("description") is not None:
            patch["description"] = fields["description"]
        if fields.get("severity") is not None:
            patch["severity"] = fields["severity"]
        if fields.get("expr") is not None:
            patch["expression"] = fields["expr"]
        if fields.get("tier") is not None:
            patch["actionPolicy"] = {"maxTier": fields["tier"], "allow": fields.get("allow") or []}
        patch["revision"] = rev
        patch["updatedAt"] = _now_ms()
        patch["audit"] = audit
        self.rule_overlay[self.name].setdefault(rule_id, {}).update(patch)
        return self.rule_get(rule_id)

    def rule_create(self, data: dict) -> dict:
        rid = data.get("ruleId") or f"manual-{_now_ms()}"
        sev = data.get("severity") or "Medium"
        rule_id = rid
        # overlay 独立存一份完整定义
        item = {
            "ruleId": rule_id,
            "ruleType": "manual",
            "name": data.get("name") or rule_id,
            "description": data.get("description") or "",
            "enabled": True,
            "state": "active",
            "severity": sev,
            "expression": data.get("expr") or data.get("expression") or "{}",
            "actionPolicy": {"maxTier": data.get("tier") or "A0", "allow": data.get("allow") or []},
            "firedTimes": 0,
            "series": [0] * 24,
            "lastTriggeredAt": None,
            "owner": "analyst",
            "createdAt": _now_ms(),
            "updatedAt": _now_ms(),
            "revision": 1,
            "audit": [{"ts": _now_ms(), "op": "manual.create", "by": "analyst", "note": "手工/NL 创建的人工规则。"}],
            "auto": False,
        }
        self.rule_overlay[self.name][rule_id] = item
        return item

    def rule_delete(self, rule_id: str) -> bool:
        if rule_id in self.rule_overlay[self.name]:
            del self.rule_overlay[self.name][rule_id]
            return True
        # 从聚合中剔除（enable=false 语义）—— 演示采用 enabled=false 挂起而非真删
        self.rule_enabled[rule_id] = False
        return True

    def rule_promote_register(self, fe: dict) -> dict:
        """把一份（记忆库已升格的）规则登记进演示人工规则池。

        保留记忆侧字段（firedTimes/sourcePatternId/confidence/审计），ruleType 改人工，
        供规则页『人工规则』Tab 展示与后续人工启停/编辑（权威边界：人工可直接治理）。
        """
        rid = fe.get("ruleId")
        if rid is None:
            raise ValueError("缺少 ruleId")
        item = dict(fe)
        item["ruleType"] = "manual"
        item["auto"] = False
        item.setdefault("enabled", True)
        item["state"] = "active" if item.get("enabled") else "paused"
        item["audit"] = list(fe.get("audit") or [])
        item.setdefault("series", [0] * 24)
        item["updatedAt"] = _now_ms()
        self.rule_overlay[self.name][rid] = item
        return item


def _now_ms() -> int:
    import time
    return int(time.time() * 1000)


class DemoStore:
    """按名字持有多个 DemoSource。"""

    def __init__(self):
        self.sources: dict[str, DemoSource] = {}

    def get(self, name: str) -> DemoSource:
        if name not in self.sources:
            self.sources[name] = DemoSource(name)
        return self.sources[name]

    def available(self) -> list[str]:
        return [k for k in SOURCES if os.path.exists(SOURCES[k]["events"])]


store = DemoStore()
