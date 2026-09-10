# -*- coding: utf-8 -*-
"""多层记忆存储：SQLite（片段/模式/衍生规则/审计/演化总开关）+ Chroma（片段向量）。

- 业务代码不直接拼 SQL，统一经 MemoryStore；
- Chroma 仅在需要向量能力时惰性打开（未安装/不可用时降级为普通 SQLite，不影响基线主链）；
- 片段低风险可随时写；可疑模式/衍生规则全部带审计，受"自动演化总开关"约束（可在 CLI/后端关）。
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Any, Iterable, Optional

from src.core.memory.models import Fragment, Pattern, now_ms

BASE_DIR = os.path.join("data", "memory")
DB_PATH = os.path.join(BASE_DIR, "memory.db")
CHROMA_DIR = os.path.join(BASE_DIR, "chroma")
FRAGMENT_COLLECTION = "fragments"


def _j(v: Any) -> str:
    return json.dumps(v, ensure_ascii=False, default=str)


def _u(v: Optional[str], default: Any = None):
    if v is None:
        return default
    return json.loads(v)


_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS fragment(
        fragment_id TEXT PRIMARY KEY,
        dataset TEXT, alert_id TEXT, seq INTEGER,
        host TEXT, ts_ms INTEGER,
        rule_id TEXT, rule_level INTEGER, groups TEXT,
        mitre TEXT, classification TEXT, verdict_priority TEXT,
        method TEXT, llm_error INTEGER, summary TEXT,
        source TEXT, created_at INTEGER)""",
    "CREATE INDEX IF NOT EXISTS idx_frag_rule ON fragment(dataset, rule_id)",
    "CREATE INDEX IF NOT EXISTS idx_frag_host_ts ON fragment(dataset, host, ts_ms)",
    "CREATE INDEX IF NOT EXISTS idx_frag_seq ON fragment(dataset, seq)",
    """CREATE TABLE IF NOT EXISTS pattern(
        pattern_id TEXT PRIMARY KEY,
        dataset TEXT, title TEXT, description TEXT, kind TEXT, state TEXT,
        confidence REAL, hits INTEGER,
        supporting_fragment_ids TEXT, rule_ids TEXT,
        mitre_techniques TEXT, mitre_tactics TEXT,
        derived_rule_id TEXT, meta TEXT,
        created_at INTEGER, updated_at INTEGER)""",
    "CREATE INDEX IF NOT EXISTS idx_pattern_state ON pattern(dataset, state)",
    """CREATE TABLE IF NOT EXISTS rule(
        rule_id TEXT PRIMARY KEY, rule_type TEXT,
        name TEXT, description TEXT,
        enabled INTEGER, state TEXT, expression TEXT, severity TEXT,
        action_policy TEXT, source_pattern_id TEXT,
        fired_times INTEGER, last_triggered_at INTEGER,
        owner TEXT, created_at INTEGER, updated_at INTEGER,
        revision INTEGER, auto INTEGER, audit TEXT)""",
    "CREATE INDEX IF NOT EXISTS idx_rule_type_state ON rule(rule_type, state)",
    """CREATE TABLE IF NOT EXISTS audit(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER, scope TEXT, obj_id TEXT, op TEXT, by TEXT, note TEXT)""",
    "CREATE INDEX IF NOT EXISTS idx_audit_obj ON audit(scope, obj_id)",
    """CREATE TABLE IF NOT EXISTS evo(k TEXT PRIMARY KEY, v TEXT)""",
]


class MemoryStore:
    def __init__(self, db_path: str = DB_PATH, chroma_dir: str = CHROMA_DIR):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self.chroma_dir = chroma_dir
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            for ddl in _SCHEMA:
                self._conn.execute(ddl)
            self._conn.commit()
        self._collection = None          # 惰性：chromadb
        self._collection_failed = False

    # ============================================================ 基础
    def _row(self, sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    def _all(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def _exec(self, sql: str, params: tuple = ()) -> None:
        with self._lock:
            self._conn.execute(sql, params)
            self._conn.commit()

    def audit(self, scope: str, obj_id: str, op: str, by: str, note: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit(ts, scope, obj_id, op, by, note) VALUES(?,?,?,?,?,?)",
                (now_ms(), scope, obj_id, op, by, note))
            self._conn.commit()

    def audit_log(self, scope: Optional[str] = None, obj_id: Optional[str] = None,
                  limit: int = 50) -> list[dict]:
        sql, params = "SELECT * FROM audit", []
        cond = []
        if scope:
            cond.append("scope=?")
            params.append(scope)
        if obj_id:
            cond.append("obj_id=?")
            params.append(obj_id)
        if cond:
            sql += " WHERE " + " AND ".join(cond)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        return [dict(r) for r in self._all(sql, tuple(params))]

    # ============================================================ 演化总开关
    def auto_evolve(self, on: Optional[bool] = None) -> bool:
        """读写自动演化总开关。"""
        with self._lock:
            if on is not None:
                self._conn.execute(
                    "INSERT INTO evo(k,v) VALUES('auto_evolve',?) "
                    "ON CONFLICT(k) DO UPDATE SET v=excluded.v", ("1" if on else "0",))
                self._conn.commit()
            row = self._conn.execute(
                "SELECT v FROM evo WHERE k='auto_evolve'").fetchone()
        return (row["v"] if row else "1") == "1"

    def evo_get(self, key: str, default: Any = None):
        """读演化相关键值（miner.skip 指纹等）。"""
        with self._lock:
            row = self._conn.execute("SELECT v FROM evo WHERE k=?", (key,)).fetchone()
        return default if row is None else json.loads(row["v"])

    def evo_set(self, key: str, value: Any) -> None:
        """写演化相关键值。"""
        with self._lock:
            self._conn.execute(
                "INSERT INTO evo(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                (key, json.dumps(value, ensure_ascii=False)))
            self._conn.commit()

    # ============================================================ 片段
    def add_fragments(self, frags: Iterable[Fragment], embed: bool = True) -> int:
        """批量写入片段（幂等：按 fragment_id 跳过重复）；embed 时同步入向量库。"""
        frags = list(frags)
        if not frags:
            return 0
        fresh: list[Fragment] = []
        seen: set[str] = set()
        with self._lock:
            rows = []
            for f in frags:
                if f.fragment_id in seen:
                    continue
                seen.add(f.fragment_id)
                exists = self._conn.execute(
                    "SELECT 1 FROM fragment WHERE fragment_id=?", (f.fragment_id,)).fetchone()
                if exists:
                    continue
                rows.append((
                    f.fragment_id, f.dataset, f.alert_id, f.seq, f.host, f.ts_ms,
                    f.rule_id, f.rule_level, _j(f.groups), _j(f.mitre),
                    f.classification, f.verdict_priority, f.method,
                    1 if f.llm_error else 0, f.summary, _j(f.source), f.created_at))
                fresh.append(f)
            if rows:
                self._conn.executemany(
                    "INSERT OR IGNORE INTO fragment(fragment_id, dataset, alert_id, seq, host, "
                    "ts_ms, rule_id, rule_level, groups, mitre, classification, verdict_priority, "
                    "method, llm_error, summary, source, created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
                self._conn.commit()
        if embed and fresh and self._try_embed_fragments(fresh):
            pass
        return len(fresh)

    def upsert_fragments(self, frags: Iterable[Fragment], embed: bool = True) -> int:
        """幂等覆盖写片段：同 fragment_id 已存在则整行更新（复核更正/feedback 场景）。

        与 add_fragments（纯跳过）互补：向量侧按 id upsert 覆盖，保证 SQLite/Chroma 一致。
        返回写入或更新的条数。
        """
        frags = list(frags)
        if not frags:
            return 0
        touched: list[Fragment] = []
        with self._lock:
            for f in frags:
                self._conn.execute(
                    "INSERT INTO fragment(fragment_id, dataset, alert_id, seq, host, ts_ms, "
                    "rule_id, rule_level, groups, mitre, classification, verdict_priority, "
                    "method, llm_error, summary, source, created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(fragment_id) DO UPDATE SET "
                    "dataset=excluded.dataset, alert_id=excluded.alert_id, seq=excluded.seq, "
                    "host=excluded.host, ts_ms=excluded.ts_ms, rule_id=excluded.rule_id, "
                    "rule_level=excluded.rule_level, groups=excluded.groups, mitre=excluded.mitre, "
                    "classification=excluded.classification, verdict_priority=excluded.verdict_priority, "
                    "method=excluded.method, llm_error=excluded.llm_error, summary=excluded.summary, "
                    "source=excluded.source, created_at=excluded.created_at",
                    (f.fragment_id, f.dataset, f.alert_id, f.seq, f.host, f.ts_ms,
                     f.rule_id, f.rule_level, _j(f.groups), _j(f.mitre),
                     f.classification, f.verdict_priority, f.method,
                     1 if f.llm_error else 0, f.summary, _j(f.source), f.created_at))
                touched.append(f)
            self._conn.commit()
        if embed and touched and self._try_embed_fragments(touched):
            pass
        return len(touched)

    def _collection_ref(self):
        if self._collection is not None:
            return self._collection
        if self._collection_failed:
            return None
        try:
            import chromadb
            os.makedirs(self.chroma_dir, exist_ok=True)
            client = chromadb.PersistentClient(path=self.chroma_dir)
            self._collection = client.get_or_create_collection(
                FRAGMENT_COLLECTION, metadata={"hnsw:space": "cosine"})
        except Exception as exc:  # noqa: BLE001  chromadb 未装/网络取模型失败 → 降级
            print(f"[memory] Chroma 不可用，向量检索降级为 SQLite: {type(exc).__name__}: {exc}")
            self._collection_failed = True
        return self._collection

    _EMBED_BATCH = 400   # chromadb 单次 upsert/query 批上限（约 5k），按安全值分批

    def _try_embed_fragments(self, frags: list[Fragment]) -> bool:
        col = self._collection_ref()
        if col is None:
            return False
        ok = True
        try:
            for i in range(0, len(frags), self._EMBED_BATCH):
                part = frags[i:i + self._EMBED_BATCH]
                col.upsert(
                    ids=[f.fragment_id for f in part],
                    documents=[f.embed_text for f in part],
                    metadatas=[{"dataset": f.dataset, "rule_id": f.rule_id or "-",
                                "host": f.host, "classification": f.classification or "-",
                                "ts_ms": f.ts_ms or 0} for f in part])
        except Exception as exc:  # noqa: BLE001
            print(f"[memory] 向量写入失败（回退 SQLite）: {type(exc).__name__}: {exc}")
            self._collection_failed = True
            ok = False
        return ok

    def embed_all(self, dataset: Optional[str] = None) -> int:
        """把已有片段补齐向量（用于首次嵌入分批失败/降级后重试）。"""
        col = self._collection_ref()
        if col is None:
            return 0
        rows = self.fragments(dataset=dataset, limit=10_000_000)
        if not rows:
            return 0
        self._collection_failed = False      # 允许降级后重试
        n = 0
        for i in range(0, len(rows), self._EMBED_BATCH):
            part = rows[i:i + self._EMBED_BATCH]
            try:
                col.upsert(
                    ids=[r["fragment_id"] for r in part],
                    documents=[str(r.get("summary") or "") for r in part],
                    metadatas=[{"dataset": r.get("dataset") or "-",
                                "rule_id": r.get("rule_id") or "-",
                                "host": r.get("host") or "-",
                                "classification": r.get("classification") or "-",
                                "ts_ms": r.get("ts_ms") or 0} for r in part])
                n += len(part)
            except Exception as exc:  # noqa: BLE001
                print(f"[memory] embed_all 批次失败: {type(exc).__name__}: {exc}")
                self._collection_failed = True
                break
        return n

    def count_fragments(self, dataset: Optional[str] = None) -> int:
        sql, params = "SELECT COUNT(*) c FROM fragment", []
        if dataset:
            sql += " WHERE dataset=?"
            params.append(dataset)
        return int(self._row(sql, tuple(params))["c"])

    def fragment_seqs(self) -> dict[str, int]:
        """全量 fragment_id → seq 映射（供流式切分：只让"当前时刻之前"的片段参与检索/模式）。"""
        return {r["fragment_id"]: r["seq"] for r in self._all("SELECT fragment_id, seq FROM fragment", ())}

    def _frag_row_to_dict(self, r: sqlite3.Row) -> dict:
        d = dict(r)
        d["groups"] = _u(d.get("groups"), [])
        d["mitre"] = _u(d.get("mitre"), None)
        d["source"] = _u(d.get("source"), None)
        d["llm_error"] = bool(d.get("llm_error"))
        return d

    def fragments(self, dataset: Optional[str] = None, rule_id: Optional[str] = None,
                  limit: int = 200, offset: int = 0) -> list[dict]:
        sql = "SELECT * FROM fragment"
        cond, params = [], []
        if dataset:
            cond.append("dataset=?"); params.append(dataset)
        if rule_id:
            cond.append("rule_id=?"); params.append(rule_id)
        if cond:
            sql += " WHERE " + " AND ".join(cond)
        sql += " ORDER BY dataset, seq LIMIT ? OFFSET ?"
        params += [limit, offset]
        return [self._frag_row_to_dict(r) for r in self._all(sql, tuple(params))]

    def fragment_ids_all(self, dataset: Optional[str] = None) -> list[str]:
        sql, params = "SELECT fragment_id FROM fragment", []
        if dataset:
            sql += " WHERE dataset=?"
            params.append(dataset)
        return [r["fragment_id"] for r in self._all(sql, tuple(params))]

    def fragment_by_ids(self, ids: Iterable[str]) -> list[dict]:
        ids = list(ids)
        if not ids:
            return []
        q = ",".join("?" * len(ids))
        rows = self._all(f"SELECT * FROM fragment WHERE fragment_id IN ({q})", tuple(ids))
        by_id = {r["fragment_id"]: self._frag_row_to_dict(r) for r in rows}
        return [by_id[i] for i in ids if i in by_id]

    def search_fragments(self, query: str, k: int = 10,
                         dataset: Optional[str] = None) -> list[dict]:
        """语义检索片段：Chroma 命中后回 SQLite 取全量（降级时按 rule/词命中近似）。"""
        col = self._collection_ref()
        if col is not None:
            try:
                where = {"dataset": dataset} if dataset else None
                res = col.query(query_texts=[query], n_results=k, where=where)
                ids = (res.get("ids") or [[]])[0]
                return self.fragment_by_ids(ids)
            except Exception as exc:  # noqa: BLE001
                print(f"[memory] 向量查询失败，走 SQLite 近似: {type(exc).__name__}: {exc}")
        # SQLite 近似：规则 id + 关键词
        frags = self.fragments(dataset=dataset, limit=5000)
        kw = query.strip().lower()
        scored = []
        for f in frags:
            hay = " ".join([str(f.get("rule_id") or ""), f.get("summary") or "",
                            f.get("host") or ""]).lower()
            s = sum(hay.count(w) for w in kw.split() if w)
            if s:
                scored.append((s, f))
        scored.sort(key=lambda x: -x[0])
        return [f for _, f in scored[:k]]

    # ============================================================ 可疑模式
    def add_pattern(self, p: Pattern) -> str:
        p.created_at = p.created_at or now_ms()
        p.updated_at = p.updated_at or p.created_at
        self._exec(
            "INSERT OR REPLACE INTO pattern(pattern_id, dataset, title, description, kind, "
            "state, confidence, hits, supporting_fragment_ids, rule_ids, mitre_techniques, "
            "mitre_tactics, derived_rule_id, meta, created_at, updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (p.pattern_id, p.dataset, p.title, p.description, p.kind, p.state, p.confidence,
             p.hits, _j(p.supporting_fragment_ids), _j(p.rule_ids),
             _j(p.mitre_techniques), _j(p.mitre_tactics), p.derived_rule_id,
             _j(p.meta), p.created_at, p.updated_at))
        return p.pattern_id

    def _pattern_row(self, r: sqlite3.Row) -> dict:
        d = dict(r)
        for k in ("supporting_fragment_ids", "rule_ids", "mitre_techniques", "mitre_tactics", "meta"):
            d[k] = _u(d.get(k), [])
        return d

    def pattern_by_id(self, pattern_id: str) -> Optional[dict]:
        r = self._row("SELECT * FROM pattern WHERE pattern_id=?", (pattern_id,))
        return self._pattern_row(r) if r else None

    def patterns(self, state: Optional[str] = None,
                 dataset: Optional[str] = None) -> list[dict]:
        sql, cond, params = "SELECT * FROM pattern", [], []
        if state:
            cond.append("state=?"); params.append(state)
        if dataset:
            cond.append("dataset=?"); params.append(dataset)
        if cond:
            sql += " WHERE " + " AND ".join(cond)
        sql += " ORDER BY created_at"
        return [self._pattern_row(r) for r in self._all(sql, tuple(params))]

    def pattern_patch(self, pattern_id: str, by: str = "analyst", **fields) -> Optional[dict]:
        cur = self._pattern_row(self._row("SELECT * FROM pattern WHERE pattern_id=?", (pattern_id,)))
        if cur is None:
            return None
        allowed = {"title", "description", "state", "confidence", "kind", "derived_rule_id"}
        changes = {k: v for k, v in fields.items() if k in allowed and v is not None}
        meta = cur.get("meta") or {}
        if changes:
            if by != "system":
                meta.setdefault("edited_by", by)
            sets, params = ["updated_at=?"], [now_ms()]
            for k, v in changes.items():
                sets.append(f"{k}=?")
                params.append(v if not isinstance(v, (list, dict)) else _j(v))
            params.append(pattern_id)
            self._exec(f"UPDATE pattern SET {', '.join(sets)} WHERE pattern_id=?", tuple(params))
            self.audit("pattern", pattern_id,
                       "manual.edit" if by != "system" else "auto.patch", by,
                       f"{'人工' if by != 'system' else '系统'}更新模式 {pattern_id}: {', '.join(changes)}")
        if "meta" in changes:
            pass
        return self.pattern_by_id(pattern_id)

    def patterns_of_fragments(self, fragment_ids: Iterable[str]) -> list[dict]:
        """某片段参与的可疑模式（溯源视图：片段 → 模式）。"""
        frag_set = set(fragment_ids)
        out = []
        for p in self.patterns():
            if frag_set.intersection(set(p["supporting_fragment_ids"])):
                out.append(p)
        return out

    # ============================================================ 衍生规则
    def add_rule(self, r: dict) -> str:
        now = now_ms()
        rid = r.get("rule_id")
        self._exec(
            "INSERT OR REPLACE INTO rule(rule_id, rule_type, name, description, enabled, state, "
            "expression, severity, action_policy, source_pattern_id, fired_times, "
            "last_triggered_at, owner, created_at, updated_at, revision, auto, audit) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rid, r.get("rule_type", "derived"), r.get("name", rid), r.get("description", ""),
             1 if r.get("enabled", True) else 0, r.get("state", "active"),
             _j(r.get("expression", [])), r.get("severity", "medium"),
             _j(r.get("action_policy", {"max_tier": "A1", "allow": []})),
             r.get("source_pattern_id"), int(r.get("fired_times", 0) or 0),
             r.get("last_triggered_at"), r.get("owner", "system"),
             r.get("created_at", now), r.get("updated_at", now),
             int(r.get("revision", 1) or 1), 1 if r.get("auto", True) else 0,
             _j(r.get("audit", []))))
        return rid

    def rule_by_id(self, rule_id: str) -> Optional[dict]:
        r = self._row("SELECT * FROM rule WHERE rule_id=? AND rule_type='derived'", (rule_id,))
        return self._rule_row(r) if r else None

    def _rule_row(self, r: sqlite3.Row) -> dict:
        d = dict(r)
        d["enabled"] = bool(d.get("enabled"))
        d["auto"] = bool(d.get("auto"))
        d["expression"] = _u(d.get("expression"), [])
        d["action_policy"] = _u(d.get("action_policy"), {"max_tier": "A1", "allow": []})
        d["audit"] = _u(d.get("audit"), [])
        return d

    def rules(self, state: Optional[str] = None) -> list[dict]:
        sql, cond, params = "SELECT * FROM rule WHERE rule_type='derived'", [], []
        if state:
            cond.append("state=?"); params.append(state)
        if cond:
            sql += " AND " + " AND ".join(cond)
        sql += " ORDER BY created_at"
        return [self._rule_row(r) for r in self._all(sql, tuple(params))]

    def _patch_rule(self, rid: str, by: str, notes: list[str],
                    state: Optional[str] = None, enabled: Optional[bool] = None,
                    fields: Optional[dict] = None) -> Optional[dict]:
        """公共写路径：改字段 + 审计 + revision。"""
        cur = self.rule_by_id(rid)
        if cur is None:
            return None
        audit = list(cur.get("audit") or [])
        new_state, new_enabled = cur["state"], cur["enabled"]
        if state is not None and state != cur["state"]:
            new_state = state
            audit.append({"ts": now_ms(), "op": "manual.state", "by": by,
                          "note": f"状态 {cur['state']} → {state}（{'冻结，系统不再演化' if state == 'paused' else '解冻/恢复' if state == 'active' else ''}）"})
        if enabled is not None and enabled != cur["enabled"]:
            new_enabled = enabled
            audit.append({"ts": now_ms(), "op": "manual." + ("enable" if enabled else "disable"),
                          "by": by, "note": f"启用状态 → {enabled}"})
        patch: dict = {}
        for k, v in (fields or {}).items():
            if k not in ("name", "description", "severity", "expression", "action_policy", "source_pattern_id"):
                continue
            if v is not None and v != cur.get(k):
                patch[k] = v
        if patch:
            audit.append({"ts": now_ms(), "op": "manual.edit", "by": by,
                          "note": f"字段更新: {', '.join(patch)}"})
        if not (patch or new_state != cur["state"] or new_enabled != cur["enabled"]):
            return cur
        sets, params = ["revision=revision+1", "updated_at=?", "state=?", "enabled=?"], \
            [now_ms(), new_state, 1 if new_enabled else 0]
        for k, v in patch.items():
            sets.append(f"{k}=?")
            params.append(_j(v) if isinstance(v, (list, dict)) else v)
        params.append(rid)
        self._exec(f"UPDATE rule SET {', '.join(sets)} WHERE rule_id=?", tuple(params))
        for n in notes:
            self.audit("rule", rid, "auto.evolve" if by == "system" else "manual", by, n)
        # audit 列同步回写（JSON 数组全量）
        merged = list(cur.get("audit") or []) + audit[len(cur.get("audit") or []):]
        self._exec("UPDATE rule SET audit=? WHERE rule_id=?", (_j(merged), rid))
        return self.rule_by_id(rid)

    def rule_patch(self, rule_id: str, by: str = "analyst", **fields) -> Optional[dict]:
        """人工/系统修改衍生规则：state(paused=冻结)/enabled/name/description/severity/expr 等。"""
        state = fields.pop("state", None)
        enabled = fields.pop("enabled", None)
        notes = []
        if fields.get("expr") is not None:
            fields["expression"] = json.loads(fields["expr"]) if isinstance(fields["expr"], str) else fields.pop("expr")
        if fields.get("tier") is not None or fields.get("allow") is not None:
            cur = self.rule_by_id(rule_id)
            ap = dict(cur["action_policy"] if cur else {})
            if fields.get("tier"):
                ap["max_tier"] = fields.pop("tier")
            if fields.get("allow") is not None:
                ap["allow"] = fields.pop("allow")
            fields["action_policy"] = ap
        return self._patch_rule(rule_id, by=by, notes=notes,
                                state=state, enabled=enabled, fields=fields or None)

    def rule_set_state(self, rule_id: str, state: str, by: str = "analyst", note: str = "") -> Optional[dict]:
        return self._patch_rule(rule_id, by=by, notes=[note] if note else [],
                                state=state)

    def rule_delete(self, rule_id: str, by: str = "analyst", note: str = "人工停用") -> bool:
        cur = self.rule_by_id(rule_id)
        if cur is None:
            return False
        self._patch_rule(rule_id, by=by, state="superseded", enabled=False,
                         fields={"description": cur["description"]}, notes=[note])
        return True

    # ============================================================ 升格（自进化 → 人工权威）
    def promoted_rule_ids(self) -> list[str]:
        """已由人工拍板升格为人工规则的衍生规则 id 列表。"""
        return self.evo_get("promoted.manual", [])

    def promote_rule(self, rule_id: str, by: str = "analyst",
                     note: str = "") -> Optional[dict]:
        """人工拍板：把衍生规则升格为人工权威规则（规格 D）。

        效果：规则 auto=0/owner=人工/审计记 manual.promote；来源模式登记 meta 标记；
        登记 evo(promoted.manual) 使其退出『衍生自动演化』列表。幂等：已升格直接返回。
        """
        cur = self.rule_by_id(rule_id)
        if cur is None:
            return None
        if not cur.get("auto"):           # 已是人工（或已升格），幂等
            return cur
        audit = list(cur.get("audit") or [])
        audit.append({"ts": now_ms(), "op": "manual.promote", "by": by,
                      "note": note or f"{rule_id} 由系统衍生规则经人工拍板升格为人工权威规则"
                                      "（此后命中直发，不再自动演化）"})
        pid = cur.get("source_pattern_id")
        with self._lock:
            self._conn.execute(
                "UPDATE rule SET auto=0, owner=?, state='active', enabled=1, "
                "revision=revision+1, updated_at=?, audit=? WHERE rule_id=?",
                (by, now_ms(), _j(audit), rule_id))
            if pid:
                self._conn.execute(
                    "UPDATE pattern SET meta=?, updated_at=? WHERE pattern_id=?",
                    (_j({"promoted_to_manual": rule_id, "promoted_by": by,
                         "promoted_at": now_ms()}), now_ms(), pid))
            self._conn.commit()
        self.audit("rule", rule_id, "manual.promote", by,
                   note or f"衍生规则 → 人工规则：{rule_id}")
        if pid:
            self.audit("pattern", pid, "manual.promote", by,
                       f"可疑模式 {pid} 经验证有含金量，人工拍板升格为人工规则 {rule_id}")
        promoted = self.promoted_rule_ids()
        if rule_id not in promoted:
            self.evo_set("promoted.manual", promoted + [rule_id])
        return self.rule_by_id(rule_id)

    def rejected_rule_ids(self) -> list[str]:
        """人工拒绝、不再推荐为升格候选的衍生规则 id 列表（规则本身仍 active 自动演化）。"""
        return self.evo_get("promote.rejected", [])

    def reject_candidate(self, rule_id: str, by: str = "analyst",
                         note: str = "") -> Optional[dict]:
        """人工拒绝候选：不再推荐升格为人工规则，但保留衍生规则原样继续演化/命中。

        效果：规则 audit 数组追加 + 审计 rule/pattern 记 manual.reject；登记
        evo(promote.rejected) 使其退出『候选推荐』（区别于升格：不改变 auto/状态）。
        幂等：已拒绝直接返回当前规则。
        """
        cur = self.rule_by_id(rule_id)
        if cur is None:
            return None
        if not cur.get("auto"):          # 已升格/人工权威：候选列表中本不会出现
            return cur
        audit = list(cur.get("audit") or [])
        audit.append({"ts": now_ms(), "op": "manual.reject", "by": by,
                      "note": note or f"{rule_id} 人工拒绝采纳为人工规则："
                                      "保留为衍生规则继续演化，不再推荐升格"})
        with self._lock:
            self._conn.execute(
                "UPDATE rule SET revision=revision+1, updated_at=?, audit=? WHERE rule_id=?",
                (now_ms(), _j(audit), rule_id))
            self._conn.commit()
        self.audit("rule", rule_id, "manual.reject", by,
                   note or f"拒绝升格候选：{rule_id}（保留衍生规则 active）")
        pid = cur.get("source_pattern_id")
        if pid:
            self.audit("pattern", pid, "manual.reject", by,
                       f"可疑模式 {pid} 的衍生规则 {rule_id} 被人工拒绝升格（仍可继续演化）")
        rejected = self.rejected_rule_ids()
        if rule_id not in rejected:
            self.evo_set("promote.rejected", rejected + [rule_id])
        return self.rule_by_id(rule_id)


    def bump_fired(self, rule_id: str, ts_ms: Optional[int] = None) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE rule SET fired_times=fired_times+1, last_triggered_at=? "
                "WHERE rule_id=? AND rule_type='derived'",
                (ts_ms or now_ms(), rule_id))
            self._conn.commit()

    def set_fired(self, rule_id: str, count: int, last_ts: Optional[int] = None) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE rule SET fired_times=?, last_triggered_at=? "
                "WHERE rule_id=? AND rule_type='derived'",
                (int(count), last_ts or now_ms(), rule_id))
            self._conn.commit()

    def pattern_merge_link(self, pattern_id: str, into_rule_id: str,
                           by: str = "system", note: str = "") -> None:
        """把模式标记为已被并入某衍生规则（自动合并去重）：状态 superseded + meta.merged_to + 审计。"""
        cur = self.pattern_by_id(pattern_id)
        if cur is None:
            return
        meta = dict(cur.get("meta") or {})
        meta["merged_to"] = into_rule_id
        with self._lock:
            self._conn.execute(
                "UPDATE pattern SET state='superseded', meta=?, updated_at=? WHERE pattern_id=?",
                (_j(meta), now_ms(), pattern_id))
            self._conn.commit()
        self.audit("pattern", pattern_id, "auto.merge", by,
                   note or f"并入衍生规则 {into_rule_id}（规则集重复），模式 superseded。")
        self.audit("rule", into_rule_id, "auto.merge", by,
                   f"并入重复模式 {pattern_id} 的片段证据，规则集不变。")

    # ============================================================ 状态快照
    def stats(self) -> dict:
        return {
            "fragments": {"llm-soc": self.count_fragments("llm-soc"),
                          "linux": self.count_fragments("linux")},
            "patterns": {"all": len(self.patterns()),
                         "active": len(self.patterns(state="active"))},
            "derived_rules": {"all": len(self.rules()),
                              "active": len(self.rules(state="active")),
                              "superseded": len(self.rules(state="superseded"))},
            "auto_evolve": self.auto_evolve(),
            "db": self.db_path,
        }

    def close(self) -> None:
        with self._lock:
            self._conn.close()
