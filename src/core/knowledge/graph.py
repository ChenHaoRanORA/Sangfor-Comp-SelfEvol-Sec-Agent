# -*- coding: utf-8 -*-
"""静态网安知识图谱封装（Kùzu，ATT&CK 本体）。

- 图库由 scripts/ingest_attack_kuzu.py 构建（data/kb/attack_kuzu 或 SCSSA_KUZU_DB）；
- 对外提供"告警 MITRE → Technique → Tactic"多跳查询（溯源/模式归纳上下文用）；
- 数据集 MITRE 字段可能是技术名（"Windows Service"/"SMB/Windows Admin Shares"）而非
  ATT&CK ID（T1078），本模块做 ID 精确匹配 + 名称子串模糊匹配两级解析。
"""
from __future__ import annotations

import os
import re
from typing import Optional

_ATTACK_ID = re.compile(r"^T\d{3,5}(\.\d+)?$")

DEFAULT_DB = os.path.join("data", "kb", "attack_kuzu")


def _resolve_ascii_path(p: str) -> str:
    """Kùzu Windows 不支持非 ASCII 路径；含非 ASCII 时回退 ASCII 目录。"""
    if p.isascii():
        return p
    override = os.environ.get("SCSSA_KUZU_DB")
    fallback = override or os.path.join(os.environ.get("TEMP", "/tmp"), "scssa_kb", "attack_kuzu")
    os.makedirs(os.path.dirname(fallback), exist_ok=True)
    return fallback


class KnowledgeKB:
    def __init__(self, db: str = DEFAULT_DB):
        import kuzu  # 延迟：库未建/未装时允许上层降级
        self.db_path = _resolve_ascii_path(db)
        self._database = kuzu.Database(self.db_path)
        self._conn = kuzu.Connection(self._database)

    # ---------------------------------------------------------- 基础查询
    def _q(self, cql: str, params: Optional[dict] = None) -> list:
        return self._conn.execute(cql, params or {}).get_all()

    def stats(self) -> dict:
        try:
            rows = self._q("MATCH (m:Meta) RETURN m.key, m.value")
            meta = dict(rows)
            counts = {"tactic": self._q("MATCH (n:Tactic) RETURN count(*)")[0][0],
                      "technique": self._q("MATCH (n:Technique) RETURN count(*)")[0][0]}
            return {"ok": True, "meta": meta, "counts": counts}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)}

    def _find_technique(self, code: str) -> list[dict]:
        """按 ATT&CK ID 或名称定位 Technique。返回 [{attack_id,name,description}]"""
        code = (code or "").strip()
        if not code:
            return []
        if _ATTACK_ID.match(code):
            rows = self._q(
                "MATCH (n:Technique) WHERE n.attack_id=$id RETURN n.attack_id, n.name, n.is_sub",
                {"id": code})
        else:
            rows = self._q(
                "MATCH (n:Technique) WHERE lower(n.name) CONTAINS lower($kw) "
                "RETURN n.attack_id, n.name, n.is_sub LIMIT 3",
                {"kw": code})
        return [{"attack_id": r[0], "name": r[1], "is_sub": bool(r[2])} for r in rows]

    # ---------------------------------------------------------- 对外：多跳溯源
    def resolve_mitre(self, techniques: list, tactics: Optional[list] = None) -> dict:
        """把数据集 MITRE 写法解析到图谱 Technique/Tactic，供溯源/检索。"""
        found_tech = []
        seen = set()
        for t in techniques or []:
            for r in self._find_technique(str(t)):
                if r["attack_id"] not in seen:
                    seen.add(r["attack_id"])
                    found_tech.append(r)
        found_tac = []
        seen_t = set()
        for t in tactics or []:
            name = str(t).strip()
            if not name:
                continue
            rows = self._q(
                "MATCH (n:Tactic) WHERE n.attack_id=$id OR lower(n.name)=lower($kw) "
                "RETURN n.attack_id, n.name", {"id": name, "kw": name})
            for attack_id, n_name in rows:
                if attack_id not in seen_t:
                    seen_t.add(attack_id)
                    found_tac.append({"attack_id": attack_id, "name": n_name})
        return {"techniques": found_tech, "tactics": found_tac}

    def alert_graph(self, techniques: list) -> dict:
        """告警 → Technique → Tactic / 使用者 多跳子图（前端/LLM 上下文）。"""
        techs = self.resolve_mitre(techniques)["techniques"]
        out = []
        for t in techs[:6]:
            node = {"attack_id": t["attack_id"], "name": t["name"],
                    "tactics": [], "actors": 0}
            rows = self._q(
                "MATCH (x:Technique {attack_id:$id})-[:HAS_TACTIC]->(t:Tactic) "
                "RETURN t.attack_id, t.name", {"id": t["attack_id"]})
            node["tactics"] = [{"attack_id": a, "name": n} for a, n in rows]
            if rows:
                cnt = self._q(
                    "MATCH (a:ThreatActor)-[:USES]->(:Technique {attack_id:$id}) RETURN count(*)",
                    {"id": t["attack_id"]})[0][0]
                node["actors"] = int(cnt)
            out.append(node)
        return {"techniques": out}

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:  # noqa: BLE001
            pass
