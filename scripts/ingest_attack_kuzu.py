# -*- coding: utf-8 -*-
"""
ATT&CK Enterprise (STIX) → Kùzu 知识图谱导入脚本
=================================================
用途：把 MITRE ATT&CK 企业版 STIX bundle（enterprise-attack.json）建成本地
      Kùzu 图库，作为"本地网安专业知识图谱"的第一阶段静态本体。

导入的实体/关系（MVP）：
  节点：Tactic / Technique / ThreatActor(含 group|campaign|malware|tool) / Mitigation
  关系：SUBTECHNIQUE_OF(技术->父技术), HAS_TACTIC(技术->战术),
        USES(组织/活动/软件->技术), MITIGATES(缓解->技术)

用法：
  python scripts/ingest_attack_kuzu.py            # 使用默认 source/db
  python scripts/ingest_attack_kuzu.py --rebuild  # 删除旧库后重建（幂等重建）
说明：
  源文件不存在时会先尝试直连 GitHub，失败则走镜像(ghfast.top 等)回退；
  若 data/kb/enterprise-attack.json 已存在则直接使用、不重复下载。
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import shutil
import sys
import tempfile
import urllib.request
from pathlib import Path

import kuzu

BASE = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = BASE / "data" / "kb" / "enterprise-attack.json"
DEFAULT_DB = BASE / "data" / "kb" / "attack_kuzu"
RAW_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
MIRRORS = [
    "https://ghfast.top/",
    "https://gh-proxy.com/",
    "https://ghproxy.net/",
]

# 各对象类型(含弃用标记等)统一跳过的属性
SKIP_FLAGS = ("revoked", "x_mitre_deprecated", "x_mitre_is_revoked")


def _s(obj: dict, key: str, default: str = "") -> str:
    """安全取字符串属性。"""
    v = obj.get(key)
    return default if v is None else str(v)


def _attack_id(obj: dict) -> str:
    """取 mitre-attack 外部引用 ID（T1078 / TA0001 / M1047 等）。"""
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack":
            return _s(ref, "external_id")
    return ""


def _usable(obj: dict) -> bool:
    """已撤销/废弃/不活跃的对象不入图。"""
    return not any(obj.get(k, False) for k in SKIP_FLAGS)


def _resolve_ascii_path(p: Path) -> Path:
    """Kùzu(Windows 构建) 底层用窄字符打开路径，不支持非 ASCII；
    若库路径含中文等字符，先尝试父目录的 8.3 短路径；仍失败则回退到
    Temp 下的 ASCII 运行库目录（可用环境变量 SCSSA_KUZU_DB 或 --db 覆盖）。"""
    if p.as_posix().isascii():
        return p
    try:
        import ctypes

        buf = ctypes.create_unicode_buffer(1024)
        n = ctypes.windll.kernel32.GetShortPathNameW(str(p.parent), buf, len(buf))
        if n and n < len(buf):
            candidate = Path(buf.value) / p.name
            if candidate.as_posix().isascii():
                return candidate
    except Exception:  # noqa: BLE001
        pass
    override = os.environ.get("SCSSA_KUZU_DB")
    fallback = Path(override) if override else Path(tempfile.gettempdir()) / "scssa_kb" / p.name
    fallback.parent.mkdir(parents=True, exist_ok=True)
    print(f"[i] 目标路径含非 ASCII，回退 ASCII 运行库：{fallback}")
    return fallback


def download_source(path: Path) -> None:
    """源文件缺失时下载：先直连，再逐镜像回退。"""
    print("[i] 未找到源文件，尝试下载 ATT&CK STIX ...")
    for url in [RAW_URL] + [m + RAW_URL for m in MIRRORS]:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=120) as rsp, open(path, "wb") as f:
                shutil.copyfileobj(rsp, f)
            print(f"[✓] 下载成功：{url}")
            return
        except Exception as e:  # noqa: BLE001
            print(f"[x] 失败({type(e).__name__}) {url}")
    sys.exit("源文件下载失败，请手动放入 data/kb/enterprise-attack.json 后重试。")


def create_schema(conn: kuzu.Connection) -> None:
    """建表（重复执行无副作用由调用方保证：建库前已删除/跳过）。"""
    ddl = [
        "CREATE NODE TABLE Tactic(id STRING PRIMARY KEY, attack_id STRING, short_name STRING, name STRING, description STRING)",
        "CREATE NODE TABLE Technique(id STRING PRIMARY KEY, attack_id STRING, name STRING, description STRING, platforms STRING, is_sub BOOLEAN)",
        "CREATE NODE TABLE ThreatActor(id STRING PRIMARY KEY, kind STRING, name STRING, description STRING)",
        "CREATE NODE TABLE Mitigation(id STRING PRIMARY KEY, attack_id STRING, name STRING, description STRING)",
        "CREATE NODE TABLE Meta(key STRING PRIMARY KEY, value STRING)",
        "CREATE REL TABLE SUBTECHNIQUE_OF(FROM Technique TO Technique)",
        "CREATE REL TABLE HAS_TACTIC(FROM Technique TO Tactic)",
        "CREATE REL TABLE USES(FROM ThreatActor TO Technique)",
        "CREATE REL TABLE MITIGATES(FROM Mitigation TO Technique)",
    ]
    for stmt in ddl:
        conn.execute(stmt)


def main() -> None:
    parser = argparse.ArgumentParser(description="ATT&CK STIX → Kùzu 建库")
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--rebuild", action="store_true", help="删除旧库后重建")
    args = parser.parse_args()

    source, db_dir = args.source.resolve(), args.db.resolve()
    db_dir = _resolve_ascii_path(db_dir)

    # 1) 准备源文件
    if not source.exists():
        source.parent.mkdir(parents=True, exist_ok=True)
        download_source(source)
    print(f"[i] 源文件：{source} ({source.stat().st_size / 1e6:.1f} MB)")

    # 2) 解析 STIX bundle
    with open(source, encoding="utf-8") as f:
        bundle = json.load(f)
    objects = bundle.get("objects", [])
    print(f"[i] bundle: {bundle.get('type')} id={bundle.get('id')} objects={len(objects)}")

    # 3) 建库（幂等：已存在且未 --rebuild 则直接退出）
    if db_dir != args.db.resolve():
        print(f"[i] 实际库路径：{db_dir}")
    if db_dir.exists():
        if not args.rebuild:
            print(f"[i] 图库已存在：{db_dir}\n    如需重建请加 --rebuild。")
            return
        print("[i] --rebuild：删除旧库 ...")
        shutil.rmtree(db_dir)
    # 注意：不预建目录，交给 Kùzu 自行创建

    db = kuzu.Database(str(db_dir))
    conn = kuzu.Connection(db)
    create_schema(conn)

    # 4) 对象分类（仅保留可用对象）
    tactics: dict[str, dict] = {}
    techniques: dict[str, dict] = {}
    actors: dict[str, dict] = {}
    mitigations: dict[str, dict] = {}
    relationships = []
    skipped = 0
    # id 前缀 -> 节点类型（用于关系过滤）
    id_type: dict[str, str] = {}

    for obj in objects:
        t = obj.get("type")
        if not _usable(obj):
            skipped += 1
            continue
        if t == "x-mitre-tactic":
            tactics[obj["id"]] = obj
            id_type[obj["id"]] = "tactic"
        elif t == "attack-pattern":
            techniques[obj["id"]] = obj
            id_type[obj["id"]] = "technique"
        elif t in ("malware", "tool", "intrusion-set", "campaign"):
            actors[obj["id"]] = obj
            id_type[obj["id"]] = "actor"
        elif t == "course-of-action":
            mitigations[obj["id"]] = obj
            id_type[obj["id"]] = "mitigation"
        elif t == "relationship":
            relationships.append(obj)

    print(f"[i] 可用对象：Tactic={len(tactics)} Technique={len(techniques)} "
          f"ThreatActor={len(actors)} Mitigation={len(mitigations)} "
          f"Relationship={len(relationships)} (跳过 {skipped})")

    # 5) 入库：战术 + 技术（含 kill_chain 归属收集）
    n_tac = n_tech = n_actor = n_mit = 0
    tech_tactics: list[tuple[str, str]] = []  # (technique_id, tactic_id)
    tactic_by_lower: dict[str, str] = {}
    for tid, obj in tactics.items():
        tactic_by_lower[_s(obj, "name").lower()] = tid
        tactic_by_lower.setdefault(_s(obj, "x_mitre_shortname").lower(), tid)
    for tid, obj in tactics.items():
        conn.execute(
            "CREATE (n:Tactic {id:$id, attack_id:$attack_id, short_name:$short_name, "
            "name:$name, description:$description})",
            {"id": tid, "attack_id": _attack_id(obj), "short_name": _s(obj, "x_mitre_shortname"),
             "name": _s(obj, "name"), "description": _s(obj, "description")},
        )
        n_tac += 1

    for tid, obj in techniques.items():
        phases = [p for p in obj.get("kill_chain_phases", []) or []
                  if str(p.get("kill_chain_name", "")).endswith("mitre-attack")]
        for p in phases:
            tid_tac = tactic_by_lower.get(str(p.get("phase_name", "")).lower())
            if tid_tac:
                tech_tactics.append((tid, tid_tac))
        platforms = ", ".join(obj.get("x_mitre_platforms", []) or [])
        conn.execute(
            "CREATE (n:Technique {id:$id, attack_id:$attack_id, name:$name, "
            "description:$description, platforms:$platforms, is_sub:$is_sub})",
            {"id": tid, "attack_id": _attack_id(obj), "name": _s(obj, "name"),
             "description": _s(obj, "description"), "platforms": platforms,
             "is_sub": bool(obj.get("x_mitre_is_subtechnique", False))},
        )
        n_tech += 1

    kind_map = {"intrusion-set": "group", "malware": "malware",
                "tool": "tool", "campaign": "campaign"}
    for aid, obj in actors.items():
        conn.execute(
            "CREATE (n:ThreatActor {id:$id, kind:$kind, name:$name, description:$description})",
            {"id": aid, "kind": kind_map.get(obj.get("type"), "other"),
             "name": _s(obj, "name"), "description": _s(obj, "description")},
        )
        n_actor += 1

    for mid, obj in mitigations.items():
        conn.execute(
            "CREATE (n:Mitigation {id:$id, attack_id:$attack_id, name:$name, description:$description})",
            {"id": mid, "attack_id": _attack_id(obj), "name": _s(obj, "name"),
             "description": _s(obj, "description")},
        )
        n_mit += 1

    # 6) 入库：关系（HAS_TACTIC / SUBTECHNIQUE_OF / USES / MITIGATES）
    n_has = n_sub = n_uses = n_mitigates = 0
    for (tech_id, tac_id) in tech_tactics:
        conn.execute("MATCH (a:Technique {id:$s}) MATCH (b:Tactic {id:$t}) "
                     "CREATE (a)-[:HAS_TACTIC]->(b)", {"s": tech_id, "t": tac_id})
        n_has += 1

    for rel in relationships:
        rtype = rel.get("relationship_type")
        sref, tref = rel.get("source_ref"), rel.get("target_ref")
        st, tt = id_type.get(sref), id_type.get(tref)
        if rtype == "subtechnique-of" and st == "technique" and tt == "technique":
            conn.execute("MATCH (a:Technique {id:$s}) MATCH (b:Technique {id:$t}) "
                         "CREATE (a)-[:SUBTECHNIQUE_OF]->(b)", {"s": sref, "t": tref})
            n_sub += 1
        elif rtype == "uses" and st == "actor" and tt == "technique":
            conn.execute("MATCH (a:ThreatActor {id:$s}) MATCH (b:Technique {id:$t}) "
                         "CREATE (a)-[:USES]->(b)", {"s": sref, "t": tref})
            n_uses += 1
        elif rtype == "mitigates" and st == "mitigation" and tt == "technique":
            conn.execute("MATCH (a:Mitigation {id:$s}) MATCH (b:Technique {id:$t}) "
                         "CREATE (a)-[:MITIGATES]->(b)", {"s": sref, "t": tref})
            n_mitigates += 1

    # 7) 元数据（溯源）
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    meta = {
        "bundle_id": _s(bundle, "id"),
        "source_file": str(source),
        "ingested_at": now,
        "counts": (f"tactic={n_tac} technique={n_tech} actor={n_actor} "
                   f"mitigation={n_mit} | has_tactic={n_has} subtechnique_of={n_sub} "
                   f"uses={n_uses} mitigates={n_mitigates}"),
    }
    for k, v in meta.items():
        conn.execute("CREATE (:Meta {key:$k, value:$v})", {"k": k, "v": v})

    # 8) 汇总
    print("[✓] 入库完成")
    print(f"    节点：Tactic={n_tac} Technique={n_tech} ThreatActor={n_actor} Mitigation={n_mit}")
    print(f"    关系：HAS_TACTIC={n_has} SUBTECHNIQUE_OF={n_sub} USES={n_uses} MITIGATES={n_mitigates}")
    print(f"    图库路径：{db_dir}")

    # 9) 演示查询
    def q(cql: str) -> list:
        return conn.execute(cql).get_all()

    print("\n--- 演示查询 ---")
    print("[Q1] 主技术/子技术/组/软件/缓解 计数：")
    for label in ("Tactic", "Technique", "ThreatActor", "Mitigation"):
        rows = q(f"MATCH (n:{label}) RETURN count(*)")
        print(f"    {label}: {rows[0][0]}")
    rows = q("MATCH (n:Technique) WHERE n.is_sub = true RETURN count(*)")
    print(f"    其中子技术: {rows[0][0]}")
    rows = q("MATCH (:Technique)-[:SUBTECHNIQUE_OF]->(:Technique) RETURN count(*)")
    print(f"    SUBTECHNIQUE_OF 边: {rows[0][0]}")

    print("\n[Q2] TA0001(Initial Access) 下的部分技术：")
    for aid, name in q("MATCH (t:Tactic {attack_id:'TA0001'})<-[:HAS_TACTIC]-(x:Technique) "
                       "RETURN x.attack_id, x.name LIMIT 10"):
        print(f"    {aid:12s} {name}")

    print("\n[Q3] T1078(Valid Accounts) 归属战术 + 使用它的组织/软件：")
    for aid, name in q("MATCH (x:Technique {attack_id:'T1078'})-[:HAS_TACTIC]->(t:Tactic) "
                       "RETURN t.attack_id, t.name"):
        print(f"    战术: {aid} {name}")
    for kind, name in q("MATCH (a:ThreatActor)-[:USES]->(:Technique {attack_id:'T1078'}) "
                        "RETURN a.kind, a.name LIMIT 8"):
        print(f"    使用者[{kind}]: {name}")

    print("\n[Q4] 使用技术最多的组织/软件 TOP 8：")
    for kind, name, c in q("MATCH (a:ThreatActor)-[:USES]->(x:Technique) "
                           "RETURN a.kind, a.name, count(*) AS c ORDER BY c DESC LIMIT 8"):
        print(f"    [{kind}] {name}: {c}")

    print("\n[Q5] T1055(Process Injection) 的缓解措施：")
    for mid, name in q("MATCH (m:Mitigation)-[:MITIGATES]->(x:Technique {attack_id:'T1055'}) "
                       "RETURN m.attack_id, m.name LIMIT 6"):
        print(f"    {mid or '-':8s} {name}")

    print("\n[Q6] 元数据：")
    for k, v in q("MATCH (m:Meta) RETURN m.key, m.value"):
        print(f"    {k} = {v}")

    conn.close()


if __name__ == "__main__":
    main()
