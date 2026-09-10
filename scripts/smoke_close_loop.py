# -*- coding: utf-8 -*-
"""最小在线闭环 v2 冒烟：在临时副本 memory 上验证 review 写回 / evidence / 升格审批。"""
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

tmp = tempfile.mkdtemp(prefix="smoke_mem_")
print("[smoke] temp memory copy:", tmp)

mem_src = os.path.join("data", "memory")
if os.path.isdir(mem_src):
    for name in os.listdir(mem_src):
        s = os.path.join(mem_src, name)
        d = os.path.join(tmp, name)
        if os.path.isdir(s):
            shutil.copytree(s, d)
        else:
            shutil.copy2(s, d)

from src.core.memory.store import MemoryStore          # noqa: E402
import src.core.api.memory_api as ma                   # noqa: E402

ma._store = MemoryStore(db_path=os.path.join(tmp, "memory.db"),
                        chroma_dir=os.path.join(tmp, "chroma"))
print("[smoke] temp stats:", ma._store.stats())

from fastapi.testclient import TestClient               # noqa: E402
from src.core.api.server import create_app              # noqa: E402

app = create_app("llm-soc")
ok = {"n": 0}


def check(label, cond, extra=""):
    ok["n"] += 1
    mark = "PASS" if cond else "FAIL"
    print(f"[{mark}] {label} {extra}")
    if not cond:
        sys.exit(1)


with TestClient(app) as c:
    # 1. 候选列表
    cands = c.get("/api/evolution/promote-candidates").json()
    check("promote-candidates 非空且带验证统计", len(cands) > 0,
          f"cands={len(cands)} top_fired={cands[0]['validation']['firedTimes'] if cands else '-'}")
    if cands:
        check("candidate 来自 auto 衍生规则", cands[0]["ruleType"] == "derived")

    # 2. 找一个靠后的告警（有足够历史可召回证据）
    page2 = c.get("/api/alerts", params={"page": 2, "size": 100}).json()
    items = page2["items"]
    check("alerts 可分页", len(items) > 0, f"total={page2['total']}")
    aid = items[0]["id"]

    # 3. 证据接口（防泄漏）
    ev = c.get(f"/api/alerts/{aid}/evidence").json()
    check("evidence 返回 counts/文本", "counts" in ev and "evidenceText" in ev,
          f"counts={ev['counts']} seq={ev['seq']} guard={ev['leakageGuard']}")

    # 4. review 写回 feedback 片段（幂等：重复复核覆盖同一 fragment_id）
    r1 = c.post(f"/api/alerts/{aid}/review",
                json={"cls": "FP", "by": "analyst", "reason": "冒烟：确认误报", "priority": "Low"}).json()
    fid = r1.get("feedback", {}).get("fragmentId")
    check("review 写回 feedback.fragmentId", bool(fid), f"fid={fid}")
    r2 = c.post(f"/api/alerts/{aid}/review",
                json={"cls": "TP", "by": "lead", "reason": "冒烟：更正确认为威胁", "priority": "High"}).json()
    fid2 = r2.get("feedback", {}).get("fragmentId")
    check("重复复核同一 fragment_id（覆盖更新）", fid == fid2, f"{fid} == {fid2}")
    rows = ma._store.fragment_by_ids([fid])
    check("feedback 片段已覆盖为最新结论 TP", bool(rows) and rows[0]["classification"] == "TP",
          f"rows={len(rows)} cls={rows[0].get('classification') if rows else '-'} method={rows[0].get('method') if rows else '-'}")

    # 5. 复核后告警 detail 反馈（feedback 片段检索入证据面在消融评测已验证，此处验库内一致性）
    rows2 = ma._store.fragments(dataset="llm-soc", rule_id=None, limit=10**9)
    check("feedback 片段已入库", any(r["fragment_id"] == fid for r in rows2))

    # 6. 升格审批：选 fired 最高的候选拍板
    top = cands[0]["ruleId"]
    prom = c.post("/api/evolution/promote", json={"ruleId": top, "by": "analyst",
                                                  "note": "冒烟：拍板升格"}).json()
    check("promote 成功", prom.get("ok") is True and prom["rule"]["ruleType"] == "manual",
          f"rule={prom['rule']['ruleId']}")
    derived = c.get("/api/rules", params={"type": "derived"}).json()
    check("升格后不再出现在衍生列表", top not in [d["ruleId"] for d in derived])
    manual = c.get("/api/rules", params={"type": "manual"}).json()
    check("升格后出现在人工规则池", any(m["ruleId"] == top for m in manual))
    tr = c.get(f"/api/rules/{top}/trace").json()
    check("升格规则保留溯源链", tr.get("rule") and tr.get("pattern") is not None,
          f"pattern={tr.get('pattern', {}).get('patternId') if tr.get('pattern') else '-'}")

    # 7. 审计齐全
    al = ma._store.audit_log(obj_id=top, limit=20)
    check("升格写审计", any(a["op"] == "manual.promote" for a in al),
          f"audits={len(al)}")
    al2 = ma._store.audit_log(obj_id=fid, limit=10)
    check("复核写审计(fragment)", any(a["op"] == "manual.review" for a in al2))

    # 8. 复核状态回读前端 verdict
    det = c.get(f"/api/alerts/{aid}").json()
    check("告警 detail 显示已复核", det["status"] == "reviewed" and det["verdict"]["classification"] == "TP",
          f"status={det['status']} cls={det['verdict']['classification'] if det['verdict'] else '-'}")

    c.close()

print(f"[smoke] ALL {ok['n']} CHECKS PASSED")
shutil.rmtree(tmp, ignore_errors=True)
print("[smoke] temp removed")
