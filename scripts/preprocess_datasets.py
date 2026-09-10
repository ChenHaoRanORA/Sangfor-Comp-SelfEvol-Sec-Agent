# -*- coding: utf-8 -*-
"""两份原始数据集 → 统一 Alert JSONL 的离线预处理。

覆盖：
1) linux-APT-Dataset-2024.csv（198.7MB，多段 Kibana 导出的直接拼接，绝大多数行错位/无表头）
2) llm-soc-alert-triage 官方 merged 178 条（已打标 TP/FP + 优先级，转内部统一结构）

产出（data/processed/，不入 git）：
- linux_apt_alerts.jsonl   可靠对齐的可解析告警
- llm_soc_alerts.jsonl     178 条评测/研判基准
- *_stats.json             清洗统计

用法（conda 环境 scssa 内 python 3.10+，仅标准库）：
    python scripts/preprocess_datasets.py --all
    python scripts/preprocess_datasets.py linux-apt
    python scripts/preprocess_datasets.py llm-soc

统一记录结构（两数据集共用同一契约，便于后续 Ingress/回放统一处理）：
    dataset / alert_id / index / agent{id,name,ip} / os / time{ms,iso} / time_raw
    rule{id,level,description,groups} / mitre{...} / decoder{name,parent}
    location / program / text / priority / verdict{...} / extra
"""
from __future__ import annotations

import argparse
import collections
import csv
import datetime as _dt
import glob
import json
import os
import re
import sys
from typing import Any, Iterable, Optional

RAW_LINUX = os.path.join("data", "linux-APT-Dataset-2024.csv")
LLM_SOC_MERGED_DIR = os.path.join("data", "llm-soc-alert-triage-main", "Data", "2_Merged")
OUT_DIR = os.path.join("data", "processed")

# 时间字段解析（linux-APT 三态并存：epoch 整数 / 秒级浮点 / Kibana 格式化串）
_KIBANA_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2}) (?P<d>\d{1,2}), (?P<y>\d{4}) @ "
    r"(?P<H>\d{2}):(?P<M>\d{2}):(?P<S>\d{2})(?:\.(?P<ms>\d+))?$"
)
_MON = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}
# ISO/空格分隔时间（可选 Z / +HH:MM / +HHMM 时区后缀）
_ISO_RE = re.compile(
    r"^(?P<base>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
    r"(?P<z>[Zz]|[+-]\d{2}:?\d{2})?$"
)


def norm(v: Any) -> str:
    """CSV 空格填充（' '）与首尾空白统一视为空。"""
    if v is None:
        return ""
    s = str(v).strip()
    return s


def to_int(v: Any) -> Optional[int]:
    s = norm(v)
    if s.isdigit():
        return int(s)
    return None


def maybe_json(v: Any):
    """CSV 里的 JSON 数组字符串（如 ["a","b"]）还原为 list；失败则原样返回字符串。

    兼容两种转义写法：标准 CSV 双写引号（已由 csv.reader 还原）与残留的反斜杠转义（\"）。
    """
    s = norm(v)
    if not s:
        return None
    for cand in (s, s.replace('\\"', '"')):
        if cand[0] in "[{":
            try:
                return json.loads(cand)
            except Exception:
                continue
    return s


def parse_ts(v: Any) -> Optional[dict]:
    """把时间原始值归一化为 {ms, iso}；解析失败返回 None。

    支持三态并存格式：
    1) Kibana 串  Oct 5, 2023 @ 20:21:16.992
    2) epoch 秒/毫秒（整数或小数）
    3) ISO/空格分隔 2025-07-04T16:05:49.052+0000（可带 Z / +HH:MM / +HHMM，转 UTC）
    """
    s = norm(v)
    if not s:
        return None
    # 1) Kibana 格式化串：Oct 5, 2023 @ 20:21:16.992
    m = _KIBANA_RE.match(s)
    if m:
        try:
            dt = _dt.datetime(int(m["y"]), _MON[m["mon"]], int(m["d"]),
                              int(m["H"]), int(m["M"]), int(m["S"]))
            ms_txt = (m["ms"] or "")[:3].ljust(3, "0")
            dt = dt.replace(microsecond=int(ms_txt) * 1000)
        except Exception:
            return None
        return _dt_to_rec(dt, s)
    # 2) epoch 秒/毫秒（纯数字/小数，如 1696121358 / 1704304027.4286179）
    if s[0].isdigit() and re.fullmatch(r"\d+(?:\.\d+)?", s):
        try:
            f = float(s)
        except Exception:
            return None
        if f < 4e12:            # 秒（含小数）量级
            dt = _dt.datetime(1970, 1, 1) + _dt.timedelta(seconds=f)
        else:                   # 毫秒量级
            dt = _dt.datetime(1970, 1, 1) + _dt.timedelta(milliseconds=f)
        return _dt_to_rec(dt, s)
    # 3) ISO / 空格分隔（可带时区后缀，含 llm-soc 的 +0000 写法）
    m3 = _ISO_RE.match(s)
    if m3:
        base = m3["base"]
        if "." in base:  # %f 最多 6 位，超长小数截断
            head, frac = base.split(".", 1)
            base = f"{head}.{frac[:6]}"
        dt = None
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S.%f",
                    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = _dt.datetime.strptime(base, fmt)
                break
            except Exception:
                continue
        if dt is None:
            return None
        z = m3["z"]
        if z and z != "Z":
            sign = 1 if z[0] == "+" else -1
            zrest = z[1:]
            if ":" in zrest:
                zh, zm = zrest.split(":")
            else:
                zh, zm = zrest[:2], zrest[2:]
            try:
                dt = dt - sign * _dt.timedelta(hours=int(zh), minutes=int(zm))
            except Exception:
                return None
        return _dt_to_rec(dt, s)
    return None


def _dt_to_rec(dt: _dt.datetime, raw: str) -> dict:
    iso = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]  # 保留毫秒
    return {"ms": int(dt.timestamp() * 1000), "iso": iso}


def priority_of_level(level: Optional[int]) -> str:
    """严重度映射，口径与 llm-soc 一致：>=15 Critical / >=12 High / >=7 Medium / 其余 Low。"""
    if level is None:
        return "low"
    if level >= 15:
        return "critical"
    if level >= 12:
        return "high"
    if level >= 7:
        return "medium"
    return "low"


def deep_get(d: dict, *path: str) -> Any:
    cur: Any = d
    for p in path:
        if isinstance(cur, dict):
            cur = cur.get(p)
        else:
            return None
    return cur


# ---------------------------------------------------------------------------
# linux-APT
# ---------------------------------------------------------------------------

def _cell_map(row: Iterable[str], header: list[str]) -> dict:
    """把一行与当前段表头配对；空值（含空格填充）不保留。"""
    out: dict[str, str] = {}
    for name, v in zip(header, row):
        s = norm(v)
        if s:
            out[name] = s
    return out


def _linux_row_plausible(m: dict) -> bool:
    """对齐行做轻量语义校验：rule.id/level 数值合理、id 数值化、location 可辨识。"""
    rid = to_int(m.get("_source.rule.id"))
    lvl = to_int(m.get("_source.rule.level"))
    if rid is None or lvl is None or not (0 <= lvl <= 16):
        return False
    wid = norm(m.get("_source.id"))
    if wid and not wid.replace(".", "", 1).isdigit():
        return False
    loc = norm(m.get("_source.location"))
    if loc and not (loc in ("rootcheck", "sca", "syscheck") or loc.startswith("/")):
        return False
    return True


def _linux_record(m: dict) -> dict:
    agent = {k: m.get(f"_source.agent.{k}") for k in ("id", "name", "ip") if m.get(f"_source.agent.{k}")}
    rule_desc = norm(m.get("_source.rule.description")) or None
    groups = maybe_json(m.get("_source.rule.groups"))
    level = to_int(m.get("_source.rule.level"))
    # 规则级 MITRE。恶意/可疑推断只看"规则命中映射"三元组(id/technique/tactic)；
    # mitre_tactics/mitre_techniques 数组多为 SCA 合规映射（如 T1200 配置项），仅作信息保留不参与标签。
    mitre = {
        "id": norm(m.get("_source.rule.mitre.id")) or None,
        "technique": maybe_json(m.get("_source.rule.mitre.technique")) or None,
        "tactic": norm(m.get("_source.rule.mitre.tactic")) or None,
        "techniques": maybe_json(m.get("_source.rule.mitre_techniques")) or None,
        "tactics": maybe_json(m.get("_source.rule.mitre_tactics")) or None,
    }
    mitre_present = bool(mitre["id"] or mitre["technique"] or mitre["tactic"])
    full_log = norm(m.get("_source.full_log")) or None
    text = full_log or (norm(m.get("_source.previous_log")) or None) or rule_desc or ""
    ts_raw = norm(m.get("_source.timestamp")) or norm(m.get("_source.@timestamp")) or None
    ts = parse_ts(ts_raw) if ts_raw else None
    alert_id = norm(m.get("_source.id")) or norm(m.get("_id")) or None
    # 核心字段之外的其余列全部保留进 extra（保留原扁平路径命名）
    core_keys = {
        "_index", "_id", "_version", "_score",
        "_source.id", "_source.timestamp", "_source.@timestamp", "_source.full_log",
        "_source.previous_log", "_source.previous_output", "_source.extra_data",
        "_source.input.type", "_source.location",
        "_source.agent.id", "_source.agent.name", "_source.agent.ip",
        "_source.manager.name",
        "_source.decoder.name", "_source.decoder.parent",
        "_source.predecoder.hostname", "_source.predecoder.program_name", "_source.predecoder.timestamp",
        "_source.rule.id", "_source.rule.level", "_source.rule.description", "_source.rule.groups",
        "_source.rule.firedtimes", "_source.rule.mail",
        "_source.rule.mitre.id", "_source.rule.mitre.technique", "_source.rule.mitre.tactic",
        "_source.rule.mitre_tactics", "_source.rule.mitre_techniques", "_source.rule.mitre_mitigations",
    }
    extra = {k: maybe_json(v) for k, v in m.items() if k not in core_keys}
    return {
        "dataset": "linux-apt",
        "alert_id": alert_id,
        "index": norm(m.get("_index")) or None,
        "agent": agent or None,
        "os": "linux",
        "time": ts,
        "time_raw": ts_raw,
        "rule": {
            "id": to_int(m.get("_source.rule.id")),
            "level": level,
            "description": rule_desc,
            "groups": groups,
            "firedtimes": to_int(m.get("_source.rule.firedtimes")),
        },
        "mitre": mitre if mitre_present else None,
        "decoder": {
            "name": norm(m.get("_source.decoder.name")) or None,
            "parent": norm(m.get("_source.decoder.parent")) or None,
        } if (m.get("_source.decoder.name") or m.get("_source.decoder.parent")) else None,
        "location": norm(m.get("_source.location")) or None,
        "program": norm(m.get("_source.predecoder.program_name")) or None,
        "text": text,
        "priority": priority_of_level(level),
        "verdict": {
            "is_malicious": bool(mitre_present),   # 论文口径：规则级 MITRE 非空即可疑
            "method": "rule_mitre_present",
        },
        "extra": extra,
    }


def preprocess_linux_apt() -> dict:
    if not os.path.exists(RAW_LINUX):
        print(f"[linux-apt] 找不到原始文件：{RAW_LINUX}")
        sys.exit(1)
    stats = collections.Counter()
    family = collections.Counter()
    labels = collections.Counter()
    levels = collections.Counter()
    n_seg = 0
    kept = 0
    seen: set = set()
    out_path = os.path.join(OUT_DIR, "linux_apt_alerts.jsonl")
    os.makedirs(OUT_DIR, exist_ok=True)
    print("[linux-apt] 流式解析", RAW_LINUX, "...")
    with open(RAW_LINUX, "r", encoding="utf-8", errors="replace", newline="") as fin, \
         open(out_path, "w", encoding="utf-8") as fout:
        reader = csv.reader(fin)
        header: Optional[list[str]] = None
        for row in reader:
            if not row:
                stats["empty"] += 1
                continue
            if row[0] == "_index":
                header = row
                n_seg += 1
                stats["header_seg"] += 1
                continue
            if header is None:
                stats["pre_header"] += 1
                continue
            stats["data_rows_total"] += 1
            if len(row) != len(header):
                stats["reject_misaligned"] += 1
                continue
            m = _cell_map(row, header)
            if not _linux_row_plausible(m):
                stats["reject_implausible"] += 1
                continue
            key = (norm(m.get("_index")), norm(m.get("_id")), norm(m.get("_source.id")))
            if key in seen:
                stats["dup"] += 1
                continue
            seen.add(key)
            rec = _linux_record(m)
            # 统计口径
            labels[rec["verdict"]["is_malicious"]] += 1
            levels[rec["rule"]["level"] or "?"] += 1
            g = (rec["rule"]["groups"] or [None])[0]
            family[g if isinstance(g, str) else "(none)"] += 1
            fout.write(json.dumps(rec, ensure_ascii=False) + "\n")
            kept += 1
    res = {
        "dataset": "linux-apt",
        "raw_file": RAW_LINUX,
        "segments_headers": n_seg,
        "counts": dict(stats),
        "kept": kept,
        "is_malicious_label": dict(labels),
        "rule_level_dist": {str(k): v for k, v in sorted(levels.items(), key=lambda x: str(x[0]))},
        "event_family_top": family.most_common(15),
        "output": out_path,
    }
    with open(os.path.join(OUT_DIR, "linux_apt_stats.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print("[linux-apt] 完成。保留", kept, "条 →", out_path)
    print("[linux-apt] 统计：", json.dumps(res["counts"], ensure_ascii=False),
          "| 恶意推断标签:", dict(labels), "| 等级分布:", res["rule_level_dist"])
    return res


# ---------------------------------------------------------------------------
# llm-soc-alert-triage
# ---------------------------------------------------------------------------

def _find_merged() -> str:
    files = sorted(glob.glob(os.path.join(LLM_SOC_MERGED_DIR, "2_alerts_preprocessed_merged_*.jsonl")))
    if not files:
        print(f"[llm-soc] 找不到 merged 文件：{LLM_SOC_MERGED_DIR}")
        sys.exit(1)
    return files[0]


def _llm_soc_time(alert: dict) -> tuple[Optional[dict], Optional[str]]:
    src = deep_get(alert, "_source") or {}
    raw = None
    for cand in ("timestamp", "@timestamp"):
        v = src.get(cand)
        if v:
            raw = v
            break
    if raw is None:
        raw = deep_get(src, "data", "win", "system", "systemTime")
    ts = parse_ts(raw) if raw else None
    return ts, raw


def _llm_soc_text(alert: dict, description: str) -> str:
    """研判输入文本：优先 sysmon 事件原文，其次 full_log，否则规则描述。"""
    src = deep_get(alert, "_source") or {}
    msg = deep_get(src, "data", "win", "system", "message")
    full = src.get("full_log")
    if isinstance(msg, str) and msg.strip():
        text = msg.strip()
    elif isinstance(full, str) and full.strip():
        text = full.strip()
    else:
        text = description or ""
    return text


def preprocess_llm_soc() -> dict:
    merged = _find_merged()
    stats = collections.Counter()
    label_c = collections.Counter()
    prio_c = collections.Counter()
    n = 0
    out_path = os.path.join(OUT_DIR, "llm_soc_alerts.jsonl")
    os.makedirs(OUT_DIR, exist_ok=True)
    print("[llm-soc] 解析", merged, "...")
    with open(merged, "r", encoding="utf-8") as fin, \
         open(out_path, "w", encoding="utf-8") as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            e = json.loads(line)
            alert = e.get("alert") or {}
            src = deep_get(alert, "_source") or {}
            agent = src.get("agent") or {}
            rule = src.get("rule") or {}
            groups = rule.get("groups") if isinstance(rule.get("groups"), list) else None
            mitre_tech = rule.get("mitre", {}).get("technique") if isinstance(rule.get("mitre"), dict) else None
            ts, ts_raw = _llm_soc_time(alert)
            desc = e.get("description")
            if desc is None or desc == "MISSING":
                desc = rule.get("description") or None
            rec = {
                "dataset": "llm-soc",
                "alert_id": e.get("id"),
                "index": alert.get("_index"),
                "agent": {k: agent.get(k) for k in ("id", "name", "ip") if agent.get(k)} or None,
                "os": "windows" if deep_get(src, "data", "win") else ("linux" if src.get("full_log") else None),
                "time": ts,
                "time_raw": ts_raw,
                "rule": {
                    "id": rule.get("id") or None,
                    "level": e.get("rule_level"),
                    "description": desc,
                    "groups": groups,
                    "firedtimes": None,
                },
                "mitre": {"technique": mitre_tech} if mitre_tech else None,
                "decoder": None,
                "location": src.get("location"),
                "program": deep_get(src, "data", "win", "system", "providerName"),
                "text": _llm_soc_text(alert, e.get("description") or ""),
                "priority": priority_of_level(e.get("rule_level")),
                "verdict": {
                    "label": e.get("label"),          # ground truth：TP / FP
                    "gt_priority": e.get("rule_priority"),
                    "method": "official_label",
                },
                "extra": {"raw_alert": alert},         # 官方清洗后的完整告警（已移除 rule.level）
            }
            stats["rows"] += 1
            label_c[e.get("label")] += 1
            prio_c[e.get("rule_priority")] += 1
            fout.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n += 1
    res = {
        "dataset": "llm-soc",
        "source_merged": merged,
        "kept": n,
        "counts": dict(stats),
        "labels": dict(label_c),
        "priorities": dict(prio_c),
        "output": out_path,
    }
    with open(os.path.join(OUT_DIR, "llm_soc_stats.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print("[llm-soc] 完成。保留", n, "条 →", out_path)
    print("[llm-soc] label:", dict(label_c), "| priority:", dict(prio_c))
    return res


def main() -> None:
    ap = argparse.ArgumentParser(description="两份本地数据集统一预处理 → data/processed/")
    ap.add_argument("target", nargs="?", default="all",
                    choices=["all", "linux-apt", "llm-soc"], help="默认处理全部")
    args = ap.parse_args()
    if args.target in ("all", "linux-apt"):
        preprocess_linux_apt()
    if args.target in ("all", "llm-soc"):
        preprocess_llm_soc()


if __name__ == "__main__":
    main()
