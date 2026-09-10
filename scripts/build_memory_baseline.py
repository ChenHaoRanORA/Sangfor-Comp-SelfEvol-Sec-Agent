# -*- coding: utf-8 -*-
"""阶段四 · 片段基线构建：把 v1 Agent 的处置事件 JSONL 沉淀为多层记忆的第一层——历史片段。

流程：
    事件 JSONL（log/agent_v1_*_full_*.jsonl）→ Fragment 列表
        → MemoryStore.add_fragments（SQLite 结构化入库，幂等；embed 时同步入 Chroma）

Fragment 字段说明：
    - fragment_id = frag-{dataset}-{seq:05d}（seq 在数据集中唯一，保证幂等可重入）
    - rule_id / rule_level / groups：取事件首个命中 RuleHit（摘要用）
    - classification / verdict_priority / method / llm_error：取 Verdict（Agent 处置结论）
    - mitre：RuleHit 携带的 MITRE（数据集可能缺失）
    - summary：浓缩文本（规则描述 + 判定理由 + 主机/数据集上下文），供向量检索与模式归纳
    - source：原始 AlertEvent（完整保留，供溯源/后续回放）

用法（conda scssa，仓库根）：
    python scripts/build_memory_baseline.py                        # 默认两份离线基线日志
    python scripts/build_memory_baseline.py --no-embed             # 只写 SQLite 不写向量
    python scripts/build_memory_baseline.py --limit 200            # 调试：只看前 200 条/数据集
"""
from __future__ import annotations

import argparse
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.memory.models import Fragment, now_ms  # noqa: E402
from src.core.memory.store import MemoryStore  # noqa: E402

# dataset 键映射：事件 JSONL 里的 dataset → 存储/挖掘统一键
DATASET_KEY = {"linux-apt": "linux", "llm-soc": "llm-soc"}

DEFAULT_EVENTS = [
    "log/agent_v1_llm_soc_full_178.jsonl",
    "log/agent_v1_linux_full_offline.jsonl",
]


def load_events(path: str, limit: int) -> list[dict]:
    out = []
    with io.open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
            if limit and len(out) >= limit:
                break
    return out


def to_fragment(ev: dict) -> Fragment:
    """事件 → 片段。单条事件独立成片段（Agent 单条告警处置即一次记忆沉淀）。"""
    hits = ev.get("rule_hits") or []
    first = hits[0] if hits else {}
    verdict = ev.get("verdict") or {}
    ds = DATASET_KEY.get(ev.get("dataset", ""), ev.get("dataset", ""))
    seq = int(ev.get("seq") or 0)

    # 浓缩文本：规则描述（若有）+ 判定理由（LLM justification / 规则回退模板）
    parts = []
    desc = (first.get("description") or "").strip()
    if desc:
        parts.append(desc)
    just = (verdict.get("justification") or "").strip()
    if just:
        parts.append(just)
    summary = " | ".join(parts)
    if not summary:
        summary = f"{ds} 事件 seq={seq}（rule {first.get('rule_id')}）"

    return Fragment(
        fragment_id=f"frag-{ds}-{seq:05d}",
        dataset=ds,
        alert_id=ev.get("alert_id"),
        seq=seq,
        host=str(ev.get("agent_name") or "-"),
        ts_ms=ev.get("ts_ms"),
        rule_id=str(first.get("rule_id")) if first.get("rule_id") is not None else None,
        rule_level=first.get("level"),
        groups=first.get("groups") or [],
        mitre=first.get("mitre") or (ev.get("mitre") or None),
        classification=verdict.get("classification"),
        verdict_priority=str(verdict.get("priority") or "low"),
        method=str(verdict.get("method") or "none"),
        llm_error=bool(verdict.get("llm_error")),
        summary=summary,
        source=ev,                      # 原始 AlertEvent 全量保留
        created_at=now_ms(),
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="阶段四：Agent 事件 → 历史片段基线")
    ap.add_argument("--events", nargs="*", default=None,
                    help="事件 JSONL 路径（默认两份 full 基线日志）")
    ap.add_argument("--limit", type=int, default=0, help="每个数据集只取前 N 条（调试）")
    ap.add_argument("--no-embed", action="store_true", help="不写 Chroma 向量（只 SQLite）")
    ap.add_argument("--db", default="", help="SQLite 路径（默认 data/memory/memory.db）")
    args = ap.parse_args()

    store = MemoryStore(db_path=args.db) if args.db else MemoryStore()
    paths = args.events or DEFAULT_EVENTS
    total_added, per = 0, {}
    for path in paths:
        if not os.path.exists(path):
            print(f"[skip] 缺失事件日志: {path}")
            continue
        evs = load_events(path, args.limit)
        frags = [to_fragment(e) for e in evs]
        ds = frags[0].dataset if frags else os.path.basename(path)
        n = store.add_fragments(frags, embed=not args.no_embed)
        total_added += n
        per[ds] = (len(evs), n)
        # 摘要
        from collections import Counter
        cls = Counter(f.classification or "None" for f in frags)
        err = sum(1 for f in frags if f.llm_error)
        print(f"[{ds}] 读取 {len(evs)} 事件 → 新增片段 {n}（classification={dict(cls)}，llm_error={err}）")
        if not args.no_embed:
            import shutil
            from src.core.memory.store import FRAGMENT_COLLECTION
            chroma_dir = store.chroma_dir
            print(f"[{ds}] 向量已尝试写入 {chroma_dir}/{FRAGMENT_COLLECTION}")
            _ = shutil  # noqa
    print(f"\n===== 片段基线汇总 =====")
    print(f"  新增片段总数: {total_added}")
    for ds, (read, added) in per.items():
        print(f"  {ds:<9}: 事件 {read:<6} 新增 {added}")
    print(f"  库内片段: llm-soc={store.count_fragments('llm-soc')} linux={store.count_fragments('linux')}")
    store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
