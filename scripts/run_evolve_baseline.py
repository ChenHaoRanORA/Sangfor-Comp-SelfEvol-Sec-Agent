# -*- coding: utf-8 -*-
"""阶段四 · 自进化离线跑批：模式挖掘 → 衍生规则编译 → fired 基线回放。

对已沉淀的历史片段（data/memory/memory.db）跑：
    1. PatternMiner.mine(dataset)   —— 片段簇/链 → 可疑模式（有界 LLM 归纳 + 启发式兜底）
    2. RuleCompiler.run(dataset)    —— active 模式 → 衍生规则（DSL/severity/审计，受 auto_evolve 门控）
    3. RuleCompiler.replay_baseline —— 按支撑片段回放 fired 基线（衍生规则生效次数）

用法（conda scssa，仓库根，可选 LLM）：
    python scripts/run_evolve_baseline.py --dataset llm-soc          # 有界 LLM 归纳
    python scripts/run_evolve_baseline.py --dataset all --no-llm     # 全部启发式，不调 LLM
说明：
    --max-llm 控制本批行为链候选的最大真实 LLM 调用次数（默认 8，成本有界）；
    LLM 不可用/失败自动启发式兜底，不中断基线；
    重复跑批：已 active 并带 derived_rule_id 的模式会被跳过（幂等）。
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config.settings import Settings  # noqa: E402
from src.core.evolve.derive import RuleCompiler  # noqa: E402
from src.core.evolve.miner import PatternMiner  # noqa: E402
from src.core.knowledge.graph import KnowledgeKB  # noqa: E402
from src.core.llm.client import LLMClient  # noqa: E402
from src.core.memory.store import MemoryStore  # noqa: E402

DATASETS = ("llm-soc", "linux")


def main() -> int:
    ap = argparse.ArgumentParser(description="阶段四：离线自进化跑批")
    ap.add_argument("--dataset", choices=["llm-soc", "linux", "all"], default="all")
    ap.add_argument("--no-llm", action="store_true", help="禁用真实 LLM（启发式归纳）")
    ap.add_argument("--no-kb", action="store_true", help="跳过知识图谱补全")
    ap.add_argument("--max-llm", type=int, default=8, help="每数据集行为链候选 LLM 调用预算")
    args = ap.parse_args()

    store = MemoryStore()
    print(f"[evo] auto_evolve={store.auto_evolve()}，"
          f"片段: llm-soc={store.count_fragments('llm-soc')} linux={store.count_fragments('linux')}")

    # 基础设施：LLM（可失败，启发式兜底）+ 知识图谱（可跳过）
    s = Settings.from_env()
    llm = None
    if not args.no_llm and s.llm_enabled:
        llm = LLMClient(s)
        print(f"[evo] LLM 启用 {s.llm_model} @ {s.llm_base_url}（预算 {args.max_llm}/数据集）")
    else:
        print("[evo] LLM 未启用 → 全部启发式归纳")
    kb = None
    if not args.no_kb:
        try:
            kb = KnowledgeKB()
            st = kb.stats()
            if st.get("ok"):
                print(f"[evo] 图谱就绪: technique={st['counts']['technique']} tactic={st['counts']['tactic']}")
            else:
                print(f"[evo] 图谱不可用（跳过补全）: {st.get('error')}")
                kb = None
        except Exception as exc:  # noqa: BLE001
            print(f"[evo] 图谱打开失败（跳过补全）: {type(exc).__name__}: {exc}")
            kb = None

    ds_list = DATASETS if args.dataset == "all" else (args.dataset,)
    miner = PatternMiner(store, llm=llm, kb=kb, max_llm=args.max_llm)
    compiler = RuleCompiler(store, by="system")

    for ds in ds_list:
        print(f"\n===== [{ds}] 1/3 模式挖掘 =====")
        pats = miner.mine(ds)
        print(f"[{ds}] 新模式 {len(pats)} 个 → 库内 pattern: "
              f"all={len(store.patterns(dataset=ds))} active={len(store.patterns(dataset=ds, state='active'))}")

        print(f"[{ds}] 2/3 衍生规则编译")
        res = compiler.run(ds)
        if not res.get("auto_evolve"):
            print(f"[{ds}] ⚠ auto_evolve=off，跳过编译：{res['note']}")
            continue
        print(f"[{ds}] 新建衍生规则 {len(res['created'])} 个，跳过 {len(res['skipped'])}（重复/不达标）")
        for r in res["created"]:
            print(f"    - {r['rule_id']} [{r['state']}/{r['severity']}] {r['name'][:50]}")

        print(f"[{ds}] 3/3 fired 基线回放")
        fb = compiler.replay_baseline(ds)
        fired = fb["fired"]
        print(f"[{ds}] 回放 {len(fired)} 条衍生规则生效计数：")
        for rid, v in fired.items():
            print(f"    - {rid}: fired={v['fired']} last={v['last_triggered_at']}")

    print("\n===== 自进化状态快照 =====")
    print(json_pretty(store.stats()))
    store.close()
    if kb is not None:
        kb.close()
    return 0


def json_pretty(d: dict) -> str:
    import json
    return json.dumps(d, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    raise SystemExit(main())
