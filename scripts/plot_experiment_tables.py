# -*- coding: utf-8 -*-
"""为自进化安全智能体的关键实验绘制 PPT 用「指标汇总表格图」。

数据来源（全部为真实运行产物，数值与 log/eval_joint/summary.json、实验记录.md 一致）：
  - 图1：llm-soc 178 条带标签基准 评测与消融（baseline / +记忆 / +图谱 / 联合）；
  - 图2：自进化链路产物规模与闭环验证一览（真实库 memory.db 基线 + 冒烟/sanity）；
  - 图3：演进路线·待补强项与预期收益（* 为按既有趋势的外推估计，非实测）。

运行（conda scssa）：
  python scripts/plot_experiment_tables.py
产物：docs/experiments/figs/*.png（dpi=200）
"""
from __future__ import annotations

import os
import re

import matplotlib
matplotlib.use("Agg")
from matplotlib import font_manager as fm
from matplotlib import pyplot as plt

OUT_DIR = os.path.join("docs", "experiments", "figs")

# 配色（浅色科技风）
INK = "#0b2447"          # 主标题/表头深蓝
SUB = "#5b6b7f"          # 副标题灰
TXT = "#1a2634"          # 正文
ACC = "#0b6bcb"          # 强调蓝
HEAD_BG = "#0b2447"
ROW_A = "#ffffff"
ROW_B = "#eff5fb"
HL_BG = "#d3e9ff"        # 最优值底
NEG_BG = "#fdecec"       # 负向行底
GRID = "#d4dee8"
MUTE = "#98a5b4"
NOTE = "#64748b"


def resolve_cjk_family() -> str:
    names = {f.name for f in fm.fontManager.ttflist}
    for cand in ("Microsoft YaHei", "Microsoft YaHei UI", "SimHei", "DengXian"):
        if cand in names:
            return cand
    for path in (r"C:/Windows/Fonts/msyh.ttc", r"C:/Windows/Fonts/msyhbd.ttc",
                 r"C:/Windows/Fonts/simhei.ttf"):
        if os.path.exists(path):
            try:
                fm.fontManager.addfont(path)
                return fm.FontProperties(fname=path).get_name()
            except Exception:  # noqa: BLE001
                continue
    return "DejaVu Sans"


FAMILY = resolve_cjk_family()


def _as_num(s: str):
    s = s.strip().replace(",", "").replace("％", "%")
    if s in ("—", "-", "", "None"):
        return None
    if s.endswith("%"):
        try:
            return float(s[:-1])
        except ValueError:
            return None
    try:
        return float(s)
    except ValueError:
        return None


def _style_cell(cell, text, *, header=False, row_i=0, col_i=0, fill=None,
                fg=None, bold=False, align="center", fontsize=9.5):
    cell.set_text_props(
        ha="left" if align == "left" else "center",
        va="center",
        color=fg or ("#ffffff" if header else TXT),
        fontsize=fontsize,
        fontweight="bold" if (header or bold) else "normal",
        family=FAMILY,
    )
    cell.set_facecolor(fill or (HEAD_BG if header else (ROW_A if row_i % 2 else ROW_B)))
    cell.set_edgecolor(GRID if not header else HEAD_BG)
    cell.set_linewidth(0.6 if not header else 1.0)
    cell.PAD = 0.03
    cell.height = cell.get_height()
    cell.width = cell.get_width()


def _auto_highlights(rows, hl_cols, best_modes, skip_rows=(0,)):
    """hl_cols: 数值列下标；best_modes 同长（max/min）。返回 {(r,c)}（r 为数据行 0 基）。"""
    out = set()
    for idx, col in enumerate(hl_cols):
        vals = {i: _as_num(rows[i][col]) for i in range(len(rows)) if i not in skip_rows}
        nums = [v for v in vals.values() if v is not None]
        if not nums:
            continue
        target = max(nums) if best_modes[idx] == "max" else min(nums)
        for i, v in vals.items():
            if v is not None and v == target:
                out.add((i, col))
    return out


def render_table(path: str, title: str, subtitle: str, headers: list,
                 rows: list, notes: list, *, widths=None, aligns=None,
                 hl_cols=(), best_modes=(), hl_skip=(0,), accent_cols=(),
                 neg_rows=(), figsize=None, fontsize=9.5) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    n_cols, n_data = len(headers), len(rows)
    n_rows = n_data + 1

    if widths is None:
        widths = [0.20] + [(1 - 0.20) / (n_cols - 1)] * (n_cols - 1)
    widths = [w / sum(widths) for w in widths]
    aligns = aligns or ["center"] * n_cols
    if figsize is None:
        figsize = (5.0 + 2.3 * n_cols, 2.35 + 0.42 * n_rows)

    fig, ax = plt.subplots(figsize=figsize)
    fig.patch.set_facecolor("white")
    ax.axis("off")

    fig.text(0.018, 0.972, title, ha="left", va="top", fontsize=15.5,
             fontweight="bold", color=INK, family=FAMILY)
    fig.text(0.018, 0.930, subtitle, ha="left", va="top", fontsize=9,
             color=SUB, family=FAMILY)

    tbl = ax.table(
        cellText=[headers] + rows,
        colLabels=None,
        cellLoc="center",
        loc="center",
        bbox=[0.012, 0.02, 0.976, 0.855],
        colWidths=widths,
    )
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(fontsize)
    hl = _auto_highlights(rows, list(hl_cols), list(best_modes), skip_rows=hl_skip)

    for key, cell in tbl.get_celld().items():
        r, c = key
        if r == 0:
            _style_cell(cell, headers[c], header=True, fontsize=fontsize + 0.5)
            continue
        i = r - 1  # 数据行 0 基
        text = rows[i][c]
        is_accent = c in accent_cols
        if (i, c) in hl:
            _style_cell(cell, text, row_i=i, col_i=c, fill=HL_BG, fg=INK,
                        bold=True, align=aligns[c], fontsize=fontsize)
        elif i in neg_rows and c == 0:
            _style_cell(cell, text, row_i=i, fill=NEG_BG, fg="#8f1f1f",
                        bold=True, align=aligns[c], fontsize=fontsize)
        elif is_accent:
            _style_cell(cell, text, row_i=i, fill="#e8f2fc", fg=ACC,
                        bold=True, align=aligns[c], fontsize=fontsize)
        elif text in ("—", "-"):
            _style_cell(cell, text, row_i=i, fg=MUTE, align=aligns[c],
                        fontsize=fontsize)
        else:
            _style_cell(cell, text, row_i=i, bold=(c == 0),
                        align=aligns[c], fontsize=fontsize)
        if c == 0:
            cell.set_text_props(ha="left")

    if notes:
        txt = "\n".join(notes)
        fig.text(0.018, 0.012, txt, ha="left", va="bottom", fontsize=8.3,
                 color=NOTE, family=FAMILY)

    plt.savefig(path, dpi=200, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("saved:", os.path.abspath(path))


# ===================================================================== 图1
def fig1_metrics() -> None:
    headers = ["实验配置", "Acc 全量", "Acc 已判", "Macro-F1", "检出 精确率",
               "检出 召回率", "检出 F1", "误报 F1", "未知率"]
    rows = [
        ["首轮研判基线（阶段三 · 独立口径）", "76.4%", "—", "—",
         "89.7%", "67.3%", "76.9%", "—", "—"],
        ["消融 · 基线（无任何证据）", "75.8%", "78.0%", "78.0%",
         "89.7%", "70.0%", "78.7%", "77.4%", "1.7%"],
        ["消融 · 追加 多层记忆", "80.3%", "81.3%", "81.2%",
         "91.6%", "74.5%", "82.2%", "80.2%", "1.1%"],
        ["消融 · 追加 知识图谱（单独）", "73.6%", "76.6%", "76.6%",
         "90.7%", "67.3%", "77.3%", "75.9%", "3.9%"],
        ["消融 · 记忆 + 图谱（联合）", "80.3%", "81.3%", "81.2%",
         "91.7%", "74.8%", "82.4%", "80.0%", "1.1%"],
    ]
    notes = [
        "数据来源：llm-soc 178 条带标签告警（官方 TP=104 / FP=74），DeepSeek 实判，temperature=0；流式切分、仅引用 seq<当前（防泄漏）。",
        "注① 首行按阶段三独立跑批口径实测（全量逐条研判），未按“流式切分/已判”口径重统，故不参与最优标注。",
        "浅蓝底＝同评测口径下行内最优：记忆(第3行)/联合(第5行)相对基线(第2行) Acc 全量 +4.5pp、检出 F1 +3.5~3.7pp；仅图谱(第4行) −2.2pp——增益主要来自经验记忆。",
    ]
    render_table(
        os.path.join(OUT_DIR, "t1_llm_soc_metrics.png"),
        "核心评测与证据消融 · llm-soc 178 条基准",
        "三辅助引擎对 LLM 研判的贡献对比（人工规则＝权威直发省 LLM，不参与本表准确率口径；表中对比记忆/图谱证据注入）",
        headers, rows, notes,
        widths=[0.20] + [0.10] * 8, fontsize=9.8,
        aligns=["left"] + ["center"] * 8,
        hl_cols=range(1, 9), best_modes=["max"] * 8, hl_skip=(0,),
    )


# ===================================================================== 图2
def fig2_evolve() -> None:
    headers = ["自进化环节 / 验证", "规模 / 结果", "说明（均为真实运行产物）"]
    rows = [
        ["历史处置经验片段 Fragment", "9,535",
         "每次告警处置沉淀一条经验（llm-soc 178 实判 + linux 9,357 规则回放），SQLite+Chroma 向量化，可语义召回"],
        ["可疑模式 Pattern", "36（均 active）",
         "miner：同主机 3 分钟窗内 ≥3 条规则共现的行为链 + 有界 LLM 归纳；全部带审计、可溯源"],
        ["衍生规则 DerivedRule", "36（27 active + 9 draft）",
         "active 实时参与处置命中；draft＝高误报 fp_noise 降噪提议，需人工确认启用"],
        ["建议升格候选（规则建议页）", "27",
         "经验证有含金量的衍生规则 → 前端逐条附 LLM 自然语言解释，人工 同意升格 / 拒绝（拒绝仅退出推荐）"],
        ["人工权威规则 Manual", "0",
         "真实库暂无（auto=0 需人工拍板升格）；入口已就绪——命中即直发、不耗 LLM"],
        ["v3 分流 sanity（真实库 no-LLM）", "174 / 4 / 0",
         "llm-soc 178 条 → memory 通道 174 · policy 4 · manual 0（库内无人工规则，符合预期）"],
        ["v3 隔离冒烟 smoke", "16 / 16 通过",
         "人工命中不唤醒 LLM / 可疑模式命中必走 LLM 且计数 / 冲突反馈幂等、防泄漏"],
        ["首轮 178 条全量跑批", "178 / 178 命中",
         "LLM 实判 176，2 次 JSON 非法自动回退规则结论（机制按设计）；异常通知 0"],
    ]
    notes = [
        "数据来源：真实库 data/memory/memory.db（WAL）+ 阶段三~六各次实验记录 / 冒烟脚本；说明列口径同各实验产物。",
        "自进化闭环：处置沉淀 → 模式归纳 → 规则编译 → 验证命中 → 前端呈现候选 → 人工拍板升格，任意跳步可溯源（规则→模式→片段）。",
    ]
    render_table(
        os.path.join(OUT_DIR, "t2_evolve_scale.png"),
        "自进化链路产物规模与闭环验证一览",
        "阶段四基线（9535 片段 / 36 模式 / 36 衍生规则）＋ 阶段六处置分流 v3 冒烟与真实库 sanity",
        headers, rows, notes,
        widths=[0.20, 0.17, 0.63], fontsize=9.6,
        aligns=["left", "center", "left"],
        accent_cols=(1,), figsize=(15.6, 6.4),
    )


# ===================================================================== 图3
def fig3_forecast() -> None:
    headers = ["待补强方向", "现状依据（实测）", "预期收益（* 外推估计）"]
    rows = [
        ["经验闭环补强：冲突沉淀 → 再挖模式 → 再验证",
         "记忆证据已带来净 +4.5pp Acc；当前 fb 冲突片段与“处置后再挖”尚未开环",
         "Acc 全量 80.3% → 81.5~82%*；误报 F1 保持 ≥80%*"],
        ["低危告警“成链”召回引导",
         "首轮漏检 34 条官方 TP 集中于低危规则（level 3/4 占 22 条），LLM 倾向判 FP",
         "检出召回 67~75% → ≥75%*，低危漏检减少约 1/3*"],
        ["优先级/定级口径统一校准",
         "优先级一致率仅 49~54%（LLM 按内容定级 vs 官方按规则等级，口径不一致）",
         "重定义判据后优先级一致率 → ≥70%*"],
        ["人工规则池逐步引入（27 候选升格）",
         "真实库 manual=0；命中人工规则可直发（manual 通道）且不耗 LLM",
         "manual 直发占比由 0 逐步上升，整体 LLM 调用量下降*"],
    ]
    notes = [
        "注：带 * 数值为依据既有实测趋势的外推/规划估计（供 PPT 展望与实验规划参考），并非已测得结果；实测列全部来自本仓库运行产物。",
    ]
    render_table(
        os.path.join(OUT_DIR, "t3_forecast.png"),
        "演进路线 · 待补强项与预期收益（预测补全）",
        "结合已定位短板（召回/定级口径/自进化未开环）给出的下一步实验假设",
        headers, rows, notes,
        widths=[0.24, 0.37, 0.39], fontsize=9.6,
        aligns=["left", "left", "left"], figsize=(15.6, 4.6),
    )


def main() -> None:
    plt.rcParams["font.family"] = FAMILY
    plt.rcParams["axes.unicode_minus"] = False
    plt.rcParams["font.sans-serif"] = [FAMILY, "DejaVu Sans"]
    print("cjk font:", FAMILY)
    fig1_metrics()
    fig2_evolve()
    fig3_forecast()
    print("done ->", os.path.abspath(OUT_DIR))


if __name__ == "__main__":
    main()
