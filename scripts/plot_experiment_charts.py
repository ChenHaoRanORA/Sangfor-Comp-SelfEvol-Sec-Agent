# -*- coding: utf-8 -*-
"""PPT 用 4 张多维对比图（matplotlib，数据与 log/eval_joint/summary.json 一致）。

c1_ablation_grouped.png  关键指标分组柱状：基线 / +记忆 / +图谱 / 记忆+图谱 × 4 项指标
c2_pr_scatter.png        检出 精确率-召回率 平面散点（含 Macro F1 等值线），4 配置 + v1 首轮
c3_radar.png             六维能力雷达：基线 vs +记忆 vs +图谱 vs 联合
c4_evolution_funnel.png  自进化收敛漏斗（9535 片段→…→27 候选）+ 处置分流三通道成本对比

运行：conda run -n scssa python scripts/plot_experiment_charts.py
产物：docs/experiments/figs/c*.png（dpi=200）
"""
from __future__ import annotations

import os

import matplotlib
matplotlib.use("Agg")
import numpy as np
from matplotlib import font_manager as fm
from matplotlib import pyplot as plt
from matplotlib.path import Path
from matplotlib.patches import PathPatch

OUT_DIR = os.path.join("docs", "experiments", "figs")

# 统一浅色科技风
INK = "#0b2447"
SUB = "#5b6b7f"
TXT = "#1a2634"
GRID = "#dbe4ee"
ACC = "#0ea5e9"

CONF_CFG = [
    ("基线（无证据）",   "#94a3b8"),
    ("+ 多层记忆",       "#0ea5e9"),
    ("+ 知识图谱",       "#f59e0b"),
    ("记忆 + 图谱",      "#10b981"),
]

# 消融核心指标（%）
METRICS = ["Acc 全量", "Macro-F1", "检出 F1", "误报 F1"]
ABL = {  # config index -> metrics
    0: [75.8, 78.0, 78.7, 77.4],
    1: [80.3, 81.2, 82.2, 80.2],
    2: [73.6, 76.6, 77.3, 75.9],
    3: [80.3, 81.2, 82.4, 80.0],
}


def resolve_cjk_family() -> str:
    names = {f.name for f in fm.fontManager.ttflist}
    for cand in ("Microsoft YaHei", "Microsoft YaHei UI", "SimHei", "DengXian"):
        if cand in names:
            return cand
    for path in (r"C:/Windows/Fonts/msyh.ttc", r"C:/Windows/Fonts/simhei.ttf"):
        if os.path.exists(path):
            try:
                fm.fontManager.addfont(path)
                return fm.FontProperties(fname=path).get_name()
            except Exception:  # noqa: BLE001
                continue
    return "DejaVu Sans"


FAMILY = resolve_cjk_family()


def _fin(ax, file: str, fig) -> None:
    fig.savefig(os.path.join(OUT_DIR, file), dpi=200, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("saved:", os.path.abspath(os.path.join(OUT_DIR, file)))


# ---------------------------------------------------------------- c1 分组柱状
def chart1_grouped() -> None:
    fig, ax = plt.subplots(figsize=(9.8, 6.4))
    fig.patch.set_facecolor("white")
    # 顶部 34% 专门留给「两行标题 + 一行图例」，图例绝不落进绘图区
    fig.subplots_adjust(top=0.66, bottom=0.14, left=0.085, right=0.97)
    x = np.arange(len(METRICS))
    w = 0.2
    for i, (name, color) in enumerate(CONF_CFG):
        vals = ABL[i]
        off = (i - 1.5) * w
        bars = ax.bar(x + off, vals, width=w * 0.9, label=name, color=color,
                      edgecolor="white", linewidth=0.6, zorder=3)
        # 只给“+多层记忆 / 联合”标数值，避免视觉噪声
        if i in (1, 3):
            for b, v in zip(bars, vals):
                ax.text(b.get_x() + b.get_width() / 2, v + 0.45, f"{v:.1f}",
                        ha="center", va="bottom", fontsize=7.6, color=color,
                        fontweight="bold")
    ax.set_xticks(x, METRICS, fontsize=10.5)
    ax.set_ylim(72, 85.5)
    ax.set_ylabel("得分（%）", fontsize=10)
    ax.grid(axis="y", color=GRID, linewidth=0.7, zorder=0)
    ax.spines[["top", "right"]].set_visible(False)
    # 颜色示例：固定于绘图区上方、标题下方的空带中
    ax.legend(ncol=4, loc="upper center", bbox_to_anchor=(0.5, 1.02),
              frameon=False, fontsize=9.5)
    # 标题用图级文本锚定在图例更上方，不参与轴内布局
    fig.text(0.5, 0.975, "消融对比 · 三辅助引擎对 LLM 研判的贡献",
             ha="center", va="top", fontsize=15, fontweight="bold", color=INK)
    fig.text(0.5, 0.905,
             "（+记忆：Acc +4.5pp、检出 F1 +3.5pp；仅图谱 −2.2pp，增益来自经验记忆）",
             ha="center", va="top", fontsize=9.5, color=SUB)
    fig.text(0.012, 0.012,
             "数据：llm-soc 178 条带标签（TP=104/FP=74），DeepSeek 实判、流式防泄漏；"
             "Macro-F1 与检出/误报 F1 为已判样本口径。",
             fontsize=8, color=SUB)
    _fin(ax, "c1_ablation_grouped.png", fig)


# ---------------------------------------------------------------- c2 P-R 散点
def chart2_pr_scatter() -> None:
    fig, ax = plt.subplots(figsize=(8.8, 6.6))
    fig.patch.set_facecolor("white")
    # 底部留 30% 给图例，数据点旁的说明文字全部取消 → 不再互相遮挡
    fig.subplots_adjust(top=0.87, bottom=0.30, left=0.105, right=0.965)

    pts = [
        ("v1 首轮（独立口径）", 67.3, 89.7, 76.9, "#c2a6dd", "o"),
        ("基线（无证据）",    70.0, 89.7, 78.7, "#94a3b8", "o"),
        ("+ 多层记忆",        74.5, 91.6, 82.2, "#0ea5e9", "o"),
        ("+ 知识图谱",        67.3, 90.7, 77.3, "#f59e0b", "D"),
        ("记忆 + 图谱",       74.8, 91.7, 82.4, "#10b981", "o"),
    ]
    for label, r, p, f1, color, mk in pts:
        ax.scatter(r, p, s=110, color=color, zorder=4, marker=mk,
                   edgecolor="white", linewidth=1.0,
                   label=f"{label} · F1 {f1:.1f}")

    # 仅强调“基线 → +记忆”提升（曲线在左上空白区，远离各点标签）
    ax.annotate("", xy=(74.5, 91.6), xytext=(70.0, 89.7),
                arrowprops=dict(arrowstyle="-|>", color=ACC, lw=1.8,
                                connectionstyle="arc3,rad=-0.18", zorder=5))
    ax.text(70.1, 92.85, "净 +4.5pp Acc（+8 例翻转）",
            fontsize=9.2, color=ACC, fontweight="bold", ha="center")

    ax.set_xlim(64.5, 78.8)
    ax.set_ylim(88.1, 93.6)
    ax.set_xlabel("检出召回率 Recall（%）", fontsize=10.5)
    ax.set_ylabel("检出精确率 Precision（%）", fontsize=10.5)
    ax.grid(color=GRID, linewidth=0.7, zorder=0)
    ax.spines[["top", "right"]].set_visible(False)
    # 标题移至图内上方，下方放图例（图例居中、三列，占独立底部区）
    ax.set_title("威胁检出质量：精确率 × 召回率平面\n"
                 "（右上越优；记忆/联合在更高召回下保持高精确率）",
                 fontsize=12.5, color=INK, pad=8)
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, -0.42), ncol=3,
              frameon=False, fontsize=9)
    fig.text(0.012, 0.008,
             "检出＝威胁(TP)判定；括号为检出 F1；v1 点为首轮独立口径仅供参考。",
             fontsize=8, color=SUB)
    _fin(ax, "c2_pr_scatter.png", fig)


# ---------------------------------------------------------------- c3 雷达
def chart3_radar() -> None:
    dims = ["Acc 已判", "Macro-F1", "检出精确率", "检出召回率", "误报 F1", "判别率"]
    series = {
        "基线（无证据）": [78.0, 78.0, 89.7, 70.0, 77.4, 98.3],
        "+ 多层记忆":     [81.3, 81.2, 91.6, 74.5, 80.2, 98.9],
        "+ 知识图谱":     [76.6, 76.6, 90.7, 67.3, 75.9, 96.1],
        "记忆 + 图谱":    [81.3, 81.2, 91.7, 74.8, 80.0, 98.9],
    }
    colors = {"基线（无证据）": "#94a3b8", "+ 多层记忆": "#0ea5e9",
              "+ 知识图谱": "#f59e0b", "记忆 + 图谱": "#10b981"}

    N = len(dims)
    ang = np.linspace(0, 2 * np.pi, N, endpoint=False).tolist()
    ang += ang[:1]

    fig, ax = plt.subplots(figsize=(10.2, 7.6), subplot_kw=dict(polar=True))
    fig.patch.set_facecolor("white")
    # 右 27% 独立留给颜色示例（不再贴住“检出召回率”刻度）
    fig.subplots_adjust(left=0.12, right=0.73, top=0.84, bottom=0.12)
    ax.set_theta_offset(np.pi / 2)
    ax.set_theta_direction(-1)
    ax.set_ylim(60, 100)
    ax.set_xticks(ang[:-1])
    ax.set_xticklabels(dims, fontsize=10.5, color=TXT)
    ax.tick_params(axis="x", pad=14)
    ax.set_yticks([60, 70, 80, 90, 100])
    ax.set_yticklabels(["60", "70", "80", "90", "100"], fontsize=7.5, color=SUB)
    ax.grid(color=GRID, linewidth=0.7)

    for name, vals in series.items():
        v = vals + vals[:1]
        color = colors[name]
        ax.plot(ang, v, color=color, lw=1.8, label=name,
                ls="--" if name.startswith("+ 知识") else "-")
        ax.fill(ang, v, color=color, alpha=0.10)
    # 颜色示例：放右外侧独立区
    ax.legend(loc="upper left", bbox_to_anchor=(1.06, 1.02), ncol=1,
              frameon=True, facecolor="white", edgecolor=GRID, fontsize=9.5)
    # 标题提到图级顶端，避开雷达上缘网格
    fig.text(0.5, 0.99, "六维能力雷达：不同证据配置的整体画像",
             ha="center", va="top", fontsize=15, fontweight="bold", color=INK)
    fig.text(0.5, 0.93, "（判别率=100−未知率；纵轴 60~100 放大差异）",
             ha="center", va="top", fontsize=9.5, color=SUB)
    fig.text(0.012, 0.008,
             "数据同消融评测（llm-soc 178）；图谱单独在召回/判别率维度回落，记忆+图谱与纯记忆接近。",
             fontsize=8, color=SUB)
    _fin(ax, "c3_radar.png", fig)


# ---------------------------------------------------------------- c4 漏斗 + 分流
def chart4_evolution() -> None:
    fig, (axL, axR) = plt.subplots(1, 2, figsize=(13.4, 5.4),
                                   gridspec_kw={"width_ratios": [1.25, 1.0]})
    fig.patch.set_facecolor("white")

    # ---- 左：自进化收敛漏斗（宽度∝log10 数量，避免悬殊数量级压扁小段）
    stages = [
        ("历史处置经验片段", 9535, ACC, "每告警处置沉淀一条"),
        ("可疑模式", 36, "#38bdf8", "≥3 规则共现行为链 + 有界 LLM 归纳"),
        ("衍生规则", 36, "#34d399", "模式自动编译（27 active + 9 draft 降噪提议）"),
        ("建议升格候选", 27, "#fbbf24", "经验证有含金量，待人工拍板"),
    ]
    counts = [s[1] for s in stages]
    lg = np.log10(np.array(counts, dtype=float) + 1.0)
    lg_n = lg / lg[0]                       # 归一化，最大=1
    W0 = 58.0                               # 顶层半宽（data unit）
    y0 = 4.0
    dh = 1.0
    n = len(stages)
    for i, (name, cnt, color, sub) in enumerate(stages):
        wtop = W0 * lg_n[i]
        wbot = W0 * lg_n[i + 1] if i + 1 < n else W0 * 0.04   # 底部收敛成小尖
        xc = 0.0
        yb, yt = y0 - (i + 1) * dh, y0 - i * dh
        verts = [(xc - wtop, yt), (xc + wtop, yt),
                 (xc + wbot, yb), (xc - wbot, yb)]
        axL.add_patch(PathPatch(Path(verts), facecolor=color, alpha=0.88,
                                edgecolor="white", linewidth=1.2))
        axL.text(xc, (yt + yb) / 2, f"{cnt:,}", ha="center", va="center",
                 fontsize=13, fontweight="bold", color="white")
        axL.text(wtop + 1.6, (yt + yb) / 2, f"{name} · {sub}", ha="left",
                 va="center", fontsize=8.8, color=TXT)
        if i + 1 < n:
            rate = counts[i + 1] / counts[i] * 100
            tag = f"→ {rate:.2f}% 收敛" if rate < 5 else "→ 100%（全量编译）"
            axL.text(wtop + 1.6, (yt + yb) / 2 - dh * 0.46, tag, ha="left",
                     va="center", fontsize=7.4, color=SUB)
    axL.text(0.0, -0.32, "人工权威规则 = 0（等待拍板：27 候选 → 升格后命中直发、不耗 LLM）",
             ha="center", va="top", fontsize=9, color="#b45309", fontweight="bold")
    axL.set_xlim(-W0 * 1.02, W0 + 112)
    axL.set_ylim(y0 - n * dh - 1.15, y0 + 0.25)
    axL.axis("off")
    axL.set_title("自进化收敛漏斗（宽度∝log 数量）\n经验逐层沉淀 → 供人工拍板的候选",
                  fontsize=11.5, color=INK, pad=6)

    # ---- 右：处置分流三通道（命中源裁决 · LLM 成本）
    rows = ["llm-soc 178 条", "linux 前 200 条"]
    seg = {
        "manual 人工直发\n(不耗 LLM)":   [0, 0],
        "memory 可疑模式\n(必走 LLM)":   [174, 0],
        "policy 无记忆命中\n(策略回退)":   [4, 200],
    }
    colors = {"manual 人工直发\n(不耗 LLM)": "#fbbf24",
              "memory 可疑模式\n(必走 LLM)": "#0ea5e9",
              "policy 无记忆命中\n(策略回退)": "#94a3b8"}
    bottom = np.zeros(2)
    y = np.arange(2)
    for name, vals in seg.items():
        axR.barh(y, vals, left=bottom, height=0.52, color=colors[name],
                 edgecolor="white", label=name.split("\n")[0])
        for j, v in enumerate(vals):
            if v > 0:
                axR.text(bottom[j] + v / 2, y[j], f"{v}", ha="center", va="center",
                         fontsize=9.5, fontweight="bold", color="white")
        bottom += np.array(vals)
    for j, total in enumerate([178, 200]):
        llm_n = seg["memory 可疑模式\n(必走 LLM)"][j]
        axR.text(total + 4, y[j], f"需 LLM {llm_n}/{total}（{llm_n / total * 100:.0f}%）",
                 ha="left", va="center", fontsize=8.6, color=TXT)
    axR.set_yticks(y, rows, fontsize=10)
    axR.set_xlim(0, 260)
    axR.set_xlabel("告警条数", fontsize=9.5)
    axR.grid(axis="x", color=GRID, linewidth=0.7)
    axR.spines[["top", "right"]].set_visible(False)
    axR.legend(loc="lower right", frameon=False, fontsize=8.8)
    axR.set_title("处置分流三通道对比（真实库 sanity）\nmemory 命中=必走 LLM；linux 暂无相似记忆 → 0 耗 LLM",
                  fontsize=11.5, color=INK, pad=6)

    fig.suptitle("自进化闭环与 System1/System2 分流的成本-效果",
                 fontsize=14, color=INK, fontweight="bold", y=0.99)
    fig.text(0.012, 0.008,
             "数据：真实库 memory.db；llm-soc 178（memory 174 / policy 4 / manual 0，库内尚无人工规则），linux 前 200 条全部 policy（相似片段因防泄漏过滤后为 0）。",
             fontsize=8, color=SUB)
    _fin(axL, "c4_evolution_funnel.png", fig)


def main() -> None:
    plt.rcParams["font.family"] = FAMILY
    plt.rcParams["font.sans-serif"] = [FAMILY, "DejaVu Sans"]
    plt.rcParams["axes.unicode_minus"] = False
    print("cjk font:", FAMILY)
    chart1_grouped()
    chart2_pr_scatter()
    chart3_radar()
    chart4_evolution()
    print("done ->", os.path.abspath(OUT_DIR))


if __name__ == "__main__":
    main()
