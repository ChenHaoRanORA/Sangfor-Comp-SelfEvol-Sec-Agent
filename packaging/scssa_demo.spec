# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 规格：SCSSA Agent 演示程序（一体化单文件 exe）。

构建（仓库根目录，conda 环境 scssa）：

    pyinstaller packaging/scssa_demo.spec --noconfirm

产物与分发结构（前端已内嵌进 exe；数据与日志外置、与 exe 同目录）：

    SCSSA-Demo.exe    ← 主程序（FastAPI 后端 + 内嵌 web/dist 前端）
    data/             ← 必需：data/memory（记忆库）、data/processed、data/kb（ATT&CK 图库）
    log/              ← 必需：回放事件 jsonl
    models/           ← 可选：Chroma ONNX 向量模型，随包后完全离线

注意：目录路径请使用纯 ASCII（Kùzu Windows 版不支持非 ASCII 路径，否则图库会回退到
%TEMP%\\scssa_kb 而读不到 data/kb）。
"""
import os
import sys

from PyInstaller.utils.hooks import collect_all, collect_submodules

ROOT = os.path.abspath(os.path.join(SPECPATH, os.pardir))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# 前端构建产物内嵌（server.py 在打包态从 _MEIPASS/web/dist 读取）
datas = [(os.path.join(ROOT, "web", "dist"), os.path.join("web", "dist"))]
binaries = []
hiddenimports = []

# 含原生扩展或动态导入（字符串反射）的依赖必须整包收集：
#   chromadb/onnxruntime/tokenizers → 向量检索与 ONNX 推理（.pyd/.dll）
#   kuzu                            → 嵌入式图库原生库
#   langgraph/langchain_core        → 处置流状态图
#   uvicorn                         → 协议/事件循环子模块为动态加载
for _pkg in ("chromadb", "onnxruntime", "kuzu", "tokenizers",
             "langgraph", "langchain_core", "uvicorn"):
    try:
        _d, _b, _h = collect_all(_pkg)
    except Exception as exc:  # noqa: BLE001  个别包收集失败不应中断构建
        print(f"[spec] collect_all({_pkg}) 跳过：{exc}")
        continue
    datas += _d
    binaries += _b
    hiddenimports += _h

# 本项目为 PEP 420 隐式命名空间包（src/ 无 __init__.py），显式收集以保证不漏模块
try:
    hiddenimports += collect_submodules("src")
except Exception as exc:  # noqa: BLE001
    print(f"[spec] collect_submodules(src) 跳过：{exc}")

a = Analysis(
    [os.path.join(ROOT, "packaging", "entry.py")],
    pathex=[ROOT],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["matplotlib", "pytest", "PyInstaller", "IPython", "tkinter"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="SCSSA-Demo",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
