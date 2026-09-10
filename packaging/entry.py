# -*- coding: utf-8 -*-
"""SCSSA Agent 演示程序打包入口（PyInstaller）。

只做"打包态启动适配"，不含业务逻辑：

1. 工作目录切到程序所在目录 —— 使外置 `data/`、`log/` 等相对路径在双击运行时正确解析
   （源码里 `web/dist`、`data/processed`、`data/memory`、`data/kb` 均以当前工作目录为基准）；
2. 若随包分发了 Chroma 的 ONNX 向量模型（`models/chroma/onnx_models`），则把 chromadb 的
   模型下载路径指过去，实现完全离线运行；未随包时保持默认（首次运行需联网下载一次）；
3. 复用 `src.core.api.server.main()` 的命令行参数与启动流程，服务就绪后自动打开浏览器。

用法（分发目录内）：

    SCSSA-Demo.exe                              # 默认 llm-soc 数据源、127.0.0.1:8000、自动开浏览器
    SCSSA-Demo.exe --source linux --eps 60 --loop
    SCSSA-Demo.exe --port 8081 --no-open        # 不自动打开浏览器
"""
from __future__ import annotations

import os
import sys
import threading
import webbrowser


def app_dir() -> str:
    """程序基准目录：打包态 = 可执行文件所在目录；开发态 = 仓库根目录。"""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _use_bundled_model(base: str) -> None:
    """随包向量模型 → 免联网；未随包则保持 chromadb 默认（首次运行联网下载）。"""
    download = os.path.join(base, "models", "chroma", "onnx_models", "all-MiniLM-L6-v2")
    if not os.path.isdir(os.path.join(download, "onnx")):
        return
    try:
        from pathlib import Path

        from chromadb.utils.embedding_functions.onnx_mini_lm_l6_v2 import ONNXMiniLM_L6_V2

        ONNXMiniLM_L6_V2.DOWNLOAD_PATH = Path(download)
        print(f"[exe] 使用随包向量模型：{download}")
    except Exception as exc:  # noqa: BLE001  模型不可用不影响启动，chromadb 会自行降级
        print(f"[exe] 随包模型启用失败，走默认逻辑：{type(exc).__name__}: {exc}")


def _parse_host_port(argv: list[str]) -> tuple[str, str]:
    host, port = "127.0.0.1", "8000"
    for i, a in enumerate(argv):
        if a == "--host" and i + 1 < len(argv):
            host = argv[i + 1]
        elif a.startswith("--host="):
            host = a.split("=", 1)[1]
        elif a == "--port" and i + 1 < len(argv):
            port = argv[i + 1]
        elif a.startswith("--port="):
            port = a.split("=", 1)[1]
    return host, port


def _preflight(base: str) -> bool:
    """分发目录自检：data/ 与 log/ 必须与 exe 同级（前端已内嵌，数据外置）。

    双击运行时控制台随进程退出而关闭，故失败时等待回车，避免用户只看到闪退。
    """
    missing = [d for d in ("data", "log") if not os.path.isdir(os.path.join(base, d))]
    if not missing:
        return True
    print("=" * 70)
    print(f"[exe] 缺少运行数据目录：{', '.join(missing)}")
    print("[exe] 请将 data/ 与 log/ 放在与可执行文件相同的目录下：")
    print(f"      {base}")
    print("[exe] 目录结构：SCSSA-Demo.exe + data/ + log/（可选 models/ 用于离线向量模型）")
    print("=" * 70)
    try:
        input("按回车键退出...")
    except EOFError:  # 非交互式（管道/重定向）下无输入可读
        pass
    return False


def main() -> None:
    base = app_dir()
    os.chdir(base)
    if base not in sys.path:
        sys.path.insert(0, base)
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")

    if not _preflight(base):
        return

    # --no-open 是本入口私有开关，交给 server.main() 前先摘掉（其 argparse 不认识该参数）
    open_browser = "--no-open" not in sys.argv[1:]
    sys.argv = [sys.argv[0]] + [a for a in sys.argv[1:] if a != "--no-open"]
    host, port = _parse_host_port(sys.argv[1:])

    _use_bundled_model(base)
    print(f"[exe] 工作目录：{base}")

    if open_browser:
        url = f"http://{host}:{port}/screen"
        threading.Timer(2.0, lambda: webbrowser.open(url)).start()

    from src.core.api.server import main as run_server

    run_server()


if __name__ == "__main__":
    main()
