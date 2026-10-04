"""
Hunters Guild UI Launcher Entrypoint
Project: Hunters Guild - Automated Model Alignment & Boundary Verification Framework
"""

import os
import subprocess
import sys
from pathlib import Path


def launch_gui(host: str = "127.0.0.1", port: int = 8501) -> None:
    """Launches the Hunters Guild Streamlit web dashboard."""
    app_path = Path(__file__).parent / "app.py"
    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(app_path.resolve()),
        "--server.address",
        host,
        "--server.port",
        str(port),
        "--theme.base",
        "dark",
    ]
    print(f"Launching Hunters Guild Dashboard on http://{host}:{port} ...")
    subprocess.run(cmd)


if __name__ == "__main__":
    launch_gui()
