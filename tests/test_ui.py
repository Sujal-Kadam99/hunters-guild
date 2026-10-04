"""
Unit tests for Hunters Guild Web UI Components.
"""

from pathlib import Path
from hunters_guild.ui.run import launch_gui
from hunters_guild.ui import launch_gui as launch_gui_pkg


def test_ui_launcher_and_app_paths():
    """Verifies that app.py and run.py exist and are importable."""
    app_path = Path(__file__).parent.parent / "hunters_guild" / "ui" / "app.py"
    run_path = Path(__file__).parent.parent / "hunters_guild" / "ui" / "run.py"

    assert app_path.exists()
    assert run_path.exists()
    assert callable(launch_gui)
    assert callable(launch_gui_pkg)
