import pathlib
import sys

_here = pathlib.Path(__file__).parent
# detect_tools.py + validate_scan_plan.py (this dir) importable regardless of
# pytest's import mode / cwd.
sys.path.insert(0, str(_here))
