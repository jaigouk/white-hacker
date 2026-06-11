import pathlib
import sys

_here = pathlib.Path(__file__).parent
# ext_scan.py (this dir) + the _shared scripts (degradation, validate_findings)
# importable regardless of pytest's import mode / cwd.
sys.path.insert(0, str(_here))
sys.path.insert(0, str(_here.parent.parent / "_shared" / "scripts"))
