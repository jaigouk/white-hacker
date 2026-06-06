import pathlib
import sys

_here = pathlib.Path(__file__).parent
# dedup_findings.py (this dir) + validate_findings.py (shared scripts) importable.
sys.path.insert(0, str(_here))
sys.path.insert(0, str(_here.parent.parent / "_shared" / "scripts"))
