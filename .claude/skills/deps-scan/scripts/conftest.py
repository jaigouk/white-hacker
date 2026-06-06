import pathlib
import sys

_here = pathlib.Path(__file__).parent
# normalize_deps.py + degradation.py (shared) + validate_findings.py (shared) + detect_tools (sec-detect)
sys.path.insert(0, str(_here))
sys.path.insert(0, str(_here.parent.parent / "_shared" / "scripts"))
sys.path.insert(0, str(_here.parent.parent / "sec-detect" / "scripts"))
