import pathlib
import sys

_here = pathlib.Path(__file__).parent
# init_profile.py (this dir) + shared scripts + sibling sec-detect's detect_tools
# importable regardless of pytest's import mode / cwd.
sys.path.insert(0, str(_here))
sys.path.insert(0, str(_here.parent.parent / "_shared" / "scripts"))
sys.path.insert(0, str(_here.parent.parent / "sec-detect" / "scripts"))
