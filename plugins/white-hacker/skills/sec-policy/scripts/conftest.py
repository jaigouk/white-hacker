import pathlib
import sys

_here = pathlib.Path(__file__).parent
# parse_policy.py (this dir) + the _shared scripts (policy_detect) importable
# regardless of pytest's import mode / cwd.
sys.path.insert(0, str(_here))
sys.path.insert(0, str(_here.parent.parent / "_shared" / "scripts"))
