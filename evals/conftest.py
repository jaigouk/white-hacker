import pathlib
import sys

# Make score.py / keep_or_revert.py (evals/) and scripts/ importable regardless of cwd.
_here = pathlib.Path(__file__).parent
sys.path.insert(0, str(_here))
sys.path.insert(0, str(_here / "scripts"))
