import pathlib
import sys

# Make ci_gate.py importable regardless of import mode / cwd.
sys.path.insert(0, str(pathlib.Path(__file__).parent))
