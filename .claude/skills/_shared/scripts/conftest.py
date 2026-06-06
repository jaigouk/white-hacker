import pathlib
import sys

# Make validate_findings.py importable regardless of pytest's import mode / cwd.
sys.path.insert(0, str(pathlib.Path(__file__).parent))
