import pathlib
import sys

# Make validate_manifest.py importable regardless of import mode / cwd.
sys.path.insert(0, str(pathlib.Path(__file__).parent))
