import pathlib
import sys

_here = pathlib.Path(__file__).parent
# validate_findings.py + degradation.py (this dir) importable regardless of import mode / cwd.
sys.path.insert(0, str(_here))

# For the cross-capability integration test (T-3.6): expose the sibling skill scripts
# (detector + normalizers) when present, so the test can drive the real pipeline without a
# cross-package install. Each is its own uv project; we only add the dirs that exist.
_skills = _here.parent.parent  # plugins/white-hacker/skills
for _rel in ("sec-detect/scripts", "deps-scan/scripts", "secrets-scan/scripts"):
    _d = _skills / _rel
    if _d.is_dir():
        sys.path.insert(0, str(_d))
