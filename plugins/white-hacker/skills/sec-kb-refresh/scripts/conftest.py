import pathlib
import sys

_here = pathlib.Path(__file__).parent
sys.path.insert(0, str(_here))
# expose ai-attack-kb scripts (validate_kb / dedupe_kb) so a test can validate poller output.
sys.path.insert(0, str(_here.parent.parent / "ai-attack-kb" / "scripts"))
