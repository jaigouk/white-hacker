"""Put install/ on sys.path so tests can `import scrub_vendored` (stdlib-only, no package install)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
