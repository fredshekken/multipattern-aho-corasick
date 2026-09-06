"""Import this first in every viber_bot script — makes enhanced_aho/ and
original_aho/ importable without copying their code into this folder."""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
for _folder in ("enhanced_aho", "original_aho"):
    _path = str(_ROOT / _folder)
    if _path not in sys.path:
        sys.path.insert(0, _path)
