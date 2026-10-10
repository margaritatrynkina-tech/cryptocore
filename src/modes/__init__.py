from __future__ import annotations

from .base import ModeBase
from .ecb import ECBMode
from .cbc import CBCMode
from .cfb import CFBMode
from .ofb import OFBMode
from .ctr import CTRMode


# Registry: name → mode class
MODES: dict[str, type[ModeBase]] = {
    "ecb": ECBMode,
    "cbc": CBCMode,
    "cfb": CFBMode,
    "ofb": OFBMode,
    "ctr": CTRMode,
}


def get_mode(name: str) -> ModeBase:
    if name not in MODES:
        available = ", ".join(sorted(MODES))
        raise ValueError(f"Unknown mode: {name!r}. Available: {available}")
    return MODES[name]()


__all__ = ["ModeBase", "MODES", "get_mode", "ECBMode", "CBCMode", "CFBMode", "OFBMode", "CTRMode"]