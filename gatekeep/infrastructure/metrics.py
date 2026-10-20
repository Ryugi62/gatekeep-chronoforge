from __future__ import annotations

import math
from typing import Iterable, Optional, Tuple


def rates(rows: Iterable[Tuple[str, bool]]):
    """rows = (label 'attack'|'benign', blocked)"""
    an = ab = bn = bb = 0
    for label, blocked in rows:
        if label == "attack":
            an += 1
            ab += int(blocked)
        else:
            bn += 1
            bb += int(blocked)
    return {
        "attack_n": an, "attack_blocked": ab, "benign_n": bn, "benign_blocked": bb,
        "block_rate": ab / an if an else None, "fp_rate": bb / bn if bn else None,
    }


def wilson(k: int, n: int, z: float = 1.96) -> Tuple[Optional[float], Optional[float]]:
    if n == 0:
        return (None, None)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - m) / d, min(1.0, (c + m) / d))
