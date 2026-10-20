from __future__ import annotations

import json
import time
from typing import Any, Dict

from ..application.ports import AuditLog


class JsonlAuditLog(AuditLog):
    def __init__(self, path: str):
        self.path = path

    def write(self, record: Dict[str, Any]) -> None:
        row = dict(record)
        row["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
