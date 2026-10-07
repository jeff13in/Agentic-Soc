"""Defense 1: data/instruction separation.

Every tool result is wrapped in an explicit untrusted-data envelope. Closing tags inside the
payload are neutralized so attacker text can't end the envelope early.
"""

from __future__ import annotations

import re

OPEN = "<untrusted_tool_result"
CLOSE = "</untrusted_tool_result>"
_ESCAPE = re.compile(r"</?\s*untrusted_tool_result", re.I)


def wrap(tool_name: str, call_id: str, content: str) -> str:
    safe = _ESCAPE.sub(lambda m: m.group(0).replace("<", "&lt;"), content)
    return f'{OPEN} tool="{tool_name}" id="{call_id}">\n{safe}\n{CLOSE}'
