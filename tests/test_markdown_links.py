from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import unquote


INLINE_LINK = re.compile(r"(?<!!)\[[^]]+\]\(([^)]+)\)")


def test_markdown_local_links_resolve() -> None:
    root = Path(__file__).resolve().parents[1]
    failures: list[str] = []
    for document in sorted(root.rglob("*.md")):
        if any(part.startswith(".") for part in document.relative_to(root).parts):
            continue
        for raw_target in INLINE_LINK.findall(document.read_text(encoding="utf-8")):
            target = raw_target.strip().split(maxsplit=1)[0].strip("<>")
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            path_text = unquote(target.split("#", 1)[0])
            if not path_text:
                continue
            resolved = (document.parent / path_text).resolve()
            if not resolved.exists():
                failures.append(f"{document.relative_to(root)} -> {target}")
    assert failures == []
