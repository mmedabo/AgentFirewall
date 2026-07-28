"""Generate a Markdown table of contents. Purely local, no side effects."""
import re
import sys


def slugify(heading: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", heading.lower()).strip("-")


def build_toc(text: str) -> str:
    lines = []
    for line in text.splitlines():
        m = re.match(r"^(#{1,3})\s+(.*)", line)
        if m:
            depth = len(m.group(1)) - 1
            title = m.group(2).strip()
            lines.append(f"{'  ' * depth}- [{title}](#{slugify(title)})")
    return "\n".join(lines)


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8") as fh:
        print(build_toc(fh.read()))
