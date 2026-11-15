#!/usr/bin/env python3
"""经过独立审核和 Clash 转换后同步规则，完整说明见 README。

- no_geoip：用于 [Host] 映射的规则。上游出现 GEOIP 或 IP 规则缺少 no-resolve 时视为异常，保留旧文件。
- drop_bare_suffix：去掉裸后缀（如 DOMAIN-SUFFIX,hk），keep_bare 里的除外。
"""

import sys
from pathlib import Path

IP_TYPES = ("IP-CIDR", "IP-CIDR6", "IP-ASN")

# 新版条数低于旧版的这个比例，视为上游异常
MIN_RATIO = 0.5


def rule_lines(text: str) -> list[str]:
    return [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]


def bare_suffix(line: str) -> str:
    fields = [f.strip() for f in line.split(",")]
    if len(fields) > 1 and fields[0].upper() == "DOMAIN-SUFFIX" and "." not in fields[1]:
        return fields[1].lower()
    return ""


def drop_bare_suffix(text: str, keep: set) -> str:
    kept, dropped = [], []
    for line in text.splitlines():
        b = bare_suffix(line)
        if b and b not in keep:
            dropped.append(b)
        else:
            kept.append(line)
    return f"# Dropped bare DOMAIN-SUFFIX: {' '.join(dropped) or '-'}\n" + "\n".join(kept) + "\n"


def check(entry: dict, text: str, out: Path) -> None:
    lines = rule_lines(text)
    if not lines:
        raise ValueError("规则为空")
    if out.exists():
        old = len(rule_lines(out.read_text(encoding="utf-8")))
        if len(lines) < old * MIN_RATIO:
            raise ValueError(f"条数从 {old} 降到 {len(lines)}，低于 {MIN_RATIO:.0%}")
    if len(lines) < entry.get("min_rules", 0):
        raise ValueError(f"只有 {len(lines)} 条，少于 {entry['min_rules']}")
    present = set(lines)
    missing = [m for m in entry.get("must_contain", []) if m not in present]
    if missing:
        raise ValueError(f"缺少关键条目 {missing}")
    if entry.get("no_geoip"):
        if any(l.upper().startswith("GEOIP,") for l in lines):
            raise ValueError("上游含有 GEOIP")
        bare = [l for l in lines if l.upper().startswith(IP_TYPES) and "no-resolve" not in l.lower()]
        if bare:
            raise ValueError(f"{len(bare)} 条 IP 规则缺少 no-resolve")
    if entry.get("drop_bare_suffix"):
        left = {bare_suffix(l) for l in lines} - {""} - set(entry.get("keep_bare", []))
        if left:
            raise ValueError(f"过滤后仍有裸后缀 {sorted(left)}")


def main() -> int:
    from update import main as guarded_main
    return guarded_main()


if __name__ == "__main__":
    sys.exit(main())
