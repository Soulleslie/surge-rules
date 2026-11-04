#!/usr/bin/env python3
"""把同步好的 Surge 规则转换成 mihomo（Clash Meta）规则集，写到 clash/（说明见 README）。

只读取 Surge 文件，不改动它们。每个 .list 拆成：
- <名称>.mrs：DOMAIN / DOMAIN-SUFFIX，domain 规则集，按索引匹配；
- <名称>-IP.mrs：IP-CIDR / IP-CIDR6，ipcidr 规则集；
- <名称>-Extra.list：DOMAIN-KEYWORD、IP-ASN、PROCESS-NAME，classical 规则集，条数很少。
mihomo 不支持的 USER-AGENT、URL-REGEX 丢弃。没有内容的部分不生成文件。

用法：python3 scripts/clash.py <mihomo 可执行文件>
"""

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "clash"
SOURCES = [*sorted((ROOT / "rules").glob("*.list")), *sorted((ROOT / "custom").glob("*.list"))]

DOMAIN_TYPES = {"DOMAIN": "{}", "DOMAIN-SUFFIX": "+.{}"}
IP_TYPES = ("IP-CIDR", "IP-CIDR6")
EXTRA_TYPES = ("DOMAIN-KEYWORD", "IP-ASN", "PROCESS-NAME")


def split(text: str) -> tuple[list[str], list[str], list[str]]:
    domains, ips, extra = [], [], []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = [f.strip() for f in line.split(",")]
        rule_type = fields[0].upper()
        if len(fields) < 2:
            continue
        if rule_type in DOMAIN_TYPES:
            domains.append(DOMAIN_TYPES[rule_type].format(fields[1].lower()))
        elif rule_type in IP_TYPES:
            ips.append(fields[1])
        elif rule_type in EXTRA_TYPES:
            # 只保留类型与值；no-resolve 由 Clash 配置里的 RULE-SET 统一指定
            extra.append(f"{rule_type},{fields[1]}")
    dedup = lambda xs: list(dict.fromkeys(xs))
    return dedup(domains), dedup(ips), dedup(extra)


def convert(mihomo: str, behavior: str, lines: list[str], out: Path) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        src, dst = Path(tmp) / "in.txt", Path(tmp) / "out.mrs"
        src.write_text("\n".join(lines) + "\n", encoding="utf-8")
        subprocess.run([mihomo, "convert-ruleset", behavior, "text", str(src), str(dst)], check=True, capture_output=True)
        if not dst.exists() or dst.stat().st_size == 0:
            raise ValueError(f"mihomo 没有生成 {out.name}")
        dst.replace(out)


def build(mihomo: str, source: Path) -> list[str]:
    name = "China" if source.name == "China_NoGEOIP.list" else source.stem
    domains, ips, extra = split(source.read_text(encoding="utf-8"))
    if not (domains or ips or extra):
        raise ValueError("没有可转换的规则")

    written = []
    for lines, behavior, out in ((domains, "domain", OUT / f"{name}.mrs"), (ips, "ipcidr", OUT / f"{name}-IP.mrs")):
        if lines:
            convert(mihomo, behavior, lines, out)
            written.append(f"{out.name}({len(lines)})")
        else:
            out.unlink(missing_ok=True)
    out = OUT / f"{name}-Extra.list"
    if extra:
        out.write_text(f"# {name}：DOMAIN-KEYWORD / IP-ASN / PROCESS-NAME，由 {source.relative_to(ROOT)} 生成\n" + "\n".join(extra) + "\n", encoding="utf-8")
        written.append(f"{out.name}({len(extra)})")
    else:
        out.unlink(missing_ok=True)
    return written


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    mihomo = sys.argv[1]
    OUT.mkdir(exist_ok=True)

    failed = []
    for source in SOURCES:
        label = str(source.relative_to(ROOT))
        try:
            print(f"OK    {label:28} -> {' '.join(build(mihomo, source))}")
        except Exception as e:  # 单条失败保留 clash/ 里的旧文件，其他照常转换
            failed.append(label)
            print(f"FAIL  {label:28} {e}", file=sys.stderr)

    if failed:
        print(f"{len(failed)} 条规则未转换：{', '.join(failed)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
