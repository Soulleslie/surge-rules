#!/usr/bin/env python3
"""按 sources.json 从 MagicRule 同步 Surge 规则，写到固定路径（说明见 README）。

- no_geoip：用于 [Host] 映射的规则。上游出现 GEOIP 或 IP 规则缺少 no-resolve 时视为异常，保留旧文件。
- drop_bare_suffix：去掉裸后缀（如 DOMAIN-SUFFIX,hk），keep_bare 里的除外。
"""

import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "sources.json"
IP_TYPES = ("IP-CIDR", "IP-CIDR6", "IP-ASN")

# 新版条数低于旧版的这个比例，视为上游异常
MIN_RATIO = 0.5


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "surge-rules-updater"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


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


def sync(entry: dict, index: dict) -> str:
    matches = index.get(entry["name"], [])
    if len(matches) != 1:
        raise ValueError(f"索引里找到 {len(matches)} 条同名规则，应为 1 条")
    manifest = json.loads(fetch(matches[0]["manifest"]))
    artifacts = [a for a in manifest.get("artifacts", []) if a.get("key") == entry["artifact"]]
    if len(artifacts) != 1:
        raise ValueError(f"manifest 里没有 {entry['artifact']}")
    url = artifacts[0]["url"]
    text = fetch(url).decode("utf-8")
    if entry.get("drop_bare_suffix"):
        text = drop_bare_suffix(text, set(entry.get("keep_bare", [])))

    out = ROOT / entry["output"]
    check(entry, text, out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    return url


def main() -> int:
    config = json.loads(SOURCES.read_text(encoding="utf-8"))
    index: dict[str, list] = {}
    for r in json.loads(fetch(config["index"])).get("rules", []):
        index.setdefault(r.get("name"), []).append(r)

    failed = []
    for entry in config["rules"]:
        label = f"{entry['name']} ({entry['artifact']})"
        try:
            url = sync(entry, index)
            print(f"OK    {label:32} -> {entry['output']}  [{url.rsplit('/', 1)[-1]}]")
        except Exception as e:  # 单条失败不影响其他规则，旧文件保持不变
            failed.append(label)
            print(f"FAIL  {label:32} {e}", file=sys.stderr)

    if failed:
        print(f"{len(failed)} 条规则未更新：{', '.join(failed)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
