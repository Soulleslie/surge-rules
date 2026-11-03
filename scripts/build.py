#!/usr/bin/env python3
"""从 MagicRule 拉取最新的 Surge China 完整规则，去掉 GEOIP 后输出 China_NoGEOIP.list。

去掉 GEOIP、并确保所有 IP 规则带 no-resolve，这样同一个文件既能用在 [Rule]，
也能用在 [Host] 映射（映射里不能有需要先解析的规则，否则整条映射会失效）。
"""

import json
import sys
import urllib.request
from pathlib import Path

INDEX_URL = "https://magicrule.pages.dev/data/index/Surge.json"
RULE_NAME = "China"
OUTPUT = Path(__file__).resolve().parent.parent / "China_NoGEOIP.list"

# 低于这个条数或缺少这些条目，视为上游异常，报错且不覆盖旧文件
MIN_RULES = 5000
MUST_CONTAIN = ["DOMAIN-SUFFIX,qq.com", "DOMAIN-SUFFIX,jd.com", "DOMAIN-KEYWORD,baidu"]

IP_TYPES = ("IP-CIDR", "IP-CIDR6", "IP-ASN")


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "surge-rules-updater"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


def find_artifact() -> tuple[str, str]:
    index = json.loads(fetch(INDEX_URL))
    rules = [r for r in index.get("rules", []) if r.get("name") == RULE_NAME]
    if len(rules) != 1:
        raise SystemExit(f"索引里找到 {len(rules)} 条名为 {RULE_NAME} 的规则，应为 1 条")
    manifest = json.loads(fetch(rules[0]["manifest"]))
    full = [a for a in manifest.get("artifacts", []) if a.get("key") == "rules"]
    if len(full) != 1:
        raise SystemExit("manifest 里没有找到完整规则（key=rules）")
    return full[0]["url"], manifest.get("rule_updated_at", "")


def transform(text: str) -> list[str]:
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = [f.strip() for f in line.split(",")]
        rule_type = fields[0].upper()
        if rule_type == "GEOIP":
            continue
        if rule_type in IP_TYPES and "no-resolve" not in (f.lower() for f in fields[2:]):
            fields.append("no-resolve")
        out.append(",".join(fields))
    return out


def check(rules: list[str]) -> None:
    if len(rules) < MIN_RULES:
        raise SystemExit(f"只有 {len(rules)} 条规则，少于 {MIN_RULES}，不更新")
    present = set(rules)
    missing = [m for m in MUST_CONTAIN if m not in present]
    if missing:
        raise SystemExit(f"缺少关键条目 {missing}，不更新")
    if any(r.upper().startswith("GEOIP,") for r in rules):
        raise SystemExit("过滤后仍有 GEOIP，不更新")


def main() -> None:
    url, updated_at = find_artifact()
    rules = transform(fetch(url).decode("utf-8"))
    check(rules)

    counts: dict[str, int] = {}
    for r in rules:
        t = r.split(",", 1)[0]
        counts[t] = counts.get(t, 0) + 1

    # 头部只写上游信息，不写当前时间，上游没变时文件内容就不变，不会产生无意义的提交
    header = [
        "# China (MagicRule) without GEOIP",
        f"# Source: {url}",
        f"# Upstream updated: {updated_at}",
        f"# Total: {len(rules)}",
        *(f"# {t}: {n}" for t, n in sorted(counts.items())),
    ]
    OUTPUT.write_text("\n".join(header + rules) + "\n", encoding="utf-8")
    print(f"写入 {OUTPUT.name}：{len(rules)} 条，来源 {url}")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:  # 网络或格式异常时让 workflow 失败，旧文件保持不变
        print(f"更新失败：{e}", file=sys.stderr)
        sys.exit(1)
