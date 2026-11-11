# surge-rules

每天自动从 [MagicRule](https://magicrule.pages.dev/) 同步 Surge 规则的最新版本。MagicRule 的文件链接带哈希，更新后会换新链接；这里把它们写到固定路径，Surge 订阅固定路径就能跟着更新。

要同步哪些规则，在 `sources.json` 里配置：

- `rules/<名称>.list`：原样同步的规则。
- `rules/China.list`：China 完整规则。上游已不含 `GEOIP`，IP 规则都带 `no-resolve`，可同时用在分流和 DNS 映射；上游一旦不满足这两点，保留旧文件：

```
[Rule]
RULE-SET,https://raw.githubusercontent.com/Soulleslie/surge-rules/main/rules/China.list,DIRECT
GEOIP,CN,DIRECT

[Host]
RULE-SET:https://raw.githubusercontent.com/Soulleslie/surge-rules/main/rules/China.list = server:system
```

某条规则下载失败、为空或条数比旧版少一半以上时，保留旧文件，其他规则照常更新，workflow 标记为失败。

## Clash（mihomo）

同步完成后，`scripts/clash.py` 用 mihomo 把上面的 Surge 规则（含 `custom/`）转换到 `clash/`，Surge 文件不受影响。每个规则拆成：

- `clash/<名称>.mrs`：DOMAIN / DOMAIN-SUFFIX，`behavior: domain`
- `clash/<名称>-IP.mrs`：IP-CIDR / IP-CIDR6，`behavior: ipcidr`
- `clash/<名称>-Extra.list`：DOMAIN-KEYWORD / IP-ASN / PROCESS-NAME，`behavior: classical`

mihomo 不支持的 USER-AGENT、URL-REGEX 会被丢弃；没有内容的部分不生成文件。

```yaml
rule-providers:
  Google:
    type: http
    behavior: domain
    format: mrs
    url: https://raw.githubusercontent.com/Soulleslie/surge-rules/main/clash/Google.mrs
    path: ./rules/Google.mrs
    interval: 86400

rules:
  - RULE-SET,Google,Google
  - RULE-SET,Google-IP,Google,no-resolve
```

转换失败时保留 `clash/` 里的旧文件，Surge 规则照常提交，workflow 标记为失败。
