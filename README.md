# surge-rules

每天自动从 [MagicRule](https://magicrule.pages.dev/) 同步 Surge 规则的最新版本。MagicRule 的文件链接带哈希，更新后会换新链接；这里把它们写到固定路径，Surge 订阅固定路径就能跟着更新。

要同步哪些规则，在 `sources.json` 里配置：

- `rules/<名称>.list`：原样同步的规则。
- `China_NoGEOIP.list`：China 完整规则去掉 `GEOIP`、IP 规则都带 `no-resolve`，可同时用在分流和 DNS 映射：

```
[Rule]
RULE-SET,https://raw.githubusercontent.com/Soulleslie/surge-rules/main/China_NoGEOIP.list,DIRECT
GEOIP,CN,DIRECT

[Host]
RULE-SET:https://raw.githubusercontent.com/Soulleslie/surge-rules/main/China_NoGEOIP.list = server:system
```

某条规则下载失败、为空或条数比旧版少一半以上时，保留旧文件，其他规则照常更新，workflow 标记为失败。
