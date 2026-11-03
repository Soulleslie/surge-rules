# surge-rules

每天自动从 [MagicRule](https://magicrule.pages.dev/) 拉取 Surge 的 China 完整规则，去掉 `GEOIP` 并确保 IP 规则都带 `no-resolve`，输出 `China_NoGEOIP.list`。

同一个文件可以同时用在分流和 DNS 映射：

```
[Rule]
RULE-SET,https://raw.githubusercontent.com/Soulleslie/surge-rules/main/China_NoGEOIP.list,DIRECT
GEOIP,CN,DIRECT

[Host]
RULE-SET:https://raw.githubusercontent.com/Soulleslie/surge-rules/main/China_NoGEOIP.list = server:system
```

上游条数异常（少于 5000 条或缺少关键条目）时，workflow 会失败，不会覆盖旧文件。
