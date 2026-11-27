# surge-rules

每天北京时间 08:00 从 [MagicRule](https://magicrule.pages.dev/) 同步经过本地审核的 Surge 规则，并生成 Clash 产物。GitHub Actions 调度可能延迟，也可在 Actions → Sync rules → Run workflow 手动运行。

上游曾把广告规则追加到 Apple、Lan、Telegram、GlobalMedia、Speedtest；连 11 月 7 日的冻结旧版也有残留。因此现在所有 31 个列表都使用 `safety/approved/` 中独立、固定的逐条白名单。五个受影响列表已对照各自原始来源重审，记录在 `safety/review.json`。

- 已审核规则才允许发布，规则类型和 `no-resolve` 参数也是审核身份的一部分。
- 已知未批准条目由 `safety/excluded.list` 或目标列表的 `safety/quarantine/` 文件隔离。
- 出现任何其他未经审核的新条目，即使只有一条，也暂停更新该列表并保留 Surge 和 Clash 旧版。
- 从原始上游下载开始验证 TLS、发布地址、manifest 身份和 SHA-256。优先核对整文件指纹。上游明确声明支持的头部标准化格式时，校验规定的元数据行后可核对其余完整字节的 `semantic_sha256`。
- 清理后剩余条数不能低于固定白名单的 90%，防止逐次减少绕过检查。
- 网络任务只提交 `rules/` 和 `clash/`，不能自动修改或扩大审核白名单。

这是一种保守的自动同步：允许已批准内容的更新和小范围删除；新的域名、IP 或匹配类型必须先人工审核。不能保证每个历史条目的业务归属永远正确，也不能保证上游永不出错。任何新增项都不会因为上游重新生成而自动获得信任。

每次运行把隔离数量、完整的 `quarantined_rules` 域名/IP 清单、`unknown_rules` 待审核新增条目和失败原因上传为 Actions 的 `sync-review-*` artifact；有列表被拦截时任务标红，其余成功列表可正常提交。同步必须通过测试、白名单校验和 Clash 转换，才一起替换单个列表的 Surge/Clash 产物。

要同步哪些规则，在 `sources.json` 里配置：

- `rules/<名称>.list`：通过本地审核白名单过滤后的规则，注释里的类型计数会重新生成。
- [GlobalAI.list](https://raw.githubusercontent.com/Soulleslie/surge-rules/refs/heads/main/rules/GlobalAI.list) 用于 GlobalAI 分流，Clash 使用同名的域名、IP 和经典规则文件。Gemini 跳转的 `URL-REGEX` 仅在 Surge 产物中保留。
- `rules/China.list`：China 规则。当前批准的 IP 规则带 `no-resolve`，不含 `GEOIP`；`no_geoip` 配置已移除，匹配类型和参数的变化由固定白名单阻止。可同时用于分流和 DNS 映射：

```
[Rule]
RULE-SET,https://raw.githubusercontent.com/Soulleslie/surge-rules/refs/heads/main/rules/China.list,DIRECT
GEOIP,CN,DIRECT

[Host]
RULE-SET:https://raw.githubusercontent.com/Soulleslie/surge-rules/refs/heads/main/rules/China.list = server:system
```

本地手动同步（要求先安装 CI 中固定版本的 mihomo）：

```bash
python3 -B -m unittest discover -s tests -v
python3 -B scripts/sync.py --mihomo /path/to/mihomo --report /tmp/sync-report.json
python3 -B tests/smoke_mihomo.py --mihomo /path/to/mihomo
```

此命令同时生成 Surge 与 Clash。旧的无参数 `python3 scripts/sync.py` 不再允许只覆盖 Surge 文件。每个列表下载失败、校验不符、出现未审核新增或转换失败时保留旧版，其他列表照常处理，退出码为 1。请检查报告和 Git 差异后再提交。

## Clash（mihomo）

安全同步器用 mihomo 把上述规则转换到临时目录，成功后一起发布。`custom/` 为本地人工维护规则，仅生成对应 Clash 文件。每个规则拆成：

- `clash/<名称>.mrs`：DOMAIN / DOMAIN-SUFFIX，`behavior: domain`
- `clash/<名称>-IP.mrs`：IP-CIDR / IP-CIDR6，`behavior: ipcidr`
- `clash/<名称>-Extra.list`：DOMAIN-KEYWORD / IP-ASN / PROCESS-NAME，`behavior: classical`

mihomo 不支持的 USER-AGENT、URL-REGEX 会被丢弃；没有内容的部分不生成文件。

在 `sources.json` 中给列表加上 `"clash": false`，该列表就只发布 Surge 产物；同步时不生成 Clash 文件，并删除已有的 Clash 文件。目前 Apple 和 TestFlight 只用于 Apple 设备上的 Surge，不提供 Clash 版本。

在 `sources.json` 中给列表加上 `"exclude_lists": ["<其他列表>"]`，同步时会从该列表中去掉其他列表白名单已批准的规则。这些规则不计入保留比例，也不会因为是新增条目而拦截该列表；排除只依据固定的审核白名单，只能减少规则，不会放入新规则。目前 Apple 排除 TestFlight，TestFlight 以后新批准的规则也会自动从 Apple 中去掉。

```yaml
rule-providers:
  Google:
    type: http
    behavior: domain
    format: mrs
    url: https://raw.githubusercontent.com/Soulleslie/surge-rules/refs/heads/main/clash/Google.mrs
    path: ./rules/Google.mrs
    interval: 86400

rules:
  - RULE-SET,Google,Google
  - RULE-SET,Google-IP,Google,no-resolve
```

转换失败时该列表的 Surge、domain、IP 和 Extra 产物均保留旧版。写入中途出现可捕获的文件系统异常会回滚该组；多文件替换不承诺断电级事务，Git 提交才是对外发布边界。

更新白名单、初始事故清理方法和能力边界见 [safety/README.md](safety/README.md)。
