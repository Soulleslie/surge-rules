# 审核策略与恢复

`policy.json` 固定每个白名单的 SHA-256、条数和最低保留比例；`approved/*.list` 是逐条批准数据，`excluded.list` 是此次对照中未获批准的已知条目。该文件名不表示其中每个条目在所有用途下都恶意。同一条规则可以在一个列表被批准，在另一个列表被隔离；批准仅对指定列表生效。

所有网络下载的新增项都不能自动成为批准数据。CI 只提交 `rules/` 与 `clash/`；`safety/` 必须通过独立代码审核更新。即使某次上游彻底修复，也不能自动从当前产物反推和扩大白名单。

## 本次来源审核

- 原工作区基于 `policy.json` 的 `baseline_commit`。
- 其余 23 个列表以此前已检查过的仓库版本作为固定基线，未宣称对它们每个历史条目的业务用途做了独立完整认证。
- Apple、Lan、Telegram、GlobalMedia、Speedtest 不信任旧基线：仅保留在实际分类源文件中有凭据的规则。来源包括配置中已经存在的 ACL4SSR、GeQ1an、Loyalsoldier、dler-io、sve1r、LM-Firefly、Telegram 官方地址，以及 Sukka 的具体分类文件、v2fly 的具体类别及其递归 include。
- 对已经存在的域名，可用原始来源中的精确相同规则，或覆盖该域名的 `DOMAIN-SUFFIX` 证明；这只用于本次离线审核，不是以后自动放行任何子域名的规则。
- 新增条目必须有原始来源中的精确类型和值证据；本次仅批准了 Speedtest 的 22 条新测速服务器。
- 原始来源中不支持的表达式（例如 host-wildcard、属性过滤 include、regexp）不作为放行凭据，记录在 `review.json`。无法核实不等同于确认恶意，但不会冒险发布。
- 原始数据本身也可能出错。固定白名单能保证今后的自动任务不放入未审核新条目，不能证明全部已有业务分类绝对正确。

`review.json` 保存实际取证 URL、下载内容 SHA-256、解析条数、未采用的语法、旧版剔除项和明确批准的新增项。审核日期在 `policy.json`。

## 初始恢复与日常同步

事故清理时，五个列表直接从经过来源对照且有本地校验和的批准快照重建，再使用真实 mihomo 生成 Clash。命令是明确的本地恢复操作，不会在日常 CI 自动执行：

```bash
python3 -B scripts/sync.py --mihomo /path/to/mihomo --report /tmp/recovery.json \
  --recover-reviewed Apple Lan Telegram GlobalMedia Speedtest
```

正常同步会验证上游 manifest 与文件 SHA-256。一旦上游发布元数据与文件不一致，保留本地审核过的旧产物并报错；不会改写期望校验和，也不使用本地恢复模式掩盖失败。只允许索引当前实际使用的两个固定 HTTPS 发布域名：`magicrule.pages.dev`、`rule-26r.pages.dev`，不会自动接纳其他域名或外站重定向。

## 以后审核新规则

1. 从 Actions 的 `sync-review-*` 报告取得被拦截的新增条目。
2. 对照对应列表的独立原始来源、规则含义和此次串表特征；不能仅凭名字像服务域名就放行。
3. 只在目标 `approved/<名称>.list` 中加入人工批准的精确条目，并重新计算相应 SHA-256 与 count；保存本次审核证据。不要用全量上游覆盖白名单。
4. 运行全部测试、安全同步和真实 mihomo 转换，检查差异，再提交审核数据与产物。CI 不代替这个审批过程。

如遇误删正常条目，可从 Git 历史回溯，但不能将未经核实的旧版本再次当作全量可信基线。
