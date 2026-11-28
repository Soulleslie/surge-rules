# AGENTS.md

This file provides guidance to AI coding agents, such as Claude Code, when working with code in this repository.

## What this repository is

A fail-closed mirror of selected [MagicRule](https://magicrule.pages.dev/) Surge rule lists. Each upstream list is filtered through a pinned, per-list allowlist and published as `rules/<Name>.list` (Surge) plus `clash/<Name>.mrs`, `<Name>-IP.mrs` and `<Name>-Extra.list` (mihomo). Any new upstream rule blocks that list until a person reviews it. The user and the README write in Chinese; keep user-facing text in Chinese.

## Commands

Python 3 standard library only; nothing to install except the pinned mihomo binary for Clash output.

```bash
python3 -B -m unittest discover -s tests -v                      # all offline tests (CI runs this on every PR)
python3 -B -m unittest tests.test_safety.PipelineTests.test_fixed_artifact_cannot_approve_unknown_rules   # one test
python3 -B scripts/preview.py                                     # read-only: compare upstream with published lists
python3 -B scripts/sync.py --mihomo /path/to/mihomo --report /tmp/sync-report.json   # real sync (writes rules/ and clash/)
python3 -B tests/smoke_mihomo.py --mihomo /path/to/mihomo         # load every .mrs in a real mihomo
```

Use mihomo v1.19.33 and check SHA-256 `132f6f3edf9a65e62f04853aed3358472e0b2b7666daa8419edfa2ddf5bb6323` (pinned in `.github/workflows/sync.yml`). `preview.py` exits 1 when any list would be blocked and needs no mihomo. Always pass `-B`, or delete `scripts/__pycache__` before committing.

## Architecture

The pipeline lives in `scripts/update.py` (`scripts/sync.py` is only the CLI entry point and holds `check()` and the bare-suffix helpers):

1. `validated_entries` validates `sources.json`. The list names must equal the lists in `safety/policy.json`.
2. `load_index` reads the upstream index on a best-effort basis. It is required only for lists without `artifact_url`.
3. `prepare`, shared by sync and preview, runs per list:
   - `candidate` downloads the list. With `artifact_url` set, it fetches that URL and checks the standard NAME/AUTHOR/REPO/UPDATED header (`fixed-artifact`). Otherwise it goes index → manifest → artifact, checking `bytes_sha256` or the declared `semantic_sha256`.
   - It then computes the `stale_hint`, applies `drop_bare_suffix`, runs `Policy.clean`, and runs `sync.check`.
4. `install` writes the Surge file and the mihomo conversion (`scripts/clash.py`) together through `artifacts.publish`, which stages the files and rolls them back on failure.

A failure in one list keeps all of its old outputs, and the other lists still update.

`scripts/safety.py` `Policy` is the security core:

- It loads `safety/policy.json`, which pins the SHA-256 and count of every `safety/approved/<Name>.list`, of the global `safety/excluded.list`, of each per-list `safety/quarantine/<Name>.list`, and of each review file.
- `clean()` publishes only rules that are approved for that list. A rule that is known-excluded is quarantined. Any other unapproved rule raises `UnsafeRules`, which blocks the whole list.
- After cleaning, a list must keep at least 90% of its allowlist (`minimum_retained_fraction`).
- Rule identity includes the type and `no-resolve`. Approval is per list.

Per-list options in `sources.json` (stored as single-line compact JSON):

- `artifact_url`: a fixed `/data/_shared/artifacts/<Name>_rules_<16hex>.list` URL on `magicrule.pages.dev` or `rule-26r.pages.dev`.
- `clash: false`: publish Surge only and delete existing Clash parts. Currently set for Apple and TestFlight.
- `exclude_lists`: drop rules approved in other lists, using the pinned allowlists only. Excluded rules don't count toward the retention floor. Apple excludes TestFlight.
- `drop_bare_suffix` / `keep_bare`, `min_rules`, `must_contain`.

`custom/*.list` files are maintained by hand. The pipeline converts them to Clash and never fetches or rewrites them.

## Reviewing new upstream rules

CI must never change `safety/`, and nothing may widen an allowlist automatically. To approve or quarantine rules:

1. Run `scripts/preview.py` (or read the `sync-review-*` Actions report) to get `unknown_rules`.
2. Gather evidence from the original sources named in the upstream index row's `providers`, for example v2fly, Sukka `ruleset.skk.moe`, Loyalsoldier, blackmatrix7 or ACL4SSR. Earlier decisions in `safety/reviews/*.json` show the expected standard:
   - Approve only when a source contains the exact rule, it has no Sukka reject-list match, and the domain resolves in public DNS.
   - For China IPs, APNIC RDAP and GeoLite must both say CN.
   - Keywords and broadened parent suffixes need explicit corroboration.
3. Add each approved rule to `safety/approved/<Name>.list` (keep the file sorted), or add it to `safety/quarantine/<Name>.list` and record it under the list's `excluded` entry.
4. Recompute `sha256` and `count` in `policy.json`, written with `indent=2, ensure_ascii=False`.
5. Write a review file in `safety/reviews/` with URLs, source SHA-256s and per-rule decisions. Append it with its SHA-256 to `policy.json` `reviews`.
6. Run the tests, then the real sync, and commit the review data together with the regenerated outputs.

A new list needs a `sources.json` entry, an allowlist, a `policy.json` entry and an existing `rules/<Name>.list`. The pre-sync tests require every configured list to have published output; `Policy.clean` can generate it.

## Current operational constraints (as of 2026-11-28)

- **Upstream access.** MagicRule manifests return 403 with `x-magicrule-block-reason: turnstile-required`, so every list now uses `artifact_url`. GitHub Actions runners get 403 even for artifacts, so the scheduled sync (00:17 UTC) fails closed every day.
- **Manual sync.** Run the real sync elsewhere and open a PR containing only `rules/` and `clash/` changes. Such a PR does not trigger `sync.yml`. Merging changes under `scripts/`, `safety/`, `tests/`, `custom/` or `sources.json` does trigger it.
- **Don't route around upstream blocking.** No other User-Agents, no probing alternate hosts for manifests, no proxies.
- **Stale hints.** The upstream index can run ahead of the published file. A `stale_hint` with the same link still on the site means the upstream hasn't published yet; it doesn't mean the URL is stale.
- **Timezone.** The `UPDATED` header in upstream files is China time (UTC+8).
