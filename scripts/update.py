"""Stage, review, convert and publish each Surge/Clash group together."""

import argparse
import hashlib
import json
import re
import sys
import tempfile
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import clash
import sync
from artifacts import publish
from safety import Policy, UnsafeRules

ROOT = Path(__file__).resolve().parent.parent
DOWNLOAD_HOSTS = {'magicrule.pages.dev', 'rule-26r.pages.dev'}
RECOVERY_LISTS = {'Apple', 'Lan', 'Telegram', 'GlobalMedia', 'Speedtest'}


def checked_url(url):
    p = urlsplit(url)
    if (p.scheme != 'https' or p.hostname not in DOWNLOAD_HOSTS or p.port not in (None, 443)
            or p.username or p.password or not p.path.startswith('/data/')):
        raise UnsafeRules('拒绝非预期的下载地址')
    return url


class SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        checked_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url):
    checked_url(url)
    req = urllib.request.Request(url, headers={'User-Agent': 'surge-rules-updater', 'Cache-Control': 'no-cache'})
    with urllib.request.build_opener(SameOriginRedirect()).open(req, timeout=60) as resp:
        data = resp.read(8 * 1024 * 1024 + 1)
    if len(data) > 8 * 1024 * 1024:
        raise UnsafeRules('下载超过 8 MiB 上限')
    return data


def valid_metadata_line(line: bytes) -> bool:
    """A normalized byte line must also be one line to the rules parser."""
    try:
        decoded = line.decode('utf-8')
    except UnicodeDecodeError:
        return False
    return decoded.splitlines() == [decoded] and not re.search(rb'[\x00-\x1f\x7f]', line)


def without_description(body: bytes) -> bytes:
    """Remove the single DESC comment in the leading header comment block."""
    lines = body.split(b'\n')
    descriptions = []
    for index, raw_line in enumerate(lines):
        line = raw_line.removesuffix(b'\r')
        if not line.startswith(b'#'):
            break
        if line.startswith(b'# DESC:'):
            if not line.startswith(b'# DESC: ') or not line[8:].strip() or not valid_metadata_line(line):
                raise UnsafeRules('正文 SHA-256 校验的 DESC 注释格式不符')
            descriptions.append(index)
    if len(descriptions) != 1 or descriptions[0] == len(lines) - 1:
        raise UnsafeRules('五行头部校验要求头部有且只有一行完整的 DESC 注释')
    del lines[descriptions[0]]
    return b'\n'.join(lines)


def standard_header(lines, expected_name: str) -> bool:
    """The four leading NAME, AUTHOR, REPO, UPDATED lines of a MagicRule list."""
    headers = [line.removesuffix(b'\r') for line in lines]
    return (len(headers) == 4 and headers[0] == b'# NAME: ' + expected_name.encode('utf-8')
            and headers[1].startswith(b'# AUTHOR: ') and bool(headers[1][10:].strip())
            and headers[2].startswith(b'# REPO: ') and bool(headers[2][8:].strip())
            and re.fullmatch(rb'# UPDATED: \d{4}-\d\d-\d\d \d\d:\d\d:\d\d', headers[3]) is not None
            and all(valid_metadata_line(line) for line in headers))


def configured_artifact(entry):
    """The fixed per-list artifact URL in sources.json; when set, no index or manifest is used."""
    url = entry.get('artifact_url')
    if url is None:
        return None
    if not isinstance(url, str):
        raise UnsafeRules('配置的 artifact_url 必须是字符串')
    checked_url(url)
    parts = urlsplit(url)
    match = re.fullmatch(r'/data/_shared/artifacts/([A-Za-z0-9]+)_rules_[0-9a-f]{16}\.list', parts.path)
    if not match or match.group(1) != entry['name'] or parts.query or parts.fragment:
        raise UnsafeRules('artifact_url 必须是该列表固定的 rules 产物地址')
    return url


def verify_artifact(data: bytes, artifact: dict, expected_name: str) -> str:
    """Verify exact bytes, or the declared digest of the rules and fixed comments."""
    dedupe = artifact.get('dedupe')
    if not isinstance(dedupe, dict):
        raise UnsafeRules('manifest 缺少有效的产物 SHA-256')
    expected = dedupe.get('bytes_sha256')
    if not isinstance(expected, str) or not re.fullmatch('[0-9a-f]{64}', expected):
        raise UnsafeRules('manifest 缺少有效的产物 SHA-256')
    if hashlib.sha256(data).hexdigest() == expected:
        return 'bytes_sha256'

    semantic = dedupe.get('semantic_sha256')
    normalized_lines = dedupe.get('normalized_header_lines')
    if (artifact.get('key') != 'rules' or artifact.get('binary') is not False
            or dedupe.get('mode') != 'standard_header_normalized'
            or type(normalized_lines) is not int or normalized_lines not in (4, 5)
            or not isinstance(semantic, str) or not re.fullmatch('[0-9a-f]{64}', semantic)):
        raise UnsafeRules('产物 SHA-256 不符，且未声明支持的正文校验协议')
    parts = data.split(b'\n', 4)
    if len(parts) != 5:
        raise UnsafeRules('正文 SHA-256 校验要求四行完整元数据头')
    if not standard_header(parts[:4], expected_name):
        raise UnsafeRules('正文 SHA-256 校验的元数据头格式或规则名称不符')
    body = without_description(parts[4]) if normalized_lines == 5 else parts[4]
    if hashlib.sha256(body).hexdigest() != semantic:
        raise UnsafeRules('产物正文 SHA-256 与 manifest 不符')
    return 'semantic_sha256'


def candidate(entry, index, fetcher):
    direct = configured_artifact(entry)
    if direct is not None:
        # No upstream digest is checked; the per-rule allowlist still applies.
        data = fetcher(direct)
        if not standard_header(data.split(b'\n', 4)[:4], entry['name']):
            raise UnsafeRules('固定产物的元数据头格式或规则名称不符')
        return data.decode('utf-8'), direct, 'fixed-artifact'
    matches = index.get(entry['name'], [])
    if len(matches) != 1:
        raise UnsafeRules(f'索引里找到 {len(matches)} 个同名条目')
    manifest = json.loads(fetcher(checked_url(matches[0]['manifest'])))
    if manifest.get('rule') != entry['name'] or manifest.get('client') != 'Surge':
        raise UnsafeRules('manifest 名称或客户端不符')
    artifacts = [a for a in manifest.get('artifacts', []) if a.get('key') == entry['artifact']]
    if len(artifacts) != 1:
        raise UnsafeRules('manifest 中产物不唯一')
    artifact = artifacts[0]
    url = checked_url(artifact['url'])
    data = fetcher(url)
    verification = verify_artifact(data, artifact, entry['name'])
    return data.decode('utf-8'), url, verification


def clash_enabled(entry):
    """`"clash": false` in sources.json publishes Surge only and removes old Clash parts."""
    value = entry.get('clash', True)
    if type(value) is not bool:
        raise UnsafeRules('配置的 clash 开关必须是 true 或 false')
    return value


def excluded_rules(entry, policy, names):
    """Rules approved in the lists named by `"exclude_lists"`, to keep out of this list.

    Uses the pinned allowlists only, so it can remove rules but never admit one.
    """
    value = entry.get('exclude_lists', [])
    if (type(value) is not list or not all(isinstance(x, str) for x in value)
            or len(set(value)) != len(value) or entry['name'] in value or not set(value) <= set(names)):
        raise UnsafeRules('配置的 exclude_lists 必须是其他已配置列表名称的数组')
    return frozenset().union(*(policy.approved[n] for n in value))


def install(root, name, clean, mihomo, *, with_clash=True):
    with tempfile.TemporaryDirectory() as tmp:
        stage = Path(tmp)
        source = stage / 'rules' / f'{name}.list'
        source.parent.mkdir(parents=True)
        source.write_text(clean, encoding='utf-8')
        if with_clash:
            clash.build(mihomo, source, root=stage, out_dir=stage / 'clash')
        updates = {root / 'rules' / f'{name}.list': source.read_bytes()}
        for suffix in ('.mrs', '-IP.mrs', '-Extra.list'):
            part = Path('clash') / f'{name}{suffix}'
            path = stage / part
            updates[root / part] = path.read_bytes() if path.exists() else None
        publish(updates)


def recover_reviewed(names, mihomo, report_path, *, root=ROOT):
    """Explicit one-time recovery from local source-audited data, not a web retry.

    The normal scheduled updater never invokes this function or ignores a failed
    upstream checksum. The reviewed snapshot has its own pinned SHA-256.
    """
    if not set(names) <= RECOVERY_LISTS:
        raise UnsafeRules('恢复命令仅用于本次事故涉及的五个列表')
    policy = Policy(root)
    entries = {e['name']: e for e in json.loads((root / 'sources.json').read_text(encoding='utf-8'))['rules']}
    report = {'mode': 'local-reviewed-recovery', 'lists': {}}
    for name in names:
        item = policy.config['lists'][name]
        text = policy.read_verified(item)
        excluded = excluded_rules(entries.get(name, {'name': name}), policy, entries)
        clean, counts = policy.clean(name, text, excluded_by_config=excluded)
        clean = clean.replace('# AUTHOR: MagicRule (review-filtered)', '# AUTHOR: source-audited recovery')
        clean = clean.replace('# UPDATED: unknown', '# REVIEWED: ' + policy.config['reviewed_at'])
        install(root, name, clean, mihomo, with_clash=clash_enabled(entries.get(name, {})))
        report['lists'][name] = dict(counts, status='recovered', approved_sha256=item['sha256'])
        print(f'RECOVERED {name}: {counts["accepted_rules"]} source-reviewed rules')
    publish({Path(report_path): (json.dumps(report, ensure_ascii=False, indent=2) + '\n').encode()})
    return 0


UPSTREAM_TZ = timezone(timedelta(hours=8))  # MagicRule writes UPDATED in China time.


def stale_hint(text, row):
    """Warn when the index says the source changed after this file and the counts differ.

    Index rows are untrusted metadata: they only ever produce a warning.
    """
    if not isinstance(row, dict):
        return None
    match = re.search(r'^# UPDATED: (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)$', text, re.M)
    source, total = row.get('source_rule_updated_at'), row.get('total_line_count')
    if not match or not isinstance(source, str) or type(total) is not int:
        return None
    try:
        source_time = datetime.fromisoformat(source)
        if source_time.tzinfo is None:
            return None
    except ValueError:
        return None
    file_time = datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S').replace(tzinfo=UPSTREAM_TZ)
    rules = sum(1 for line in text.splitlines() if line.strip() and not line.lstrip().startswith('#'))
    if source_time > file_time + timedelta(hours=1) and total != rules:
        return (f'上游索引显示来源在 {source_time.astimezone(timezone.utc):%Y-%m-%d %H:%M} UTC 更新为 {total} 条，'
                f'固定产物仍是 {file_time.astimezone(timezone.utc):%Y-%m-%d %H:%M} UTC 的 {rules} 条；'
                '上游可能尚未发布，或 artifact_url 已过期')
    return None


def validated_entries(config, policy, root):
    entries = config['rules']
    names = [e['name'] for e in entries]
    if len(names) != len(set(names)) or set(names) != set(policy.approved):
        raise UnsafeRules('配置必须与独立审核的列表集合完全一致')
    if any(p.stem in names for p in (root / 'custom').glob('*.list')):
        raise UnsafeRules('custom/ 名称与上游列表冲突，可能覆盖已审核产物')
    for entry in entries:
        name = entry['name']
        if (not re.fullmatch(r'[A-Za-z0-9]+', name) or entry['output'] != f'rules/{name}.list'
                or entry['artifact'] != 'rules'):
            raise UnsafeRules('配置包含非预期输出路径或产物')
        clash_enabled(entry)
        excluded_rules(entry, policy, names)
        configured_artifact(entry)
    return entries, names


def load_index(config, entries, fetcher):
    """Return (index, available). Required only for lists without a fixed artifact_url."""
    index = {}
    try:
        for row in json.loads(fetcher(checked_url(config['index']))).get('rules', []):
            index.setdefault(row.get('name'), []).append(row)
    except Exception:
        if any(configured_artifact(entry) is None for entry in entries):
            raise
        return {}, False
    return index, True


def prepare(entry, index, fetcher, policy, names):
    """Download, verify and clean one list. Writes nothing."""
    name = entry['name']
    text, url, verification = candidate(entry, index, fetcher)
    detail = {'source': url, 'integrity_verification': verification}
    if verification == 'fixed-artifact' and len(index.get(name, [])) == 1:
        hint = stale_hint(text, index[name][0])
        if hint:
            detail['stale_hint'] = hint
    try:
        if entry.get('drop_bare_suffix'):
            text = sync.drop_bare_suffix(text, set(entry.get('keep_bare', [])))
        clean, counts = policy.clean(name, text, excluded_by_config=excluded_rules(entry, policy, names))
        detail.update(counts)
        with tempfile.TemporaryDirectory() as tmp:
            # Policy supplies the stronger, immutable retention floor.
            sync.check(entry, clean, Path(tmp) / 'not-written')
    except Exception as exc:
        exc.detail = detail  # Keep source, verification and any hint in the failure report.
        raise
    return clean, detail


def run(config, mihomo, report_path, *, root=ROOT, fetcher=fetch):
    report = {'lists': {}, 'fatal_error': None}
    failed = False
    try:
        policy = Policy(root)
        entries, names = validated_entries(config, policy, root)
        index, report['index_available'] = load_index(config, entries, fetcher)
        for entry in entries:
            name = entry['name']
            detail = {'status': 'failed'}
            report['lists'][name] = detail
            try:
                clean, prepared = prepare(entry, index, fetcher, policy, names)
                detail.update(prepared)
                if 'stale_hint' in detail:
                    print(f'::warning title={name} may be stale::{detail["stale_hint"]}')
                install(root, name, clean, mihomo, with_clash=clash_enabled(entry))
                detail['status'] = 'updated'
                print(f'OK {name}: {detail["accepted_rules"]} accepted, {detail["filtered_rules"]} quarantined')
            except Exception as exc:
                failed = True
                detail.update(getattr(exc, 'detail', {}))
                if 'stale_hint' in detail:
                    print(f'::warning title={name} may be stale::{detail["stale_hint"]}')
                detail['error'] = str(exc)
                detail['unknown_rules'] = getattr(exc, 'unknown', [])
                detail.setdefault('quarantined_rules', getattr(exc, 'quarantined', []))
                print(f'FAIL {name}: {exc}', file=sys.stderr)
        # custom/ is locally maintained, never fetched or modified by this updater.
        for source in sorted((root / 'custom').glob('*.list')):
            try:
                clash.build(mihomo, source, root=root, out_dir=root / 'clash')
            except Exception as exc:
                failed = True
                report['lists'][f'custom/{source.stem}'] = {'status': 'failed', 'error': str(exc)}
    except Exception as exc:
        failed = True
        report['fatal_error'] = str(exc)
        print(f'FAIL setup: {exc}', file=sys.stderr)
    finally:
        publish({Path(report_path): (json.dumps(report, ensure_ascii=False, indent=2) + '\n').encode()})
    return 1 if failed else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mihomo', required=True)
    parser.add_argument('--report', required=True)
    parser.add_argument('--recover-reviewed', nargs='+', choices=sorted(RECOVERY_LISTS),
                        help='Explicit recovery from checked-in audited data; never run by CI')
    args = parser.parse_args()
    if args.recover_reviewed:
        return recover_reviewed(args.recover_reviewed, args.mihomo, args.report)
    return run(json.loads((ROOT / 'sources.json').read_text(encoding='utf-8')),
               args.mihomo, args.report)
