"""Stage, review, convert and publish each Surge/Clash group together."""

import argparse
import hashlib
import json
import re
import sys
import tempfile
import urllib.request
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
    headers = [line.removesuffix(b'\r') for line in parts[:4]]
    if (headers[0] != b'# NAME: ' + expected_name.encode('utf-8')
            or not headers[1].startswith(b'# AUTHOR: ') or not headers[1][10:].strip()
            or not headers[2].startswith(b'# REPO: ') or not headers[2][8:].strip()
            or not re.fullmatch(rb'# UPDATED: \d{4}-\d\d-\d\d \d\d:\d\d:\d\d', headers[3])
            or not all(valid_metadata_line(line) for line in headers)):
        raise UnsafeRules('正文 SHA-256 校验的元数据头格式或规则名称不符')
    body = without_description(parts[4]) if normalized_lines == 5 else parts[4]
    if hashlib.sha256(body).hexdigest() != semantic:
        raise UnsafeRules('产物正文 SHA-256 与 manifest 不符')
    return 'semantic_sha256'


def candidate(entry, index, fetcher):
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


def install(root, name, clean, mihomo):
    with tempfile.TemporaryDirectory() as tmp:
        stage = Path(tmp)
        source = stage / 'rules' / f'{name}.list'
        source.parent.mkdir(parents=True)
        source.write_text(clean, encoding='utf-8')
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
    report = {'mode': 'local-reviewed-recovery', 'lists': {}}
    for name in names:
        item = policy.config['lists'][name]
        text = policy.read_verified(item)
        clean, counts = policy.clean(name, text)
        clean = clean.replace('# AUTHOR: MagicRule (review-filtered)', '# AUTHOR: source-audited recovery')
        clean = clean.replace('# UPDATED: unknown', '# REVIEWED: ' + policy.config['reviewed_at'])
        install(root, name, clean, mihomo)
        report['lists'][name] = dict(counts, status='recovered', approved_sha256=item['sha256'])
        print(f'RECOVERED {name}: {counts["accepted_rules"]} source-reviewed rules')
    publish({Path(report_path): (json.dumps(report, ensure_ascii=False, indent=2) + '\n').encode()})
    return 0


def run(config, mihomo, report_path, *, root=ROOT, fetcher=fetch):
    report = {'lists': {}, 'fatal_error': None}
    failed = False
    try:
        policy = Policy(root)
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
        index = {}
        for row in json.loads(fetcher(checked_url(config['index']))).get('rules', []):
            index.setdefault(row.get('name'), []).append(row)
        for entry in entries:
            name = entry['name']
            detail = {'status': 'failed'}
            report['lists'][name] = detail
            try:
                text, url, verification = candidate(entry, index, fetcher)
                detail.update(source=url, integrity_verification=verification)
                if entry.get('drop_bare_suffix'):
                    text = sync.drop_bare_suffix(text, set(entry.get('keep_bare', [])))
                clean, counts = policy.clean(name, text)
                detail.update(counts, source=url)
                with tempfile.TemporaryDirectory() as tmp:
                    # Policy supplies the stronger, immutable retention floor.
                    sync.check(entry, clean, Path(tmp) / 'not-written')
                install(root, name, clean, mihomo)
                detail['status'] = 'updated'
                print(f'OK {name}: {counts["accepted_rules"]} accepted, {counts["filtered_rules"]} quarantined')
            except Exception as exc:
                failed = True
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
