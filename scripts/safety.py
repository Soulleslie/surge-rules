"""Fail-closed, per-list reviewed rules. Network input cannot grant approval."""

import hashlib
import ipaddress
import json
import re
from collections import Counter
from pathlib import Path

TYPES = {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR', 'IP-CIDR6',
         'IP-ASN', 'PROCESS-NAME', 'USER-AGENT', 'URL-REGEX'}
IP_TYPES = {'IP-CIDR', 'IP-CIDR6', 'IP-ASN'}


class UnsafeRules(ValueError):
    def __init__(self, message, *, unknown=()):
        super().__init__(message)
        self.unknown = sorted(unknown)


def parse(text: str) -> list[str]:
    """Keep flags in the approval identity; reject policies/unknown rule syntax."""
    output = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if any(ord(c) < 32 or ord(c) == 127 for c in line):
            raise UnsafeRules('规则含控制字符')
        fields = [x.strip() for x in line.split(',')]
        kind = fields[0].upper()
        if kind not in TYPES or len(fields) < 2 or not fields[1]:
            raise UnsafeRules(f'不支持的规则语法: {line[:160]}')
        if kind in IP_TYPES:
            if len(fields) not in (2, 3) or len(fields) == 3 and fields[2].lower() != 'no-resolve':
                raise UnsafeRules(f'IP 规则含非预期参数: {line[:160]}')
            if kind == 'IP-ASN':
                if not fields[1].isdigit():
                    raise UnsafeRules('IP-ASN 不是数字')
            else:
                network = ipaddress.ip_network(fields[1], strict=False)
                if network.version != (4 if kind == 'IP-CIDR' else 6):
                    raise UnsafeRules('IP 规则地址族不符')
            fields[2:] = [x.lower() for x in fields[2:]]
        elif len(fields) != 2:
            raise UnsafeRules(f'规则含非预期参数: {line[:160]}')
        if kind in {'DOMAIN', 'DOMAIN-SUFFIX'}:
            if not re.fullmatch(r'[A-Za-z0-9_.-]+', fields[1]):
                raise UnsafeRules(f'域名格式不支持: {line[:160]}')
            fields[1] = fields[1].lower()
        fields[0] = kind
        output.append(','.join(fields))
    if not output:
        raise UnsafeRules('没有有效规则')
    return list(dict.fromkeys(output))


class Policy:
    def __init__(self, root: Path):
        self.root = root
        self.config = json.loads((root / 'safety/policy.json').read_text())
        if self.config.get('version') != 1:
            raise UnsafeRules('不支持的审核策略版本')
        if not 0.9 <= self.config.get('minimum_retained_fraction', 0) <= 1:
            raise UnsafeRules('最低保留比例不能低于 90%')
        self.excluded = set(parse(self.read_verified(self.config['excluded'])))
        self.approved = {}
        for name, item in self.config['lists'].items():
            if not re.fullmatch(r'[A-Za-z0-9]+', name):
                raise UnsafeRules('审核列表名称不合法')
            lines = set(parse(self.read_verified(item)))
            if len(lines) != item['count']:
                raise UnsafeRules(f'{name}: 审核条数与记录不符')
            self.approved[name] = lines

    def read_verified(self, item):
        path = Path(item['path'])
        if path.is_absolute() or '..' in path.parts or path.parts[0] != 'safety':
            raise UnsafeRules('审核路径必须位于 safety/ 中')
        if not (self.root / path).resolve().is_relative_to((self.root / 'safety').resolve()):
            raise UnsafeRules('审核文件不能通过链接逃逸 safety/')
        data = (self.root / path).read_bytes()
        if hashlib.sha256(data).hexdigest() != item['sha256']:
            raise UnsafeRules(f'审核文件校验和不符: {path}')
        return data.decode('utf-8')

    def clean(self, name: str, text: str) -> tuple[str, dict]:
        if name not in self.approved:
            raise UnsafeRules(f'{name}: 缺少独立审核白名单')
        lines = parse(text)
        approved = self.approved[name]
        unknown = set(lines) - approved - self.excluded
        # Never silently bless an unknown rule, even a single rule or a small growth.
        if unknown:
            raise UnsafeRules(f'{len(unknown)} 条未经审核的新规则，保留旧版', unknown=unknown)
        kept = [line for line in lines if line in approved]
        if len(kept) < len(approved) * self.config['minimum_retained_fraction']:
            raise UnsafeRules(f'清理后只剩 {len(kept)}/{len(approved)} 条，疑似不完整')
        if not kept:
            raise UnsafeRules('清理后规则为空')
        counts = Counter(line.split(',', 1)[0] for line in kept)
        updated = next((line.removeprefix('# UPDATED: ') for line in text.splitlines()
                        if re.fullmatch(r'# UPDATED: \d{4}-\d\d-\d\d \d\d:\d\d:\d\d', line)), 'unknown')
        header = [f'# NAME: {name}', '# AUTHOR: MagicRule (review-filtered)',
                  '# REPO: https://magicrule.pages.dev', f'# UPDATED: {updated}',
                  '# SAFETY: exact per-list reviewed allowlist; unknown additions require review']
        header += [f'# {kind}: {count}' for kind, count in sorted(counts.items())]
        return '\n'.join(header + [''] + kept) + '\n', {
            'upstream_rules': len(lines), 'accepted_rules': len(kept),
            'filtered_rules': len(lines) - len(kept), 'updated': updated,
        }
