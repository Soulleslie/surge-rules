#!/usr/bin/env python3
"""只读预检：按正式同步的同一流程下载、校验和清理每个列表，与已发布的 Surge 规则比对。

不修改仓库中的任何文件（只在指定 --json 时写出报告），也不需要 mihomo。用于在同步前查看待审核的新增条目、上游删除和过期提示。

用法：python3 -B scripts/preview.py [--json 报告路径]
退出码：0 表示全部列表可以同步；1 表示有列表被拦截（例如出现未审核的新增）或无法下载。
"""

import argparse
import json
import sys
from pathlib import Path

import update
from safety import Policy, parse

ROOT = Path(__file__).resolve().parent.parent


def preview(config, *, root=ROOT, fetcher=update.fetch):
    policy = Policy(root)
    entries, names = update.validated_entries(config, policy, root)
    index, available = update.load_index(config, entries, fetcher)
    report = {'index_available': available, 'lists': {}}
    for entry in entries:
        name = entry['name']
        published = set(parse((root / entry['output']).read_text(encoding='utf-8')))
        item = {}
        try:
            clean, detail = update.prepare(entry, index, fetcher, policy, names)
            item.update(detail)
            fresh = set(parse(clean))
            item['added'] = sorted(fresh - published)
            item['removed'] = sorted(published - fresh)
            item['status'] = 'changed' if fresh != published else 'same'
        except Exception as exc:
            item.update(getattr(exc, 'detail', {}))
            item.update(status='blocked', error=str(exc), unknown_rules=list(getattr(exc, 'unknown', [])))
        report['lists'][name] = item
    return report


def show(report):
    for name, item in report['lists'].items():
        status = item['status']
        line = f'{status.upper():8} {name}'
        if status == 'changed':
            line += f'  +{len(item["added"])} -{len(item["removed"])}'
        elif status == 'blocked':
            line += f'  {item["error"]}'
        print(line)
        for rule in item.get('unknown_rules', []):
            print(f'    待审核  {rule}')
        for rule in item.get('added', []):
            print(f'    新增    {rule}')
        for rule in item.get('removed', []):
            print(f'    删除    {rule}')
        if item.get('stale_hint'):
            print(f'    提示    {item["stale_hint"]}')
    if not report['index_available']:
        print('注意：上游索引不可用，未检查固定产物是否过期。')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--json', help='另存完整 JSON 报告到此路径')
    args = parser.parse_args()
    try:
        report = preview(json.loads((ROOT / 'sources.json').read_text(encoding='utf-8')))
    except Exception as exc:
        print(f'FAIL setup: {exc}', file=sys.stderr)
        return 1
    show(report)
    if args.json:
        Path(args.json).write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return 1 if any(item['status'] == 'blocked' for item in report['lists'].values()) else 0


if __name__ == '__main__':
    sys.exit(main())
