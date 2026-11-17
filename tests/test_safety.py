import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import artifacts
import clash
import update
from safety import Policy, UnsafeRules, parse


class RepositoryCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, path, text):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        return target

    def policy(self, lists, excluded='DOMAIN-SUFFIX,ad.invalid\n'):
        def item(path, text):
            p = self.write(path, text)
            return {'path': path, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest(),
                    'count': len(parse(text))}
        config = {'version': 1, 'minimum_retained_fraction': 0.9,
                  'excluded': item('safety/excluded.list', excluded), 'lists': {}}
        for name, lines in lists.items():
            config['lists'][name] = item(f'safety/approved/{name}.list', lines)
        self.write('safety/policy.json', json.dumps(config))
        return Policy(self.root)


class PolicyTests(RepositoryCase):
    def test_single_unknown_is_blocked_and_reported(self):
        policy = self.policy({'One': 'DOMAIN-SUFFIX,good.invalid\n'})
        with self.assertRaises(UnsafeRules) as result:
            policy.clean('One', 'DOMAIN-SUFFIX,good.invalid\nDOMAIN,novel-ad.invalid\nDOMAIN-SUFFIX,ad.invalid\n')
        self.assertEqual(result.exception.unknown, ['DOMAIN,novel-ad.invalid'])
        self.assertEqual(result.exception.quarantined, ['DOMAIN-SUFFIX,ad.invalid'])

    def test_known_pollution_is_removed_and_counts_rebuilt(self):
        policy = self.policy({'One': 'DOMAIN-SUFFIX,good.invalid\n'})
        clean, report = policy.clean('One', '# DOMAIN-SUFFIX: 1000\nDOMAIN-SUFFIX,good.invalid\nDOMAIN-SUFFIX,ad.invalid\n')
        self.assertNotIn('ad.invalid', clean)
        self.assertIn('# DOMAIN-SUFFIX: 1\n', clean)
        self.assertEqual(report['filtered_rules'], 1)
        self.assertEqual(report['quarantined_rules'], ['DOMAIN-SUFFIX,ad.invalid'])

    def test_approval_is_per_list_not_global(self):
        policy = self.policy({'One': 'DOMAIN,shared.invalid\n', 'Two': 'DOMAIN,other.invalid\n'},
                             'DOMAIN,shared.invalid\n')
        self.assertIn('DOMAIN,shared.invalid', policy.clean('One', 'DOMAIN,shared.invalid')[0])
        self.assertNotIn('shared.invalid', policy.clean('Two', 'DOMAIN,other.invalid\nDOMAIN,shared.invalid')[0])

    def test_modified_allowlist_cannot_self_approve(self):
        self.policy({'One': 'DOMAIN,good.invalid\n'})
        self.write('safety/approved/One.list', 'DOMAIN,ad.invalid\n')
        with self.assertRaisesRegex(UnsafeRules, '校验和'):
            Policy(self.root)

    def test_missing_policy_fails_closed(self):
        with self.assertRaises(FileNotFoundError):
            Policy(self.root)

    def test_extra_rule_argument_rejected(self):
        for text in ['DOMAIN,good.invalid,DIRECT', 'IP-CIDR,10.0.0.0/8,Proxy', '<html>error</html>']:
            with self.subTest(text=text), self.assertRaises(UnsafeRules):
                parse(text)

    def test_missing_no_resolve_is_not_same_approval(self):
        p = self.policy({'One': 'IP-CIDR,10.0.0.0/8,no-resolve\n'})
        with self.assertRaises(UnsafeRules):
            p.clean('One', 'IP-CIDR,10.0.0.0/8')

    def test_duplicates_cannot_hide_mass_deletion(self):
        lines = ''.join(f'DOMAIN,h{i}.invalid\n' for i in range(10))
        p = self.policy({'One': lines})
        with self.assertRaisesRegex(UnsafeRules, '清理后'):
            p.clean('One', 'DOMAIN,h0.invalid\n' * 100)

    def test_scope_never_broadens_from_full_domain_to_suffix(self):
        p = self.policy({'One': 'DOMAIN,good.invalid\n'})
        with self.assertRaises(UnsafeRules):
            p.clean('One', 'DOMAIN-SUFFIX,good.invalid')

    def test_case_and_spaces_normalized_before_check(self):
        p = self.policy({'One': 'DOMAIN,good.invalid\n'})
        self.assertEqual(parse(p.clean('One', 'domain, GOOD.INVALID')[0]), ['DOMAIN,good.invalid'])

    def test_new_list_needs_separate_approval(self):
        p = self.policy({'One': 'DOMAIN,good.invalid\n'})
        with self.assertRaises(UnsafeRules):
            p.clean('Two', 'DOMAIN,good.invalid')

    def test_minimum_retention_cannot_be_weakened(self):
        self.policy({'One': 'DOMAIN,good.invalid\n'})
        path = self.root / 'safety/policy.json'
        p = json.loads(path.read_text()); p['minimum_retained_fraction'] = 0.1
        path.write_text(json.dumps(p))
        with self.assertRaises(UnsafeRules):
            Policy(self.root)


class PipelineTests(RepositoryCase):
    def setup_remote(self, approved, incoming):
        self.policy(approved)
        config = {'index': 'https://magicrule.pages.dev/data/index.json', 'rules': []}
        rows, network = [], {}
        for name, text in incoming.items():
            manifest_url = f'https://magicrule.pages.dev/data/{name}/manifest.json'
            artifact_url = f'https://magicrule.pages.dev/data/{name}.list'
            config['rules'].append({'name': name, 'output': f'rules/{name}.list', 'artifact': 'rules'})
            rows.append({'name': name, 'manifest': manifest_url})
            network[artifact_url] = text.encode()
            network[manifest_url] = json.dumps({'rule': name, 'client': 'Surge', 'artifacts': [{
                'key': 'rules', 'url': artifact_url,
                'dedupe': {'bytes_sha256': hashlib.sha256(text.encode()).hexdigest()}}]}).encode()
            self.write(f'rules/{name}.list', 'OLD SURGE')
            for suffix in ('.mrs', '-IP.mrs', '-Extra.list'):
                self.write(f'clash/{name}{suffix}', 'OLD CLASH')
        network[config['index']] = json.dumps({'rules': rows}).encode()
        return config, network

    def execute(self, config, network, converter=None):
        def convert(mihomo, behavior, lines, out):
            out.write_bytes((behavior + '\n' + '\n'.join(lines)).encode())
        with patch.object(clash, 'convert', side_effect=converter or convert):
            code = update.run(config, 'fake', self.root / 'report.json',
                              root=self.root, fetcher=network.__getitem__)
        return code, json.loads((self.root / 'report.json').read_text())

    def snapshot(self):
        return {str(p.relative_to(self.root)): p.read_bytes()
                for folder in ['rules', 'clash'] for p in (self.root / folder).glob('*')}

    def normalized_remote(self, network, name, body):
        header = (f'# NAME: {name}\n# AUTHOR: MagicRule\n# REPO: https://magicrule.pages.dev\n'
                  '# UPDATED: 2026-11-15 09:50:07\n')
        received = (header + body).encode()
        original = (header.replace('09:50:07', '09:50:08') + body).encode()
        url = f'https://magicrule.pages.dev/data/{name}/manifest.json'
        manifest = json.loads(network[url])
        artifact = manifest['artifacts'][0]
        artifact['binary'] = False
        artifact['dedupe'] = {'mode': 'standard_header_normalized', 'normalized_header_lines': 4,
                              'bytes_sha256': hashlib.sha256(original).hexdigest(),
                              'semantic_sha256': hashlib.sha256(body.encode()).hexdigest()}
        network[artifact['url']] = received
        network[url] = json.dumps(manifest).encode()

    def test_valid_body_digest_still_filters_known_pollution(self):
        body = 'DOMAIN,good.invalid\nDOMAIN-SUFFIX,ad.invalid\n'
        c, n = self.setup_remote({'One': 'DOMAIN,good.invalid\n'}, {'One': body})
        self.normalized_remote(n, 'One', body)
        code, report = self.execute(c, n)
        self.assertEqual(code, 0)
        self.assertEqual(report['lists']['One']['integrity_verification'], 'semantic_sha256')
        self.assertEqual(report['lists']['One']['filtered_rules'], 1)
        self.assertNotIn('ad.invalid', (self.root / 'rules/One.list').read_text())
        self.assertNotIn(b'ad.invalid', (self.root / 'clash/One.mrs').read_bytes())

    def test_valid_body_digest_cannot_approve_unknown_rules(self):
        body = 'DOMAIN,good.invalid\nDOMAIN,new.invalid\n'
        c, n = self.setup_remote({'One': 'DOMAIN,good.invalid\n'}, {'One': body})
        self.normalized_remote(n, 'One', body)
        before = self.snapshot()
        code, report = self.execute(c, n)
        self.assertEqual(code, 1)
        self.assertEqual(report['lists']['One']['integrity_verification'], 'semantic_sha256')
        self.assertEqual(report['lists']['One']['unknown_rules'], ['DOMAIN,new.invalid'])
        self.assertEqual(before, self.snapshot())

    def test_cleaning_known_pollution_updates_surge_and_clash(self):
        c, n = self.setup_remote({'One': 'DOMAIN,good.invalid\n'},
                                 {'One': 'DOMAIN,good.invalid\nDOMAIN-SUFFIX,ad.invalid\n'})
        code, report = self.execute(c, n)
        self.assertEqual(code, 0)
        self.assertEqual(report['lists']['One']['filtered_rules'], 1)
        self.assertEqual(parse((self.root / 'rules/One.list').read_text()), ['DOMAIN,good.invalid'])
        self.assertIn(b'good.invalid', (self.root / 'clash/One.mrs').read_bytes())
        self.assertFalse((self.root / 'clash/One-IP.mrs').exists())

    def test_unknown_blocks_entire_group_but_other_list_updates(self):
        c, n = self.setup_remote({'One': 'DOMAIN,good.invalid\n', 'Two': 'DOMAIN,other.invalid\n'},
                                 {'One': 'DOMAIN,good.invalid\nDOMAIN,new.invalid\nDOMAIN-SUFFIX,ad.invalid\n', 'Two': 'DOMAIN,other.invalid\n'})
        code, report = self.execute(c, n)
        self.assertEqual(code, 1)
        self.assertEqual(report['lists']['One']['unknown_rules'], ['DOMAIN,new.invalid'])
        self.assertEqual(report['lists']['One']['quarantined_rules'], ['DOMAIN-SUFFIX,ad.invalid'])
        self.assertEqual((self.root / 'rules/One.list').read_text(), 'OLD SURGE')
        self.assertEqual((self.root / 'clash/One.mrs').read_text(), 'OLD CLASH')
        self.assertEqual(report['lists']['Two']['status'], 'updated')

    def test_ip_conversion_failure_keeps_all_previous_parts(self):
        text = 'DOMAIN,good.invalid\nIP-CIDR,10.0.0.0/8,no-resolve\n'
        c, n = self.setup_remote({'One': text}, {'One': text})
        before = self.snapshot()

        def converter(mihomo, behavior, lines, out):
            if behavior == 'ipcidr':
                raise RuntimeError('conversion failed')
            out.write_bytes(b'NEW DOMAIN MRS')

        code, _ = self.execute(c, n, converter)
        self.assertEqual(code, 1)
        self.assertEqual(before, self.snapshot())

    def test_sha_mismatch_keeps_previous_group(self):
        c, n = self.setup_remote({'One': 'DOMAIN,good.invalid\n'}, {'One': 'DOMAIN,good.invalid\n'})
        before = self.snapshot()
        n['https://magicrule.pages.dev/data/One.list'] = b'DOMAIN,changed.invalid\n'
        code, report = self.execute(c, n)
        self.assertEqual(code, 1)
        self.assertIn('SHA-256', report['lists']['One']['error'])
        self.assertEqual(before, self.snapshot())

    def test_network_failure_keeps_previous_group(self):
        c, n = self.setup_remote({'One': 'DOMAIN,good.invalid\n'}, {'One': 'DOMAIN,good.invalid\n'})
        before = self.snapshot()
        del n['https://magicrule.pages.dev/data/One.list']
        self.assertEqual(self.execute(c, n)[0], 1)
        self.assertEqual(before, self.snapshot())

    def test_ambiguous_index_keeps_previous_group(self):
        c, n = self.setup_remote({'One': 'DOMAIN,good.invalid\n'}, {'One': 'DOMAIN,good.invalid\n'})
        index = json.loads(n[c['index']])
        index['rules'] *= 2
        n[c['index']] = json.dumps(index).encode()
        before = self.snapshot()
        self.assertEqual(self.execute(c, n)[0], 1)
        self.assertEqual(before, self.snapshot())

    def test_mismatched_manifest_identity_rejected(self):
        c, n = self.setup_remote({'One': 'DOMAIN,good.invalid\n'}, {'One': 'DOMAIN,good.invalid\n'})
        url = 'https://magicrule.pages.dev/data/One/manifest.json'
        m = json.loads(n[url]); m['rule'] = 'Advertising'; n[url] = json.dumps(m).encode()
        before = self.snapshot()
        self.assertEqual(self.execute(c, n)[0], 1)
        self.assertEqual(before, self.snapshot())

    def test_configuration_cannot_escape_checkout(self):
        c, n = self.setup_remote({'One': 'DOMAIN,good.invalid\n'}, {'One': 'DOMAIN,good.invalid\n'})
        c['rules'][0]['output'] = '../outside.list'
        before = self.snapshot()
        code, report = self.execute(c, n)
        self.assertEqual(code, 1)
        self.assertIsNotNone(report['fatal_error'])
        self.assertEqual(before, self.snapshot())

    def test_missing_manifest_checksum_fails_closed(self):
        c, n = self.setup_remote({'One': 'DOMAIN,good.invalid\n'}, {'One': 'DOMAIN,good.invalid\n'})
        url = 'https://magicrule.pages.dev/data/One/manifest.json'
        m = json.loads(n[url]); del m['artifacts'][0]['dedupe']; n[url] = json.dumps(m).encode()
        before = self.snapshot()
        self.assertEqual(self.execute(c, n)[0], 1)
        self.assertEqual(before, self.snapshot())

    def test_custom_name_collision_fails_before_writes(self):
        c, n = self.setup_remote({'One': 'DOMAIN,good.invalid\n'}, {'One': 'DOMAIN,good.invalid\n'})
        self.write('custom/One.list', 'DOMAIN,custom.invalid\n')
        before = self.snapshot()
        self.assertEqual(self.execute(c, n)[0], 1)
        self.assertEqual(before, self.snapshot())

    def test_success_never_changes_approval_data(self):
        c, n = self.setup_remote({'One': 'DOMAIN,good.invalid\n'}, {'One': 'DOMAIN,good.invalid\n'})
        before = {str(p): p.read_bytes() for p in (self.root / 'safety').rglob('*') if p.is_file()}
        self.assertEqual(self.execute(c, n)[0], 0)
        self.assertEqual(before, {str(p): p.read_bytes() for p in (self.root / 'safety').rglob('*') if p.is_file()})


class ArtifactTests(RepositoryCase):
    def test_publish_rolls_back_replacement_failure(self):
        a, b = self.write('a', 'old a'), self.write('b', 'old b')
        original_replace = os.replace
        calls = 0

        def failing_replace(src, dst):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError('disk failure')
            return original_replace(src, dst)

        with patch.object(artifacts.os, 'replace', side_effect=failing_replace):
            with self.assertRaises(OSError):
                artifacts.publish({a: b'new a', b: b'new b'})
        self.assertEqual(a.read_text(), 'old a')
        self.assertEqual(b.read_text(), 'old b')
        self.assertFalse(list(self.root.glob('.rules-stage-*')))

    def test_deletion_is_rolled_back_with_other_parts(self):
        a, b = self.write('a', 'old a'), self.write('b', 'old b')
        original_replace = os.replace
        count = 0

        def fail_once(src, dst):
            nonlocal count
            count += 1
            if count == 1:
                raise OSError('disk failure')
            return original_replace(src, dst)

        with patch.object(artifacts.os, 'replace', side_effect=fail_once), self.assertRaises(OSError):
            artifacts.publish({a: None, b: b'new b'})
        self.assertEqual(a.read_text(), 'old a')
        self.assertEqual(b.read_text(), 'old b')


class DownloadTests(unittest.TestCase):
    def test_foreign_or_non_https_urls_rejected(self):
        for url in ['http://magicrule.pages.dev/data/x', 'https://evil.invalid/data/x',
                    'https://user@magicrule.pages.dev/data/x', 'https://magicrule.pages.dev/other/x']:
            with self.subTest(url=url), self.assertRaises(UnsafeRules):
                update.checked_url(url)

    def test_published_secondary_host_is_explicitly_allowed(self):
        url = 'https://rule-26r.pages.dev/data/Bybit.list'
        self.assertEqual(update.checked_url(url), url)


class ReviewedRepositoryTests(unittest.TestCase):
    def test_published_lists_are_all_reviewed(self):
        root = Path(__file__).resolve().parents[1]
        policy = Policy(root)
        config = json.loads((root / 'sources.json').read_text())
        self.assertEqual({e['name'] for e in config['rules']}, set(policy.approved))
        for e in config['rules']:
            with self.subTest(name=e['name']):
                text = (root / e['output']).read_text()
                self.assertLessEqual(set(parse(text)), policy.approved[e['name']])
                policy.clean(e['name'], text)

    def test_known_ad_examples_absent_from_five_cleaned_lists(self):
        root = Path(__file__).resolve().parents[1]
        markers = {'creenborsht.cfd', 'ibsbjipbonaxj.site', '8fjklyd4os.com',
                   'adorableorchid.com', 'agkmngwhtwtni.site'}
        for name in update.RECOVERY_LISTS:
            for line in parse((root / 'rules' / f'{name}.list').read_text()):
                self.assertFalse(markers.intersection(line.split(',')), (name, line))


if __name__ == '__main__':
    unittest.main()
