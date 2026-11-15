"""Regression coverage for the upstream's explicitly declared header deduplication.

The fallback authenticates the exact bytes after the four metadata lines. It
must never normalize, sort, strip comments from, or rewrite the rule body.
"""

import copy
import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import update
from safety import UnsafeRules


class ArtifactIntegrityTests(unittest.TestCase):
    NAME = 'Example'
    ORIGINAL_TIME = '2026-11-15 09:50:08'
    SHARED_TIME = '2026-11-15 09:50:07'
    BODY = b'# DOMAIN: 2\n# DOMAIN-SUFFIX: 1\n\nDOMAIN,a.example\nDOMAIN,b.example\nDOMAIN-SUFFIX,c.example\n'

    @staticmethod
    def digest(data):
        return hashlib.sha256(data).hexdigest()

    def document(self, timestamp=None, body=None, headers=None):
        if headers is None:
            headers = [f'# NAME: {self.NAME}', '# AUTHOR: MagicRule',
                       '# REPO: https://magicrule.pages.dev',
                       '# UPDATED: ' + (timestamp or self.ORIGINAL_TIME)]
        prefix = ('\n'.join(headers) + '\n').encode('utf-8')
        return prefix + (self.BODY if body is None else body)

    def artifact(self, body=None):
        body = self.BODY if body is None else body
        return {
            'key': 'rules',
            'binary': False,
            'dedupe': {
                'bytes_sha256': self.digest(self.document(body=body)),
                'mode': 'standard_header_normalized',
                'normalized_header_lines': 4,
                'semantic_sha256': self.digest(body),
            },
        }

    def verify(self, data, artifact=None):
        return update.verify_artifact(data, self.artifact() if artifact is None else artifact, self.NAME)

    def assert_unsafe(self, data, artifact):
        with self.assertRaises(UnsafeRules):
            self.verify(data, artifact)

    def test_exact_original_bytes_pass(self):
        self.assertEqual(self.verify(self.document()), 'bytes_sha256')

    def test_exact_bytes_do_not_require_fallback_metadata(self):
        minimal = {'dedupe': {'bytes_sha256': self.digest(self.document())}}
        self.assertEqual(self.verify(self.document(), minimal), 'bytes_sha256')

    def test_timestamp_only_difference_uses_declared_semantic_digest(self):
        data = self.document(timestamp=self.SHARED_TIME)
        self.assertNotEqual(self.digest(data), self.artifact()['dedupe']['bytes_sha256'])
        self.assertEqual(self.verify(data), 'semantic_sha256')

    def test_fallback_does_not_mutate_inputs(self):
        data = self.document(timestamp=self.SHARED_TIME)
        artifact = self.artifact()
        before = copy.deepcopy(artifact)
        self.assertEqual(self.verify(data, artifact), 'semantic_sha256')
        self.assertEqual(artifact, before)
        self.assertEqual(data, self.document(timestamp=self.SHARED_TIME))

    def test_added_rule_is_not_hidden_by_semantic_fallback(self):
        body = self.BODY + b'DOMAIN-SUFFIX,unreviewed.example\n'
        self.assert_unsafe(self.document(timestamp=self.SHARED_TIME, body=body), self.artifact())

    def test_changed_rule_value_is_rejected(self):
        body = self.BODY.replace(b'a.example', b'ads.example')
        self.assert_unsafe(self.document(timestamp=self.SHARED_TIME, body=body), self.artifact())

    def test_changed_rule_type_is_rejected(self):
        body = self.BODY.replace(b'DOMAIN,a.example', b'DOMAIN-SUFFIX,a.example')
        self.assert_unsafe(self.document(timestamp=self.SHARED_TIME, body=body), self.artifact())

    def test_changed_count_comment_is_rejected(self):
        body = self.BODY.replace(b'# DOMAIN: 2', b'# DOMAIN: 999')
        self.assert_unsafe(self.document(timestamp=self.SHARED_TIME, body=body), self.artifact())

    def test_changed_body_comment_is_rejected(self):
        body = self.BODY + b'# different comment\n'
        self.assert_unsafe(self.document(timestamp=self.SHARED_TIME, body=body), self.artifact())

    def test_changed_rule_order_is_rejected(self):
        body = self.BODY.replace(b'DOMAIN,a.example\nDOMAIN,b.example',
                                 b'DOMAIN,b.example\nDOMAIN,a.example')
        self.assert_unsafe(self.document(timestamp=self.SHARED_TIME, body=body), self.artifact())

    def test_missing_final_newline_is_rejected(self):
        self.assert_unsafe(self.document(timestamp=self.SHARED_TIME, body=self.BODY[:-1]), self.artifact())

    def test_added_final_newline_is_rejected(self):
        self.assert_unsafe(self.document(timestamp=self.SHARED_TIME, body=self.BODY + b'\n'), self.artifact())

    def test_body_crlf_rewriting_is_rejected(self):
        self.assert_unsafe(self.document(timestamp=self.SHARED_TIME, body=self.BODY.replace(b'\n', b'\r\n')),
                           self.artifact())

    def test_missing_or_unknown_mode_cannot_enable_fallback(self):
        for mode in [None, '', 'standard', 'normalize_anything']:
            with self.subTest(mode=mode):
                artifact = self.artifact()
                if mode is None:
                    del artifact['dedupe']['mode']
                else:
                    artifact['dedupe']['mode'] = mode
                self.assert_unsafe(self.document(timestamp=self.SHARED_TIME), artifact)

    def test_header_count_requires_exact_integer_four(self):
        for count in [None, 0, 3, 5, 4.0, '4', True, False]:
            with self.subTest(count=count):
                artifact = self.artifact()
                if count is None:
                    del artifact['dedupe']['normalized_header_lines']
                else:
                    artifact['dedupe']['normalized_header_lines'] = count
                self.assert_unsafe(self.document(timestamp=self.SHARED_TIME), artifact)

    def test_binary_artifact_cannot_use_fallback(self):
        for binary in [None, True, 0, 'false']:
            with self.subTest(binary=binary):
                artifact = self.artifact()
                if binary is None:
                    del artifact['binary']
                else:
                    artifact['binary'] = binary
                self.assert_unsafe(self.document(timestamp=self.SHARED_TIME), artifact)

    def test_other_artifact_key_cannot_use_fallback(self):
        for key in [None, 'domain-set', 'rule-set', 'RULES']:
            with self.subTest(key=key):
                artifact = self.artifact()
                if key is None:
                    del artifact['key']
                else:
                    artifact['key'] = key
                self.assert_unsafe(self.document(timestamp=self.SHARED_TIME), artifact)

    def test_missing_invalid_bytes_digest_rejected_even_when_body_matches(self):
        for digest in [None, '', 'a' * 63, 'a' * 65, 'g' * 64, 0, True]:
            with self.subTest(digest=digest):
                artifact = self.artifact()
                if digest is None:
                    del artifact['dedupe']['bytes_sha256']
                else:
                    artifact['dedupe']['bytes_sha256'] = digest
                self.assert_unsafe(self.document(timestamp=self.SHARED_TIME), artifact)

    def test_missing_invalid_semantic_digest_rejected(self):
        for digest in [None, '', 'a' * 63, 'a' * 65, 'g' * 64, 0, True]:
            with self.subTest(digest=digest):
                artifact = self.artifact()
                if digest is None:
                    del artifact['dedupe']['semantic_sha256']
                else:
                    artifact['dedupe']['semantic_sha256'] = digest
                self.assert_unsafe(self.document(timestamp=self.SHARED_TIME), artifact)

    def test_mismatched_semantic_digest_rejected(self):
        artifact = self.artifact()
        artifact['dedupe']['semantic_sha256'] = self.digest(b'other body\n')
        self.assert_unsafe(self.document(timestamp=self.SHARED_TIME), artifact)

    def test_short_header_rejected_even_for_matching_empty_body_digest(self):
        artifact = self.artifact()
        artifact['dedupe']['semantic_sha256'] = self.digest(b'')
        for data in [b'', b'# NAME: Example\n',
                     b'# NAME: Example\n# AUTHOR: MagicRule\n# REPO: https://example.invalid\n']:
            with self.subTest(data=data):
                self.assert_unsafe(data, artifact)

    def test_wrong_metadata_labels_rejected(self):
        headers = ['# NAME: Example', '# AUTHOR: MagicRule',
                   '# REPO: https://magicrule.pages.dev', '# UPDATED: ' + self.SHARED_TIME]
        for index, replacement in enumerate(['# TITLE: Example', '# WRITER: MagicRule',
                                              '# SOURCE: https://magicrule.pages.dev',
                                              '# DATE: ' + self.SHARED_TIME]):
            with self.subTest(index=index):
                changed = headers.copy(); changed[index] = replacement
                self.assert_unsafe(self.document(headers=changed), self.artifact())

    def test_wrong_name_rejected_even_with_valid_semantic_digest(self):
        headers = ['# NAME: OtherList', '# AUTHOR: MagicRule',
                   '# REPO: https://magicrule.pages.dev', '# UPDATED: ' + self.SHARED_TIME]
        self.assert_unsafe(self.document(headers=headers), self.artifact())

    def test_empty_author_or_repo_rejected(self):
        for index, replacement in [(1, '# AUTHOR: '), (1, '# AUTHOR:    '),
                                    (2, '# REPO: '), (2, '# REPO:    ')]:
            with self.subTest(index=index, replacement=replacement):
                headers = ['# NAME: Example', '# AUTHOR: MagicRule',
                           '# REPO: https://magicrule.pages.dev', '# UPDATED: ' + self.SHARED_TIME]
                headers[index] = replacement
                self.assert_unsafe(self.document(headers=headers), self.artifact())

    def test_updated_header_requires_full_date_format(self):
        for timestamp in ['unknown', '2026-11-15', '2026-11-15T09:50:07',
                          '2026-11-15 09:50:07Z', '2026-1-15 09:50:07']:
            with self.subTest(timestamp=timestamp):
                self.assert_unsafe(self.document(timestamp=timestamp), self.artifact())

    def test_utf8_body_is_hashed_as_original_bytes(self):
        body = '# 备注：保持原始字节\nDOMAIN,example.invalid\n'.encode('utf-8')
        artifact = self.artifact(body)
        self.assertEqual(self.verify(self.document(timestamp=self.SHARED_TIME, body=body), artifact),
                         'semantic_sha256')
        changed = body.replace('备注'.encode('utf-8'), '说明'.encode('utf-8'))
        self.assert_unsafe(self.document(timestamp=self.SHARED_TIME, body=changed), artifact)

    def test_declared_original_crlf_body_is_preserved(self):
        body = b'# DOMAIN: 1\r\n\r\nDOMAIN,example.invalid\r\n'
        artifact = self.artifact(body)
        self.assertEqual(self.verify(self.document(timestamp=self.SHARED_TIME, body=body), artifact),
                         'semantic_sha256')


if __name__ == '__main__':
    unittest.main()
