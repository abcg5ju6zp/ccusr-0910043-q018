#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  tests/archive.py
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are
#  met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above
#    copyright notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
#  * Neither the name of the project nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

import base64
import copy
import datetime
import decimal
import json
import re
import unittest

import rule_engine
import rule_engine.errors as errors
from rule_engine import archive
from rule_engine.archive import format as archive_format
from rule_engine.archive.canonical import canonical_dumps

import dateutil.tz

try:
    import cryptography  # noqa: F401
except ImportError:
    has_cryptography = False
else:
    has_cryptography = True

def make_rule(**context_kwargs):
    type_resolver = rule_engine.type_resolver_from_dict({'user': {'age': 0, 'name': ''}})
    context = rule_engine.Context(type_resolver=type_resolver, **context_kwargs)
    return rule_engine.Rule("user['age'] >= 18 and user['name'] =~ 'a.*'", context=context)

def sign_payload(payload, key, format_version=archive.CURRENT_FORMAT_VERSION):
    """用指定密钥对手工构造的负载重新签名，生成完整档案字节。"""
    signature = {
            'kid': key.kid,
            'algorithm': key.algorithm,
            'value': base64.b64encode(key.sign(canonical_dumps(payload))).decode('ascii'),
    }
    envelope = archive_format.build_envelope(payload, signature, format_version=format_version)
    return canonical_dumps(envelope)

class ArchiveTestCase(unittest.TestCase):
    def setUp(self):
        self.key_ring = archive.KeyRing()
        self.key = self.key_ring.generate()
        self.importer = archive.ArchiveImporter(self.key_ring)

    def tearDown(self):
        archive_format.MIGRATIONS.clear()
        archive_format.KNOWN_EXTENSIONS.clear()

    def export(self, rule, **kwargs):
        return archive.export_rule(rule, self.key_ring, **kwargs)

    def import_payload(self, payload, key=None, format_version=archive.CURRENT_FORMAT_VERSION):
        return self.importer.import_archive(sign_payload(payload, key or self.key, format_version=format_version))

    def payload_of(self, rule):
        return archive_format.build_payload(rule)

class ArchiveRoundTripTests(ArchiveTestCase):
    def test_export_import_roundtrip(self):
        rule = make_rule()
        report = self.importer.import_archive(self.export(rule))
        self.assertEqual(report.decision, archive.ImportDecision.ACCEPT)
        self.assertTrue(report.accepted)
        self.assertFalse(report.duplicate)
        self.assertTrue(report.archive_id.startswith('sha256:'))
        materialized = report.materialize()
        self.assertEqual(materialized.text, rule.text)
        thing = {'user': {'age': 20, 'name': 'alice'}}
        self.assertEqual(materialized.evaluate(thing), rule.evaluate(thing))
        thing = {'user': {'age': 20, 'name': 'bob'}}
        self.assertEqual(materialized.evaluate(thing), rule.evaluate(thing))

    def test_export_is_deterministic(self):
        rule = make_rule()
        self.assertEqual(self.export(rule), self.export(rule))

    def test_export_contains_only_json_data(self):
        envelope = json.loads(self.export(make_rule()))
        self.assertEqual(envelope['format'], archive.FORMAT_MARKER)
        self.assertEqual(envelope['format_version'], archive.CURRENT_FORMAT_VERSION)
        self.assertIsInstance(envelope['payload']['expression']['text'], str)
        # 档案中不得出现解析器、类型解析器等环境代码的任何痕迹
        self.assertNotIn('resolver', json.dumps(envelope['payload']['context_options']))

    def test_context_options_roundtrip(self):
        type_resolver = rule_engine.type_resolver_from_dict({'user': {'age': 0, 'name': ''}})
        context = rule_engine.Context(
                type_resolver=type_resolver,
                regex_flags=re.IGNORECASE,
                default_timezone='utc',
                mapping_attribute_lookup=False,
                default_value=None,
                decimal_context=decimal.Context(prec=10),
        )
        rule = rule_engine.Rule("user['age'] >= 18 and user['name'] =~ 'a.*'", context=context)
        report = self.importer.import_archive(self.export(rule))
        self.assertTrue(report.accepted, msg=repr(report.reasons))
        context = report.materialize().context
        self.assertEqual(context.regex_flags, re.IGNORECASE)
        self.assertEqual(context.default_timezone, dateutil.tz.tzutc())
        self.assertFalse(context.mapping_attribute_lookup)
        self.assertIsNone(context.default_value)
        self.assertEqual(context.decimal_context.prec, 10)

    def test_regex_flags_behavior_preserved(self):
        rule = rule_engine.Rule("'ABC' =~ 'abc'", context=rule_engine.Context(regex_flags=re.IGNORECASE))
        report = self.importer.import_archive(self.export(rule))
        self.assertTrue(report.materialize().evaluate(None))

    def test_default_value_behavior_preserved(self):
        rule = rule_engine.Rule('missing_symbol == 42', context=rule_engine.Context(default_value=42))
        report = self.importer.import_archive(self.export(rule))
        self.assertTrue(report.materialize().evaluate({}))

    def test_symbol_manifest_recorded(self):
        rule = rule_engine.Rule('user.age > 17 and abs(user.age) > 0', context=rule_engine.Context())
        payload = self.payload_of(rule)
        self.assertEqual(payload['symbols']['external'], ['user'])
        self.assertEqual(payload['symbols']['builtins'], ['abs'])

class ArchiveTamperTests(ArchiveTestCase):
    def test_tampered_expression_quarantined(self):
        payload = self.payload_of(make_rule())
        payload['expression']['text'] = 'true'
        report = self.import_payload(payload)
        self.assertEqual(report.decision, archive.ImportDecision.QUARANTINE)
        self.assertFalse(report.accepted)

    def test_tampered_context_option_quarantined(self):
        # 传输途中被修改但攻击者无法重签：摘要或签名验证必须失败
        envelope = json.loads(self.export(make_rule(regex_flags=re.IGNORECASE)))
        envelope['payload']['context_options']['regex_flags'] = 0
        report = self.importer.import_archive(canonical_dumps(envelope))
        self.assertEqual(report.decision, archive.ImportDecision.QUARANTINE)
        # 攻击者重算摘要但无法伪造签名：仍然隔离
        envelope['header']['archive_id'] = archive.content_digest(envelope['payload'])
        report = self.importer.import_archive(canonical_dumps(envelope))
        self.assertEqual(report.decision, archive.ImportDecision.QUARANTINE)

    def test_tampered_bytes_quarantined(self):
        data = bytearray(self.export(make_rule()))
        data[-20] ^= 0x01
        report = self.importer.import_archive(bytes(data))
        self.assertEqual(report.decision, archive.ImportDecision.QUARANTINE)

    def test_tampered_archive_id_quarantined(self):
        envelope = json.loads(self.export(make_rule()))
        envelope['header']['archive_id'] = 'sha256:' + '0' * 64
        report = self.importer.import_archive(canonical_dumps(envelope))
        self.assertEqual(report.decision, archive.ImportDecision.QUARANTINE)

    def test_wrong_key_ring_quarantined(self):
        data = self.export(make_rule())
        other_ring = archive.KeyRing()
        other_ring.generate()
        report = archive.ArchiveImporter(other_ring).import_archive(data)
        self.assertEqual(report.decision, archive.ImportDecision.QUARANTINE)
        self.assertIn('not in the local trust key ring', report.reasons[0])

    def test_algorithm_mismatch_quarantined(self):
        payload = self.payload_of(make_rule())
        signature = {
                'kid': self.key.kid,
                'algorithm': archive.ALGORITHM_ED25519,
                'value': base64.b64encode(self.key.sign(canonical_dumps(payload))).decode('ascii'),
        }
        envelope = archive_format.build_envelope(payload, signature)
        report = self.importer.import_archive(canonical_dumps(envelope))
        self.assertEqual(report.decision, archive.ImportDecision.QUARANTINE)
        self.assertIn('algorithm', report.reasons[0])

    def test_malformed_envelopes_quarantined(self):
        for data in (
                b'not json',
                canonical_dumps(['not', 'an', 'object']),
                canonical_dumps({'format': 'other/format', 'format_version': 1}),
                canonical_dumps({'format': archive.FORMAT_MARKER, 'format_version': 'one'}),
                canonical_dumps({'format': archive.FORMAT_MARKER, 'format_version': 1, 'header': {}, 'payload': None}),
        ):
            report = self.importer.import_archive(data)
            self.assertEqual(report.decision, archive.ImportDecision.QUARANTINE, msg=repr(data))

    def test_symbol_manifest_mismatch_quarantined(self):
        payload = self.payload_of(make_rule())
        payload['symbols']['external'] = ['something.else']
        report = self.import_payload(payload)
        self.assertEqual(report.decision, archive.ImportDecision.QUARANTINE)
        self.assertIn('symbol manifest', report.reasons[0])

    def test_quarantined_archive_cannot_materialize(self):
        payload = self.payload_of(make_rule())
        payload['expression']['text'] = 'true'
        report = self.import_payload(payload)
        with self.assertRaises(errors.ArchiveImportError):
            report.materialize()

class ArchiveKeyLifecycleTests(ArchiveTestCase):
    def test_rotation_old_archives_still_verify(self):
        old_data = self.export(make_rule())
        old_kid = self.key_ring.active_key().kid
        new_key = self.key_ring.rotate()
        self.assertNotEqual(old_kid, new_key.kid)
        self.assertEqual(self.key_ring.get(old_kid).status(), 'retired')
        new_data = self.export(make_rule())
        importer = archive.ArchiveImporter(self.key_ring)
        self.assertTrue(importer.import_archive(old_data).accepted)
        self.assertTrue(importer.import_archive(new_data).accepted)

    def test_revoked_key_quarantines(self):
        data = self.export(make_rule())
        self.key_ring.revoke(self.key.kid)
        report = archive.ArchiveImporter(self.key_ring).import_archive(data)
        self.assertEqual(report.decision, archive.ImportDecision.QUARANTINE)
        self.assertIn('revoked', report.reasons[0])

    def test_expired_key_quarantines(self):
        key_ring = archive.KeyRing()
        key_ring.generate(expires_at=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1))
        data = archive.export_rule(make_rule(), key_ring)
        report = archive.ArchiveImporter(key_ring).import_archive(data)
        self.assertEqual(report.decision, archive.ImportDecision.QUARANTINE)
        self.assertIn('expired', report.reasons[0])

    def test_revoked_active_key_cannot_sign(self):
        self.key_ring.revoke(self.key.kid)
        with self.assertRaises(errors.ArchiveExportError):
            self.export(make_rule())

    def test_key_ring_persistence_roundtrip(self):
        data = self.export(make_rule())
        self.key_ring.revoke(self.key.kid)
        restored = archive.KeyRing.from_dict(json.loads(json.dumps(self.key_ring.to_dict())))
        self.assertEqual(restored.active_kid, self.key_ring.active_kid)
        self.assertTrue(restored.get(self.key.kid).revoked)
        report = archive.ArchiveImporter(restored).import_archive(data)
        self.assertEqual(report.decision, archive.ImportDecision.QUARANTINE)

    def test_trust_key_record_validation(self):
        with self.assertRaises(errors.ArchiveError):
            archive.TrustKey.from_dict({'kid': 'k-x', 'algorithm': 'rot13', 'material': '', 'created_at': ''})

    @unittest.skipUnless(has_cryptography, 'the cryptography package is not installed')
    def test_ed25519_roundtrip(self):
        key_ring = archive.KeyRing()
        key_ring.generate(archive.ALGORITHM_ED25519)
        data = archive.export_rule(make_rule(), key_ring)
        report = archive.ArchiveImporter(key_ring).import_archive(data)
        self.assertTrue(report.accepted, msg=repr(report.reasons))

class ArchiveIdempotencyTests(ArchiveTestCase):
    def test_duplicate_import_is_idempotent(self):
        data = self.export(make_rule())
        first = self.importer.import_archive(data)
        second = self.importer.import_archive(data)
        self.assertFalse(first.duplicate)
        self.assertTrue(second.duplicate)
        self.assertEqual(first.decision, second.decision)
        self.assertEqual(first.archive_id, second.archive_id)

    def test_duplicate_quarantine_is_sticky(self):
        payload = self.payload_of(make_rule())
        payload['expression']['text'] = 'true'
        data = sign_payload(payload, self.key)
        first = self.importer.import_archive(data)
        second = self.importer.import_archive(data)
        self.assertEqual(first.decision, archive.ImportDecision.QUARANTINE)
        self.assertEqual(second.decision, archive.ImportDecision.QUARANTINE)
        self.assertTrue(second.duplicate)

    def test_resigned_identical_payload_is_duplicate(self):
        rule = make_rule()
        first = self.importer.import_archive(self.export(rule))
        self.key_ring.rotate()
        second = self.importer.import_archive(self.export(rule))
        # 负载内容相同则 archive_id 相同：换钥重签不会改变规则含义，按幂等重放处理
        self.assertEqual(first.archive_id, second.archive_id)
        self.assertTrue(second.duplicate)
        self.assertEqual(second.key_id, first.key_id)

class ArchiveMigrationTests(ArchiveTestCase):
    def make_v0_archive(self, rule):
        # 假想的历史 v0 格式：expression 直接是文本字符串而非对象
        payload = self.payload_of(rule)
        payload['expression'] = payload['expression']['text']
        return sign_payload(payload, self.key, format_version=0)

    @staticmethod
    def migrate_v0(payload):
        payload = dict(payload)
        payload['expression'] = {'grammar': archive.GRAMMAR_VERSION, 'text': payload['expression']}
        return payload

    def test_old_format_is_migrated(self):
        archive.register_migration(0, self.migrate_v0)
        report = self.importer.import_archive(self.make_v0_archive(make_rule()))
        self.assertEqual(report.decision, archive.ImportDecision.MIGRATE)
        self.assertEqual(report.migrated_from, 0)
        self.assertIsNotNone(report.migrated_archive_id)
        self.assertNotEqual(report.migrated_archive_id, report.archive_id)
        self.assertTrue(report.materialize().evaluate({'user': {'age': 20, 'name': 'alice'}}))

    def test_missing_migrator_quarantines(self):
        report = self.importer.import_archive(self.make_v0_archive(make_rule()))
        self.assertEqual(report.decision, archive.ImportDecision.QUARANTINE)
        self.assertIn('no migration is registered', report.reasons[0])

    def test_migration_requires_valid_signature_first(self):
        data = bytearray(self.make_v0_archive(make_rule()))
        data[-20] ^= 0x01
        archive.register_migration(0, self.migrate_v0)
        report = self.importer.import_archive(bytes(data))
        self.assertEqual(report.decision, archive.ImportDecision.QUARANTINE)

    def test_newer_format_quarantines(self):
        payload = self.payload_of(make_rule())
        report = self.import_payload(payload, format_version=archive.CURRENT_FORMAT_VERSION + 1)
        self.assertEqual(report.decision, archive.ImportDecision.QUARANTINE)
        self.assertIn('newer than supported', report.reasons[0])

    def test_invalid_migration_registration(self):
        with self.assertRaises(errors.ArchiveError):
            archive.register_migration(archive.CURRENT_FORMAT_VERSION, self.migrate_v0)

class ArchiveExtensionTests(ArchiveTestCase):
    def test_unknown_critical_extension_quarantines(self):
        data = self.export(make_rule(), extensions={'acme.scoring': {'critical': True, 'data': {'weight': 2}}})
        report = self.importer.import_archive(data)
        self.assertEqual(report.decision, archive.ImportDecision.QUARANTINE)
        self.assertIn('unknown critical extension', report.reasons[0])

    def test_unknown_noncritical_extension_is_ignored(self):
        data = self.export(make_rule(), extensions={'acme.audit': {'critical': False, 'data': {'ticket': 'T-1'}}})
        report = self.importer.import_archive(data)
        self.assertTrue(report.accepted, msg=repr(report.reasons))
        self.assertEqual(report.ignored_extensions, ('acme.audit',))
        # 被剥离的扩展不参与物化，规则含义不变
        self.assertEqual(report._payload['extensions'], {})
        self.assertTrue(report.materialize().evaluate({'user': {'age': 20, 'name': 'alice'}}))

    def test_known_extension_is_validated(self):
        def validate(data):
            if not isinstance(data, dict) or 'owner' not in data:
                raise ValueError('owner is required')
        archive.register_extension('acme.ownership', validate)
        good = self.export(make_rule(), extensions={'acme.ownership': {'critical': True, 'data': {'owner': 'compliance'}}})
        self.assertTrue(self.importer.import_archive(good).accepted)
        bad = self.export(make_rule(), extensions={'acme.ownership': {'critical': True, 'data': {}}})
        report = self.importer.import_archive(bad)
        self.assertEqual(report.decision, archive.ImportDecision.QUARANTINE)
        self.assertIn('failed validation', report.reasons[0])

    def test_extension_data_must_be_json_safe(self):
        with self.assertRaises(errors.ArchiveExportError):
            self.export(make_rule(), extensions={'acme.bad': {'data': object()}})

class ArchiveCapabilityTests(ArchiveTestCase):
    def test_engine_version_out_of_range_quarantines(self):
        payload = self.payload_of(make_rule())
        payload['engine']['max_version'] = '5.0'
        report = self.import_payload(payload)
        self.assertEqual(report.decision, archive.ImportDecision.QUARANTINE)
        self.assertIn('compatibility range', report.reasons[0])

    def test_unknown_context_option_quarantines(self):
        payload = self.payload_of(make_rule())
        payload['context_options']['surprise_option'] = True
        report = self.import_payload(payload)
        self.assertEqual(report.decision, archive.ImportDecision.QUARANTINE)
        self.assertIn('unknown context option', report.reasons[0])

    def test_missing_builtin_quarantines(self):
        payload = self.payload_of(make_rule())
        payload['symbols']['builtins'] = sorted(payload['symbols']['builtins'] + ['definitely_not_a_builtin'])
        report = self.import_payload(payload)
        self.assertEqual(report.decision, archive.ImportDecision.QUARANTINE)
        self.assertIn('builtin', report.reasons[0])

    def test_unsupported_regex_flags_quarantine(self):
        payload = self.payload_of(make_rule())
        payload['context_options']['regex_flags'] = 1 << 20
        report = self.import_payload(payload)
        self.assertEqual(report.decision, archive.ImportDecision.QUARANTINE)
        self.assertIn('regex_flags', report.reasons[0])

    def test_unparseable_expression_quarantines(self):
        payload = self.payload_of(make_rule())
        payload['expression']['text'] = 'and or not'
        payload['symbols'] = {'builtins': [], 'external': []}
        report = self.import_payload(payload)
        self.assertEqual(report.decision, archive.ImportDecision.QUARANTINE)
        self.assertIn('failed to parse', report.reasons[0])

    def test_non_finite_numbers_rejected(self):
        report = self.importer.import_archive(b'{"format": "rule-engine/archive", "format_version": NaN}')
        self.assertEqual(report.decision, archive.ImportDecision.QUARANTINE)

class ArchiveExportBoundaryTests(ArchiveTestCase):
    def test_default_value_object_rejected(self):
        rule = rule_engine.Rule('true', context=rule_engine.Context(default_value=object()))
        with self.assertRaises(errors.ArchiveExportError):
            self.export(rule)

    def test_custom_timezone_rejected(self):
        rule = rule_engine.Rule('true', context=rule_engine.Context(
                default_timezone=dateutil.tz.gettz('America/New_York')
        ))
        with self.assertRaises(errors.ArchiveExportError):
            self.export(rule)

    def test_future_format_version_rejected(self):
        with self.assertRaises(errors.ArchiveExportError):
            archive.export_rule(make_rule(), self.key_ring, format_version=archive.CURRENT_FORMAT_VERSION + 1)

    def test_resolver_is_not_serialized(self):
        # 自定义解析器属于环境代码：导出不含它，导入方用自己的环境解析业务对象
        context = rule_engine.Context(resolver=lambda thing, name: thing[name])
        rule = rule_engine.Rule('value > 1', context=context)
        envelope = json.loads(self.export(rule))
        self.assertEqual(set(envelope['payload']['context_options']), set(archive_format.CONTEXT_OPTION_KEYS))
        report = self.importer.import_archive(self.export(rule))
        materialized = report.materialize()
        self.assertTrue(materialized.evaluate({'value': 2}))
        self.assertFalse(materialized.evaluate({'value': 0}))

    def test_archive_carries_no_business_objects(self):
        rule = make_rule()
        rule.evaluate({'user': {'age': 20, 'name': 'alice', 'secret': 's3cr3t'}})
        envelope_text = self.export(rule).decode('utf-8')
        self.assertNotIn('alice', envelope_text)
        self.assertNotIn('s3cr3t', envelope_text)
