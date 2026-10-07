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

"""可移植规则档案的回归测试。

覆盖：往返等价、上下文选项保真、签名完整性、未知/撤销密钥、密钥轮换、
重复导入幂等与冲突、能力边界、旧格式迁移、未知扩展隔离、OBJECT 模式
（含自引用）、以及业务对象绝不进入档案。
"""

import dataclasses
import datetime
import decimal
import json
import os
import re
import tempfile
import unittest

import rule_engine
from rule_engine import Context, Rule, DataType, resolve_attribute, type_resolver_from_dataclass
from rule_engine.archive import (
    ImportDecision,
    ImportRegistry,
    LocalKeyring,
    RuleArchive,
    SigningKey,
    TrustedKey,
    UnverifiedArchiveError,
)
from rule_engine.archive.errors import (
    ArchiveFormatError,
    SchemaExportError,
)
from rule_engine.archive.manifest import FORMAT_VERSION, canonical_encode


@dataclasses.dataclass
class ArchiveAddress:
    city: str
    zip_code: 'str | None' = None


@dataclasses.dataclass
class ArchivePerson:
    name: str
    age: float
    address: ArchiveAddress
    friends: 'list[ArchivePerson] | None' = None


def make_keyring(*signing_keys):
    keyring = LocalKeyring()
    for signing_key in signing_keys:
        keyring.add_signing_key(signing_key)
    return keyring


def resign(archive: RuleArchive, signing_key: SigningKey) -> RuleArchive:
    """用 *signing_key* 对（可能被篡改的）档案重新签名，模拟持有受信密钥一方手工构造的档案。"""
    manifest = archive.manifest
    payload = canonical_encode(manifest)
    import base64
    archive.envelope['signatures'] = [{
        'algorithm': 'ed25519',
        'key_id': signing_key.key_id,
        'signature': base64.b64encode(signing_key.sign(payload)).decode('ascii'),
    }]
    return archive


class ArchiveRoundtripTests(unittest.TestCase):
    def setUp(self):
        self.signing_key = SigningKey.generate()
        self.keyring = make_keyring(self.signing_key)

    def _roundtrip(self, rule, **export_kwargs):
        archive = RuleArchive.export(rule, self.signing_key, **export_kwargs)
        data = archive.to_bytes()
        report = RuleArchive.from_bytes(data).import_rule(self.keyring)
        return archive, report

    def test_basic_roundtrip(self):
        context = Context(type_resolver={'name': DataType.STRING, 'age': DataType.FLOAT})
        rule = Rule('name =~ "alice" and age > 18', context=context)
        archive, report = self._roundtrip(rule)
        self.assertIs(report.decision, ImportDecision.ACCEPT)
        self.assertEqual(report.reasons, [])
        self.assertFalse(report.duplicate)
        imported = report.require_accepted()
        self.assertTrue(imported.matches({'name': 'alice', 'age': 20}))
        self.assertFalse(imported.matches({'name': 'bob', 'age': 20}))
        self.assertEqual(imported.text, rule.text)
        self.assertEqual(report.rule_id, archive.manifest['rule']['id'])
        self.assertEqual(len(report.digest), 64)

    def test_regex_flags_are_preserved(self):
        context = Context(regex_flags=re.IGNORECASE, type_resolver={'name': DataType.STRING})
        rule = Rule('name =~ "alice"', context=context)
        _, report = self._roundtrip(rule)
        imported = report.require_accepted()
        # IGNORECASE 必须随档案迁移，否则 'ALICE' 不会匹配
        self.assertTrue(imported.matches({'name': 'ALICE'}))

    def test_decimal_context_is_preserved(self):
        context = Context(decimal_context=decimal.Context(prec=4), type_resolver={'n': DataType.FLOAT})
        rule = Rule('n / 3.0 == 0.3333', context=context)
        _, report = self._roundtrip(rule)
        imported = report.require_accepted()
        # prec=4 必须随档案迁移：1/3 在运行期舍入到 0.3333
        self.assertTrue(imported.matches({'n': 1}))
        self.assertEqual(imported.context.decimal_context.prec, 4)

    def test_default_value_null_is_preserved(self):
        context = Context(default_value=None)
        rule = Rule('missing == null', context=context)
        _, report = self._roundtrip(rule)
        imported = report.require_accepted()
        self.assertTrue(imported.matches({'other': 1}))

    def test_mapping_attribute_lookup_flag_is_preserved(self):
        context = Context(mapping_attribute_lookup=False, type_resolver={'n': DataType.FLOAT})
        rule = Rule('n == 1', context=context)
        _, report = self._roundtrip(rule)
        imported = report.require_accepted()
        self.assertFalse(imported.context.mapping_attribute_lookup)

    def test_default_timezone_utc_is_preserved(self):
        context = Context(default_timezone='utc')
        rule = Rule('$now != null', context=context)
        _, report = self._roundtrip(rule)
        imported = report.require_accepted()
        import dateutil.tz
        self.assertIsInstance(imported.context.default_timezone, dateutil.tz.tzutc)

    def test_resolver_attribute_is_preserved(self):
        context = Context(
            type_resolver=type_resolver_from_dataclass(ArchivePerson),
            resolver=resolve_attribute
        )
        rule = Rule('name == "alice" and address.city == "nyc"', context=context)
        _, report = self._roundtrip(rule)
        imported = report.require_accepted()
        self.assertTrue(imported.matches(ArchivePerson(name='alice', age=30, address=ArchiveAddress(city='nyc'))))
        self.assertFalse(imported.matches(ArchivePerson(name='bob', age=30, address=ArchiveAddress(city='nyc'))))

    def test_self_referencing_object_schema(self):
        context = Context(type_resolver=type_resolver_from_dataclass(ArchivePerson), resolver=resolve_attribute)
        rule = Rule('friends != null and address.zip_code == "10001"', context=context)
        archive, report = self._roundtrip(rule)
        self.assertIs(report.decision, ImportDecision.ACCEPT, msg=report.reasons)
        imported = report.require_accepted()
        person = ArchivePerson(
            name='alice', age=30,
            address=ArchiveAddress(city='nyc', zip_code='10001'),
            friends=[]
        )
        self.assertTrue(imported.matches(person))
        # 自引用必须编码为 REF，而不是无限展开
        serialized = archive.to_json()
        self.assertIn('"kind": "REF"', serialized)

    def test_nullable_and_collection_types(self):
        context = Context(type_resolver={
            'tags': DataType.ARRAY(DataType.NULLABLE(DataType.STRING)),
            'meta': DataType.MAPPING(DataType.STRING, DataType.FLOAT),
        })
        rule = Rule('tags[0] == "a" and meta["k"] > 1', context=context)
        _, report = self._roundtrip(rule)
        self.assertIs(report.decision, ImportDecision.ACCEPT, msg=report.reasons)
        self.assertTrue(report.require_accepted().matches({'tags': ['a', None], 'meta': {'k': 2}}))

    def test_builtin_symbols_are_listed(self):
        rule = Rule('$now != null and $pi > 3')
        archive, report = self._roundtrip(rule)
        self.assertIs(report.decision, ImportDecision.ACCEPT)
        builtins = {(entry['scope'], entry['name']) for entry in archive.manifest['symbols']}
        self.assertIn(('built-in', 'now'), builtins)
        self.assertIn(('built-in', 'pi'), builtins)

    def test_explicit_rule_id(self):
        rule = Rule('n == 1', Context(type_resolver={'n': DataType.FLOAT}))
        archive, report = self._roundtrip(rule, rule_id='stable-rule-id')
        self.assertEqual(archive.manifest['rule']['id'], 'stable-rule-id')
        self.assertEqual(report.rule_id, 'stable-rule-id')

    def test_file_roundtrip(self):
        rule = Rule('n == 1', Context(type_resolver={'n': DataType.FLOAT}))
        archive = RuleArchive.export(rule, self.signing_key)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, 'rule.re-archive.json')
            archive.save(path)
            loaded = RuleArchive.load(path)
        report = loaded.import_rule(self.keyring)
        self.assertIs(report.decision, ImportDecision.ACCEPT)


class ArchiveIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.signing_key = SigningKey.generate()
        self.keyring = make_keyring(self.signing_key)
        self.context = Context(type_resolver={'name': DataType.STRING, 'age': DataType.FLOAT})
        self.rule = Rule('name == "alice" and age > 18', context=self.context)
        self.archive = RuleArchive.export(self.rule, self.signing_key)

    def test_tampered_expression_is_quarantined(self):
        envelope = json.loads(self.archive.to_bytes())
        envelope['manifest']['rule']['text'] = 'age > 0'
        report = RuleArchive.from_dict(envelope).import_rule(self.keyring)
        self.assertIs(report.decision, ImportDecision.QUARANTINE)
        self.assertTrue(any('trusted' in reason for reason in report.reasons))
        with self.assertRaises(UnverifiedArchiveError):
            report.require_accepted()

    def test_tampered_context_options_are_quarantined(self):
        envelope = json.loads(self.archive.to_bytes())
        envelope['manifest']['context']['regex_flags'] = ['IGNORECASE']
        report = RuleArchive.from_dict(envelope).import_rule(self.keyring)
        self.assertIs(report.decision, ImportDecision.QUARANTINE)

    def test_unknown_signing_key_is_quarantined(self):
        report = self.archive.import_rule(LocalKeyring())
        self.assertIs(report.decision, ImportDecision.QUARANTINE)
        self.assertTrue(any('trusted' in reason for reason in report.reasons))

    def test_corrupt_signature_is_quarantined(self):
        envelope = json.loads(self.archive.to_bytes())
        envelope['signatures'][0]['signature'] = envelope['signatures'][0]['signature'][:-4] + 'AAAA'
        report = RuleArchive.from_dict(envelope).import_rule(self.keyring)
        self.assertIs(report.decision, ImportDecision.QUARANTINE)
        self.assertFalse(report.signatures[0].verified)

    def test_revoked_key_is_quarantined(self):
        self.keyring.revoke(self.signing_key.key_id)
        report = self.archive.import_rule(self.keyring)
        self.assertIs(report.decision, ImportDecision.QUARANTINE)
        self.assertEqual(report.signatures[0].error, 'revoked')
        self.assertTrue(any('revoked' in reason for reason in report.reasons))

    def test_revocation_does_not_accept_reinstalled_key(self):
        self.keyring.revoke(self.signing_key.key_id)
        # 重新安装同标识公钥不能覆盖撤销状态（撤销是单向的本地信任决定）
        from rule_engine.archive.errors import RevokedKeyError
        with self.assertRaises(RevokedKeyError):
            self.keyring.add_signing_key(self.signing_key)
        report = self.archive.import_rule(self.keyring)
        self.assertIs(report.decision, ImportDecision.QUARANTINE)

    def test_remove_allows_clean_reinstall(self):
        self.keyring.revoke(self.signing_key.key_id)
        self.keyring.remove(self.signing_key.key_id)
        # 移除后重新安装是一次全新的显式信任决定
        self.keyring.add_signing_key(self.signing_key)
        self.assertIs(self.archive.import_rule(self.keyring).decision, ImportDecision.ACCEPT)

    def test_revoked_entry_stays_revoked_in_keyring(self):
        self.keyring.revoke(self.signing_key.key_id)
        self.assertTrue(self.keyring.get(self.signing_key.key_id).revoked)
        self.assertFalse(self.keyring.is_trusted(self.signing_key.key_id))

    def test_mutual_signature_information(self):
        second_key = SigningKey.generate()
        archive = RuleArchive.export(self.rule, self.signing_key)
        archive.add_signature(second_key)
        report = archive.import_rule(self.keyring)
        self.assertIs(report.decision, ImportDecision.ACCEPT)
        self.assertTrue(report.signatures[0].verified)   # installed signing key
        self.assertFalse(report.signatures[1].verified)  # second key not installed

    def test_forged_certificate_is_quarantined(self):
        anchor = SigningKey.generate()
        fresh = SigningKey.generate()
        keyring = make_keyring(anchor)
        certificate = anchor.issue_certificate(TrustedKey(fresh.key_id, fresh.public_key))
        # 把证书中的公钥替换成另一把：签名立即失效
        forged = dict(certificate)
        forged['public_key'] = SigningKey.generate().public_pem()
        archive = RuleArchive.export(self.rule, fresh, certificate=forged)
        report = archive.import_rule(keyring, allow_certified_keys=True)
        self.assertIs(report.decision, ImportDecision.QUARANTINE)

    def test_certificate_for_other_key_is_quarantined(self):
        anchor = SigningKey.generate()
        signer = SigningKey.generate()
        other = SigningKey.generate()
        keyring = make_keyring(anchor)
        # 证书背书 other，但档案由 signer 签名
        certificate = anchor.issue_certificate(TrustedKey(other.key_id, other.public_key))
        archive = RuleArchive.export(self.rule, signer, certificate=certificate)
        report = archive.import_rule(keyring, allow_certified_keys=True)
        self.assertIs(report.decision, ImportDecision.QUARANTINE)

    def test_garbage_input_is_quarantined(self):
        report = RuleArchive.from_bytes(b'{not json at all').import_rule(self.keyring)
        self.assertIs(report.decision, ImportDecision.QUARANTINE)


class ArchiveKeyRotationTests(unittest.TestCase):
    def setUp(self):
        self.old_key = SigningKey.generate()
        self.new_key = SigningKey.generate()
        self.context = Context(type_resolver={'n': DataType.FLOAT})
        self.rule = Rule('n > 1', context=self.context)

    def test_transition_period_both_keys_trusted(self):
        archive = RuleArchive.export(self.rule, self.old_key)
        keyring = make_keyring(self.old_key, self.new_key)
        self.assertIs(archive.import_rule(keyring).decision, ImportDecision.ACCEPT)
        # 旧密钥撤销后，只带旧签名的档案立即失去信任
        keyring.revoke(self.old_key.key_id)
        self.assertIs(archive.import_rule(keyring).decision, ImportDecision.QUARANTINE)

    def test_dual_signature_survives_revocation(self):
        archive = RuleArchive.export(self.rule, self.old_key)
        archive.add_signature(self.new_key)
        keyring = make_keyring(self.old_key, self.new_key)
        keyring.revoke(self.old_key.key_id)
        report = archive.import_rule(keyring)
        self.assertIs(report.decision, ImportDecision.ACCEPT)
        self.assertTrue(any(info.verified for info in report.signatures if info.key_id == self.new_key.key_id))

    def test_certificate_based_rotation(self):
        # 新密钥由当前受信锚点显式背书；导入方必须显式开启才接受
        keyring = make_keyring(self.old_key)
        certificate = self.old_key.issue_certificate(TrustedKey(self.new_key.key_id, self.new_key.public_key))
        archive = RuleArchive.export(self.rule, self.new_key, certificate=certificate)
        self.assertIs(archive.import_rule(keyring).decision, ImportDecision.QUARANTINE)
        report = archive.import_rule(keyring, allow_certified_keys=True)
        self.assertIs(report.decision, ImportDecision.ACCEPT)
        self.assertTrue(any(info.certified for info in report.signatures))

    def test_certificate_dies_with_anchor_revocation(self):
        keyring = make_keyring(self.old_key)
        certificate = self.old_key.issue_certificate(TrustedKey(self.new_key.key_id, self.new_key.public_key))
        archive = RuleArchive.export(self.rule, self.new_key, certificate=certificate)
        keyring.revoke(self.old_key.key_id)
        report = archive.import_rule(keyring, allow_certified_keys=True)
        self.assertIs(report.decision, ImportDecision.QUARANTINE)

    def test_duplicate_counter_signature_is_rejected(self):
        archive = RuleArchive.export(self.rule, self.old_key)
        with self.assertRaises(ValueError):
            archive.add_signature(self.old_key)

    def test_key_identifier_is_deterministic(self):
        self.assertEqual(SigningKey.from_pem(self.old_key.to_pem()).key_id, self.old_key.key_id)

    def test_keyring_persistence_preserves_revocation(self):
        keyring = make_keyring(self.old_key, self.new_key)
        keyring.revoke(self.old_key.key_id)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, 'keyring.json')
            keyring.save(path)
            restored = LocalKeyring.load(path)
        self.assertTrue(restored.get(self.old_key.key_id).revoked)
        self.assertFalse(restored.is_trusted(self.old_key.key_id))
        self.assertTrue(restored.is_trusted(self.new_key.key_id))
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, 'key.pem')
            self.old_key.save(path)
            mode = os.stat(path).st_mode & 0o777
            self.assertEqual(mode, 0o600)
            self.assertEqual(SigningKey.load(path).key_id, self.old_key.key_id)


class ArchiveDuplicateTests(unittest.TestCase):
    def setUp(self):
        self.signing_key = SigningKey.generate()
        self.keyring = make_keyring(self.signing_key)
        self.context = Context(type_resolver={'n': DataType.FLOAT})
        self.rule = Rule('n > 1', context=self.context)
        self.archive = RuleArchive.export(self.rule, self.signing_key)

    def test_duplicate_import_is_idempotent(self):
        registry = ImportRegistry()
        first = self.archive.import_rule(self.keyring, rule_registry=registry)
        second = self.archive.import_rule(self.keyring, rule_registry=registry)
        self.assertIs(first.decision, ImportDecision.ACCEPT)
        self.assertFalse(first.duplicate)
        self.assertIs(second.decision, ImportDecision.ACCEPT)
        self.assertTrue(second.duplicate)

    def test_same_id_different_content_is_quarantined(self):
        registry = ImportRegistry()
        self.archive.import_rule(self.keyring, rule_registry=registry)
        conflicting = RuleArchive.export(
            Rule('n > 2', context=self.context), self.signing_key,
            rule_id=self.archive.manifest['rule']['id']
        )
        report = RuleArchive.from_bytes(conflicting.to_bytes()).import_rule(self.keyring, rule_registry=registry)
        self.assertIs(report.decision, ImportDecision.QUARANTINE)
        self.assertTrue(any('already exists' in reason for reason in report.reasons))

    def test_registry_persistence(self):
        registry = ImportRegistry()
        self.archive.import_rule(self.keyring, rule_registry=registry)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, 'registry.json')
            registry.save(path)
            restored = ImportRegistry.load(path)
        report = self.archive.import_rule(self.keyring, rule_registry=restored)
        self.assertTrue(report.duplicate)

    def test_re_export_with_new_timestamp_is_still_duplicate(self):
        # 完整摘要随 created_at 变化，但语义指纹不变：重新导出同一规则必须幂等
        import time
        first_bytes = RuleArchive.export(
            self.rule, self.signing_key, created_at='2026-01-01T00:00:00Z').to_bytes()
        time.sleep(0.01)
        second_bytes = RuleArchive.export(
            self.rule, self.signing_key, created_at='2026-02-02T00:00:00Z').to_bytes()
        registry = ImportRegistry()
        first = RuleArchive.from_bytes(first_bytes).import_rule(self.keyring, rule_registry=registry)
        second = RuleArchive.from_bytes(second_bytes).import_rule(self.keyring, rule_registry=registry)
        self.assertTrue(first.accepted and second.accepted)
        self.assertTrue(second.duplicate)
        self.assertNotEqual(first.digest, second.digest)
        self.assertEqual(first.semantic_digest, second.semantic_digest)


class ArchiveCapabilityTests(unittest.TestCase):
    def setUp(self):
        self.signing_key = SigningKey.generate()
        self.keyring = make_keyring(self.signing_key)
        self.rule = Rule('n > 1', Context(type_resolver={'n': DataType.FLOAT}))

    def test_future_minimum_engine_version_is_quarantined(self):
        archive = RuleArchive.export(self.rule, self.signing_key, min_engine_version='99.0.0')
        report = RuleArchive.from_bytes(archive.to_bytes()).import_rule(self.keyring)
        self.assertIs(report.decision, ImportDecision.QUARANTINE)
        self.assertTrue(any('engine' in reason for reason in report.reasons))

    def test_newer_envelope_format_is_quarantined(self):
        envelope = json.loads(RuleArchive.export(self.rule, self.signing_key).to_bytes())
        envelope['format_version'] = FORMAT_VERSION + 1
        report = RuleArchive.from_dict(envelope).import_rule(self.keyring)
        self.assertIs(report.decision, ImportDecision.QUARANTINE)
        self.assertTrue(any('newer' in reason for reason in report.reasons))

    def test_older_signed_format_requires_migration(self):
        envelope = json.loads(RuleArchive.export(self.rule, self.signing_key).to_bytes())
        envelope['format_version'] = 0
        report = RuleArchive.from_dict(envelope).import_rule(self.keyring)
        self.assertIs(report.decision, ImportDecision.MIGRATE)
        self.assertTrue(any('migration' in reason for reason in report.reasons))

    def test_unknown_regex_flag_is_quarantined(self):
        envelope = json.loads(RuleArchive.export(self.rule, self.signing_key).to_bytes())
        envelope['manifest']['context']['regex_flags'] = ['FANCYFLAG']
        archive = resign(RuleArchive.from_dict(envelope), self.signing_key)
        report = archive.import_rule(self.keyring)
        self.assertIs(report.decision, ImportDecision.QUARANTINE)

    def test_unknown_type_kind_is_quarantined(self):
        envelope = json.loads(RuleArchive.export(self.rule, self.signing_key).to_bytes())
        envelope['manifest']['types']['n']['kind'] = 'QUANTUM'
        archive = resign(RuleArchive.from_dict(envelope), self.signing_key)
        report = archive.import_rule(self.keyring)
        self.assertIs(report.decision, ImportDecision.QUARANTINE)

    def test_missing_builtin_symbol_is_quarantined(self):
        # 清单声称表达式依赖一个本地引擎不提供的内建符号（能力边界）
        rule = Rule('$pi > 3')
        envelope = json.loads(RuleArchive.export(rule, self.signing_key).to_bytes())
        for entry in envelope['manifest']['symbols']:
            if entry['name'] == 'pi':
                entry['name'] = 'imaginary_math_constant'
        archive = resign(RuleArchive.from_dict(envelope), self.signing_key)
        report = archive.import_rule(self.keyring)
        # 符号集合首先对不上 → 隔离
        self.assertIs(report.decision, ImportDecision.QUARANTINE)


class ArchiveSemanticTests(unittest.TestCase):
    def setUp(self):
        self.signing_key = SigningKey.generate()
        self.keyring = make_keyring(self.signing_key)

    def test_declared_symbol_type_must_match_reparse(self):
        rule = Rule('n > 1', Context(type_resolver={'n': DataType.FLOAT}))
        envelope = json.loads(RuleArchive.export(rule, self.signing_key).to_bytes())
        # 手改符号声明为 STRING 后重新签名：签名有效，但语义复核必须发现漂移
        for entry in envelope['manifest']['symbols']:
            if entry['name'] == 'n':
                entry['type'] = {'kind': 'STRING'}
        archive = resign(RuleArchive.from_dict(envelope), self.signing_key)
        report = archive.import_rule(self.keyring)
        self.assertIs(report.decision, ImportDecision.QUARANTINE)
        self.assertTrue(any('re-parses to type' in reason for reason in report.reasons))

    def test_declared_type_map_must_match_reparse(self):
        rule = Rule('n > 1', Context(type_resolver={'n': DataType.FLOAT}))
        envelope = json.loads(RuleArchive.export(rule, self.signing_key).to_bytes())
        envelope['manifest']['types']['n'] = {'kind': 'STRING'}
        archive = resign(RuleArchive.from_dict(envelope), self.signing_key)
        report = archive.import_rule(self.keyring)
        self.assertIs(report.decision, ImportDecision.QUARANTINE)

    def test_expression_must_parse_under_reconstructed_context(self):
        rule = Rule('n > 1', Context(type_resolver={'n': DataType.FLOAT}))
        envelope = json.loads(RuleArchive.export(rule, self.signing_key).to_bytes())
        # 删掉类型声明但文本仍引用 n：在无类型上下文下 n 是 UNDEFINED，表达式仍可解析；
        # 改为语法错误文本则必须隔离
        envelope['manifest']['rule']['text'] = 'n >>> 1'
        archive = resign(RuleArchive.from_dict(envelope), self.signing_key)
        report = archive.import_rule(self.keyring)
        self.assertIs(report.decision, ImportDecision.QUARANTINE)
        self.assertTrue(any('parse' in reason for reason in report.reasons))

    def test_type_resolver_mode_flip_is_quarantined(self):
        # 持信方把类型解析模式从 mapping 改成 default（弱类型化）后重新签名：
        # 符号类型复核必须发现 FLOAT → UNDEFINED 的含义漂移
        rule = Rule('n > 1', Context(type_resolver={'n': DataType.FLOAT}))
        envelope = json.loads(RuleArchive.export(rule, self.signing_key).to_bytes())
        envelope['manifest']['context']['type_resolver'] = 'default'
        archive = resign(RuleArchive.from_dict(envelope), self.signing_key)
        report = archive.import_rule(self.keyring)
        self.assertIs(report.decision, ImportDecision.QUARANTINE)
        self.assertTrue(any('UNDEFINED' in reason for reason in report.reasons))

    def test_symbol_and_type_sections_must_agree(self):
        rule = Rule('n > 1', Context(type_resolver={'n': DataType.FLOAT}))
        envelope = json.loads(RuleArchive.export(rule, self.signing_key).to_bytes())
        # 只改 symbols 段的类型，types 段仍为 FLOAT：两个签名覆盖的元数据源互相漂移
        envelope['manifest']['symbols'][0]['type'] = {'kind': 'STRING'}
        archive = resign(RuleArchive.from_dict(envelope), self.signing_key)
        report = archive.import_rule(self.keyring)
        self.assertIs(report.decision, ImportDecision.QUARANTINE)


class ArchiveExtensionTests(unittest.TestCase):
    def setUp(self):
        self.signing_key = SigningKey.generate()
        self.keyring = make_keyring(self.signing_key)
        self.rule = Rule('n > 1', Context(type_resolver={'n': DataType.FLOAT}))

    def test_unknown_manifest_extension_is_quarantined(self):
        archive = RuleArchive.export(self.rule, self.signing_key, extensions={'x_future_semantics': {'mode': 42}})
        report = RuleArchive.from_bytes(archive.to_bytes()).import_rule(self.keyring)
        self.assertIs(report.decision, ImportDecision.QUARANTINE)
        self.assertTrue(any('extension' in reason for reason in report.reasons))

    def test_whitelisted_extension_is_accepted(self):
        archive = RuleArchive.export(self.rule, self.signing_key, extensions={'x_owner': 'risk-team'})
        report = RuleArchive.from_bytes(archive.to_bytes()).import_rule(
            self.keyring, known_extensions={'x_owner'})
        self.assertIs(report.decision, ImportDecision.ACCEPT)
        self.assertEqual(report.extensions, {'x_owner': 'risk-team'})

    def test_unknown_envelope_field_is_quarantined(self):
        envelope = json.loads(RuleArchive.export(self.rule, self.signing_key).to_bytes())
        envelope['x_hint'] = 'rewrite-semantics'
        report = RuleArchive.from_dict(envelope).import_rule(self.keyring)
        self.assertIs(report.decision, ImportDecision.QUARANTINE)


class ArchiveLegacyMigrationTests(unittest.TestCase):
    def setUp(self):
        self.signing_key = SigningKey.generate()
        self.keyring = make_keyring(self.signing_key)
        self.context = Context(type_resolver={'n': DataType.FLOAT})

    def test_plain_text_is_legacy_migrate(self):
        archive = RuleArchive.from_bytes(b'n > 1')
        self.assertTrue(archive.is_legacy)
        report = archive.import_rule(self.keyring)
        self.assertIs(report.decision, ImportDecision.MIGRATE)
        self.assertTrue(any('unsigned' in reason for reason in report.reasons))

    def test_legacy_json_shape_is_migrate(self):
        report = RuleArchive.from_dict({'rule': 'n > 1'}).import_rule(self.keyring)
        self.assertIs(report.decision, ImportDecision.MIGRATE)

    def test_legacy_with_context_preview(self):
        archive = RuleArchive.from_legacy('n > 1')
        report = archive.import_rule(self.keyring, migration_context=self.context)
        self.assertIs(report.decision, ImportDecision.MIGRATE)
        # 提供迁移上下文时会预解析，但绝不自动激活
        self.assertIsNone(report.rule)

    def test_legacy_that_does_not_parse_stays_migrate(self):
        archive = RuleArchive.from_legacy('n >>> 1')
        report = archive.import_rule(self.keyring, migration_context=self.context)
        self.assertIs(report.decision, ImportDecision.MIGRATE)
        self.assertTrue(any('parse' in reason for reason in report.reasons))

    def test_explicit_migration_is_reproducible(self):
        migrated = RuleArchive.migrate('n > 1', self.context, self.signing_key)
        self.assertFalse(migrated.is_legacy)
        report = RuleArchive.from_bytes(migrated.to_bytes()).import_rule(self.keyring)
        self.assertIs(report.decision, ImportDecision.ACCEPT)
        self.assertTrue(report.require_accepted().matches({'n': 2}))

    def test_migrating_signed_archive_is_rejected(self):
        archive = RuleArchive.export(Rule('n > 1', self.context), self.signing_key)
        with self.assertRaises(ArchiveFormatError):
            RuleArchive.migrate(archive, self.context, self.signing_key)

    def test_unsigned_archive_can_not_be_serialized(self):
        archive = RuleArchive.from_legacy('n > 1')
        with self.assertRaises(ArchiveFormatError):
            archive.to_bytes()


class ArchiveExportSafetyTests(unittest.TestCase):
    def setUp(self):
        self.signing_key = SigningKey.generate()

    def test_custom_type_resolver_is_not_exportable(self):
        with self.assertRaises(SchemaExportError) as context:
            RuleArchive.export(Rule('n == 1', Context(type_resolver=lambda name: DataType.UNDEFINED)), self.signing_key)
        self.assertEqual(context.exception.capability, 'type_resolver')

    def test_custom_runtime_resolver_is_not_exportable(self):
        with self.assertRaises(SchemaExportError) as context:
            RuleArchive.export(Rule('n == 1', Context(resolver=lambda thing, name: None)), self.signing_key)
        self.assertEqual(context.exception.capability, 'resolver')

    def test_non_null_default_value_is_not_exportable(self):
        with self.assertRaises(SchemaExportError) as context:
            RuleArchive.export(Rule('n == 1', Context(default_value=42)), self.signing_key)
        self.assertEqual(context.exception.capability, 'default_value')

    def test_arbitrary_timezone_is_not_exportable(self):
        tzinfo = datetime.timezone(datetime.timedelta(hours=9))
        with self.assertRaises(SchemaExportError) as context:
            RuleArchive.export(Rule('n == 1', Context(default_timezone=tzinfo)), self.signing_key)
        self.assertEqual(context.exception.capability, 'default_timezone')

    def test_archive_contains_no_business_values(self):
        context = Context(type_resolver={'secret': DataType.STRING})
        rule = Rule('secret == "placeholder"', context=context)
        rule.matches({'secret': 'TOP-SECRET-BUSINESS-VALUE'})
        archive = RuleArchive.export(rule, self.signing_key)
        serialized = archive.to_bytes().decode('utf-8')
        self.assertNotIn('TOP-SECRET-BUSINESS-VALUE', serialized)
        # 档案只有声明性内容：没有运行期对象，类型仅以名称/结构出现
        self.assertIn('STRING', serialized)
        self.assertIn('"types"', serialized)


if __name__ == '__main__':
    unittest.main()
