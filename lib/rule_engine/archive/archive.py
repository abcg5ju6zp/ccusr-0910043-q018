#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  rule_engine/archive/archive.py
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

"""可移植、签名的规则档案：导出、验证与导入决策。

决策只有三种：

* :data:`ImportDecision.ACCEPT` —— 签名通过本地信任密钥环验证、能力边界满足、
  语义复核一致、且无重复冲突，规则可以激活；
* :data:`ImportDecision.QUARANTINE` —— 档案被隔离保存但绝不激活：签名无法验证、
  密钥已撤销、结构损坏、引用未知扩展、能力超出本地边界或与既有规则冲突；
* :data:`ImportDecision.MIGRATE` —— 签名时代之前的旧纯文本格式，来源完整性
  无法证明，必须调用方显式提供解析选项并重新签名后才能成为受信规则。

重复导入相同内容是幂等的（ACCEPT 且标记 duplicate）；内容不同但 id 相同则隔离。
"""

from __future__ import annotations

import base64
import dataclasses
import enum
import json
from typing import Any, TYPE_CHECKING

from .. import __version__ as ENGINE_VERSION
from .. import errors
from ..types import DataType
from ..types.definitions import _DataTypeDef
from ..types._object import _ObjectDataTypeDef

from . import _types
from .errors import (
    ArchiveFormatError,
    ArchiveIntegrityError,
    RevokedKeyError,
    SchemaExportError,
    UnknownKeyError,
    UnsupportedCapabilityError,
    UnverifiedArchiveError,
)
from .keys import SIGNATURE_ALGORITHM, LocalKeyring, SigningKey
from .manifest import (
    ARCHIVE_FORMAT,
    FORMAT_VERSION,
    build_manifest,
    canonical_encode,
    collect_symbol_references,
    iter_ast_nodes,
    manifest_digest,
    parse_version,
    semantic_fingerprint,
    validate_envelope_shape,
    validate_manifest_shape,
)

if TYPE_CHECKING:
    from ..engine.context import Context
    from ..engine.rule import Rule

class ImportDecision(enum.Enum):
    """导入决策。"""
    ACCEPT = 'accept'
    QUARANTINE = 'quarantine'
    MIGRATE = 'migrate'

@dataclasses.dataclass
class SignatureInfo:
    """单个签名的验证结果。"""
    key_id: str
    verified: bool
    certified: bool = False
    error: str | None = None

@dataclasses.dataclass
class ImportReport:
    """一次导入尝试的完整结论。无论什么决策都不会抛出签名/格式异常。"""
    decision: ImportDecision
    reasons: list[str] = dataclasses.field(default_factory=list)
    rule: 'Rule | None' = None
    rule_id: str | None = None
    digest: str | None = None
    semantic_digest: str | None = None
    signatures: list[SignatureInfo] = dataclasses.field(default_factory=list)
    duplicate: bool = False
    manifest: dict[str, Any] | None = None
    extensions: dict[str, Any] = dataclasses.field(default_factory=dict)

    @property
    def accepted(self) -> bool:
        return self.decision is ImportDecision.ACCEPT

    def require_accepted(self) -> 'Rule':
        """激活规则的唯一入口：非 ACCEPT 时抛出异常，杜绝调用方忽略隔离结论。"""
        if self.decision is not ImportDecision.ACCEPT:
            raise UnverifiedArchiveError(
                'rule archive was not accepted (decision={0}): {1}'.format(self.decision.value, '; '.join(self.reasons))
            )
        assert self.rule is not None
        return self.rule

class RuleArchive:
    """一个已签名的规则档案信封。"""
    def __init__(
            self,
            envelope: dict[str, Any],
            *,
            legacy_text: str | None = None,
            load_error: str | None = None
    ) -> None:
        self.envelope = envelope
        self._legacy_text = legacy_text
        self._load_error = load_error

    # ---------------------------------------------------------------- 导出
    @classmethod
    def export(
            cls,
            rule: 'Rule',
            signing_key: SigningKey,
            *,
            rule_id: str | None = None,
            min_engine_version: str | None = None,
            extensions: dict[str, Any] | None = None,
            certificate: dict[str, Any] | None = None,
            created_at: str | None = None
    ) -> 'RuleArchive':
        """把已解析规则导出为签名档案。

        导出过程只读取表达式文本、上下文选项与类型声明；任何业务对象、
        自定义可调用对象都会触发 :exc:`SchemaExportError`，不会进入档案。
        """
        manifest = build_manifest(
            rule,
            rule_id=rule_id,
            min_engine_version=min_engine_version,
            extensions=extensions,
            created_at=created_at
        )
        payload = canonical_encode(manifest)
        signature_entry: dict[str, Any] = {
            'algorithm': SIGNATURE_ALGORITHM,
            'key_id': signing_key.key_id,
            'signature': base64.b64encode(signing_key.sign(payload)).decode('ascii'),
        }
        if certificate is not None:
            signature_entry['certificate'] = certificate
        envelope = {
            'archive_format': ARCHIVE_FORMAT,
            'format_version': FORMAT_VERSION,
            'manifest': manifest,
            'signatures': [signature_entry],
        }
        return cls(envelope)

    @classmethod
    def from_legacy(cls, source: str | bytes | dict[str, Any]) -> 'RuleArchive':
        """接纳签名时代之前的旧格式（纯表达式文本或 {'rule': text} JSON）。

        旧档案没有任何完整性证明，导入决策只能是 MIGRATE。
        """
        if isinstance(source, (bytes, bytearray)):
            source = bytes(source).decode('utf-8')
        if isinstance(source, str):
            text = source.strip()
        elif isinstance(source, dict):
            if set(source) <= {'rule', 'text'} and isinstance(source.get('rule', source.get('text')), str):
                text = source['rule'] if 'rule' in source else source['text']
            else:
                raise ArchiveFormatError('unrecognized legacy archive shape')
        else:
            raise ArchiveFormatError('unrecognized legacy archive type: ' + type(source).__name__)
        return cls({}, legacy_text=text)

    @classmethod
    def migrate(
            cls,
            legacy: 'str | bytes | dict[str, Any] | RuleArchive',
            context: 'Context',
            signing_key: SigningKey,
            *,
            rule_id: str | None = None,
            min_engine_version: str | None = None,
            extensions: dict[str, Any] | None = None
    ) -> 'RuleArchive':
        """显式迁移：在调用方提供的上下文下重解析旧文本，然后用本地密钥重新签名。

        解析选项由调用方显式承担——迁移后的档案与正常导出的档案走同一条
        验证流水线，旧格式本身永远不会被直接激活。
        """
        from ..engine.rule import Rule
        archive = legacy if isinstance(legacy, RuleArchive) else cls.from_legacy(legacy)
        if not archive.is_legacy:
            raise ArchiveFormatError('archive is already signed; migration only applies to legacy formats')
        rule = Rule(archive._legacy_text or '', context=context)
        return cls.export(
            rule,
            signing_key,
            rule_id=rule_id,
            min_engine_version=min_engine_version,
            extensions=extensions
        )

    # ------------------------------------------------------------ 序列化
    def to_dict(self) -> dict[str, Any]:
        if self._legacy_text is not None:
            raise ArchiveFormatError('legacy archives are unsigned; migrate and re-export before serializing')
        return json.loads(self.to_json())

    def to_json(self, *, indent: int | None = 2) -> str:
        if self._legacy_text is not None:
            raise ArchiveFormatError('legacy archives are unsigned; migrate and re-export before serializing')
        return json.dumps(self.envelope, indent=indent, sort_keys=True, ensure_ascii=False)

    def to_bytes(self) -> bytes:
        return self.to_json().encode('utf-8')

    def save(self, path: str) -> None:
        with open(path, 'wb') as file_obj:
            file_obj.write(self.to_bytes())

    @classmethod
    def from_bytes(cls, data: bytes | str) -> 'RuleArchive':
        """从字节加载档案。

        无法解析的内容不抛出异常，而是返回一个 :meth:`import_rule` 必然
        给出 QUARANTINE 结论的档案（损坏输入不能破坏导入流水线）。
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        try:
            text = data.decode('utf-8')
        except UnicodeDecodeError as error:
            return cls({}, load_error='archive is not valid UTF-8: ' + str(error))
        stripped = text.strip()
        if not stripped.startswith('{'):
            # 非 JSON：旧的纯表达式文本
            try:
                return cls.from_legacy(stripped)
            except ArchiveFormatError as error:
                return cls({}, load_error=error.message)
        try:
            envelope = json.loads(text)
        except json.JSONDecodeError as error:
            return cls({}, load_error='archive is not valid JSON: ' + str(error))
        return cls.from_dict(envelope)

    @classmethod
    def from_dict(cls, envelope: Any) -> 'RuleArchive':
        if not isinstance(envelope, dict):
            # 来自 from_bytes 的不可信输入不应抛出；但直接调用方传入错误类型属于 API 误用
            return cls({}, load_error='archive envelope must be a JSON object, got ' + type(envelope).__name__)
        # 旧的无签名 JSON 形状
        if envelope.get('archive_format') != ARCHIVE_FORMAT and set(envelope) <= {'rule', 'text'}:
            try:
                return cls.from_legacy(envelope)
            except ArchiveFormatError as error:
                return cls({}, load_error=error.message)
        return cls(envelope)

    @classmethod
    def load(cls, path: str) -> 'RuleArchive':
        with open(path, 'rb') as file_obj:
            return cls.from_bytes(file_obj.read())

    # -------------------------------------------------------------- 检视
    @property
    def is_legacy(self) -> bool:
        return self._legacy_text is not None

    @property
    def manifest(self) -> dict[str, Any]:
        if self._legacy_text is not None:
            raise ArchiveFormatError('legacy archive has no manifest')
        return self.envelope['manifest']

    @property
    def digest(self) -> str:
        return manifest_digest(self.manifest)

    def add_signature(self, signing_key: SigningKey, *, certificate: dict[str, Any] | None = None) -> None:
        """追加一把密钥的签名（密钥轮换过渡期，同一档案可由多把密钥共同背书）。"""
        if self._legacy_text is not None:
            raise ArchiveFormatError('legacy archives can not be counter-signed; migrate first')
        payload = canonical_encode(self.envelope['manifest'])
        entry: dict[str, Any] = {
            'algorithm': SIGNATURE_ALGORITHM,
            'key_id': signing_key.key_id,
            'signature': base64.b64encode(signing_key.sign(payload)).decode('ascii'),
        }
        if certificate is not None:
            entry['certificate'] = certificate
        for existing in self.envelope['signatures']:
            if existing['key_id'] == entry['key_id']:
                raise ValueError('a signature for this key is already present: ' + signing_key.key_id)
        self.envelope['signatures'].append(entry)

    # -------------------------------------------------------------- 验证
    def verify_signatures(self, keyring: LocalKeyring, *, allow_certified_keys: bool = False) -> list[SignatureInfo]:
        """逐个验证签名，返回全部结果（不抛异常）。至少一条受信未撤销签名通过才算可信。"""
        results: list[SignatureInfo] = []
        payload = canonical_encode(self.envelope['manifest'])
        for entry in self.envelope['signatures']:
            key_id = str(entry.get('key_id', ''))
            info = SignatureInfo(key_id=key_id, verified=False)
            try:
                signature = base64.b64decode(entry.get('signature', ''), validate=True)
            except (ValueError, TypeError):
                info.error = 'malformed signature'
                results.append(info)
                continue
            try:
                keyring.verify(payload, signature, key_id)
            except RevokedKeyError:
                info.error = 'revoked'
            except ArchiveIntegrityError as error:
                info.error = error.message
            except Exception as error:  # UnknownKeyError 等
                verified_by_certificate = False
                if allow_certified_keys and isinstance(entry.get('certificate'), dict) and isinstance(error, UnknownKeyError):
                    verified_by_certificate = self._verify_with_certificate(keyring, payload, signature, entry['certificate'], info)
                if not verified_by_certificate:
                    info.error = getattr(error, 'message', str(error))
                else:
                    info.verified = True
                    info.certified = True
            else:
                info.verified = True
            results.append(info)
        return results

    def _verify_with_certificate(
            self,
            keyring: LocalKeyring,
            payload: bytes,
            signature: bytes,
            certificate: dict[str, Any],
            info: SignatureInfo
    ) -> bool:
        if certificate.get('certified_key_id') != info.key_id:
            info.error = 'certificate is for a different key'
            return False
        try:
            certified = keyring.verify_certificate(certificate)
            certified.public_key.verify(signature, payload)
        except (ArchiveIntegrityError, RevokedKeyError, ArchiveFormatError, UnknownKeyError) as error:
            info.error = getattr(error, 'message', str(error))
            return False
        return True

    # -------------------------------------------------------------- 导入
    def import_rule(
            self,
            keyring: LocalKeyring,
            *,
            allow_certified_keys: bool = False,
            migration_context: 'Context | None' = None,
            rule_registry: 'ImportRegistry | None' = None,
            known_extensions: 'frozenset[str] | set[str] | None' = None
    ) -> ImportReport:
        """执行完整的导入流水线并返回三选一决策（不抛签名/格式类异常）。

        *known_extensions* 是调用方明确理解其语义的扩展键白名单；清单中出现
        任何其它扩展都会导致隔离——新扩展绝不允许在未确认的情况下改变规则含义。
        """
        if self._legacy_text is not None:
            return self._import_legacy(migration_context, rule_registry)

        if self._load_error is not None:
            return ImportReport(
                decision=ImportDecision.QUARANTINE,
                reasons=['envelope: ' + self._load_error]
            )

        manifest = self.envelope.get('manifest')
        report = ImportReport(decision=ImportDecision.QUARANTINE, manifest=manifest if isinstance(manifest, dict) else None)
        try:
            rule_id = manifest['rule']['id'] if isinstance(manifest, dict) else None
        except (KeyError, TypeError):
            rule_id = None
        report.rule_id = rule_id

        # 1) 最小信封标记与格式版本路由（先于完整形状校验，避免旧格式因结构差异
        #    被笼统隔离——旧格式必须进入显式 MIGRATE 流程）
        envelope = self.envelope
        if not isinstance(envelope, dict) or envelope.get('archive_format') != ARCHIVE_FORMAT:
            return self._quarantine(report, 'envelope: not a rule engine archive envelope')
        version = envelope.get('format_version')
        if not isinstance(version, int) or isinstance(version, bool):
            return self._quarantine(report, 'envelope: format_version must be an integer')
        if version > FORMAT_VERSION:
            report.reasons.append('archive format_version {} is newer than supported {}'.format(version, FORMAT_VERSION))
            return report
        if version < FORMAT_VERSION:
            # 更早的签名格式：不猜测其含义，走显式迁移
            report.decision = ImportDecision.MIGRATE
            report.reasons.append('older signed format_version {} requires explicit migration'.format(version))
            return report

        # 当前版本：完整信封形状校验
        try:
            validate_envelope_shape(envelope)
        except ArchiveFormatError as error:
            return self._quarantine(report, 'envelope: ' + error.message)

        assert isinstance(manifest, dict)

        # 2) 信任验证
        report.signatures = self.verify_signatures(keyring, allow_certified_keys=allow_certified_keys)
        if not any(info.verified and info.error != 'revoked' for info in report.signatures):
            report.reasons.append('no signature from a trusted, non-revoked key')
            if any(info.error == 'revoked' for info in report.signatures):
                report.reasons.append('at least one signing key has been revoked')
            return report

        # 3) 清单结构
        try:
            validate_manifest_shape(manifest)
        except ArchiveFormatError as error:
            report.reasons.append('manifest: ' + error.message)
            return report
        report.digest = manifest_digest(manifest)
        report.semantic_digest = semantic_fingerprint(manifest)
        report.extensions = dict(manifest.get('extensions', {}))

        # 未知扩展：默认全部不认识 → 隔离。调用方必须显式声明自己理解某个扩展键，
        # 该扩展才不会阻止接受（扩展内容仍在签名覆盖范围内，不可被事后篡改）。
        allowed = set(known_extensions or ())
        unknown_extensions = sorted(set(report.extensions) - allowed)
        if unknown_extensions:
            report.reasons.append('unknown manifest extensions: ' + ', '.join(unknown_extensions))
            return report

        # 4) 引擎能力边界
        try:
            self._check_engine_capabilities(manifest)
        except UnsupportedCapabilityError as error:
            report.reasons.append('capability: ' + error.message)
            return report

        # 5) 重建上下文并重解析（语义复核）
        try:
            context = reconstruct_context(manifest)
            rule = _reparse(manifest['rule']['text'], context)
        except ArchiveFormatError as error:
            report.reasons.append('reconstruction: ' + error.message)
            return report
        except errors.EngineError as error:
            report.reasons.append('rule does not parse under the reconstructed context: ' + getattr(error, 'message', str(error)))
            return report

        try:
            semantic_reasons = self._verify_semantics(manifest, rule, context)
        except ArchiveFormatError as error:
            report.reasons.append('semantics: ' + error.message)
            return report
        if semantic_reasons:
            report.reasons.extend(semantic_reasons)
            return report

        # 6) 重复导入（按规则语义指纹判断；重新导出同内容档案是幂等的）
        if rule_registry is not None:
            existing = rule_registry.get_digest(manifest['rule']['id'])
            if existing is not None:
                if existing == report.semantic_digest:
                    report.decision = ImportDecision.ACCEPT
                    report.rule = rule
                    report.duplicate = True
                    return report
                report.reasons.append('rule id {0!r} already exists with different semantics'.format(manifest['rule']['id']))
                return report
            rule_registry.remember(manifest['rule']['id'], report.semantic_digest)

        report.decision = ImportDecision.ACCEPT
        report.rule = rule
        return report

    @staticmethod
    def _quarantine(report: ImportReport, reason: str) -> ImportReport:
        report.decision = ImportDecision.QUARANTINE
        report.reasons.append(reason)
        return report

    def _import_legacy(self, migration_context: 'Context | None', rule_registry: 'ImportRegistry | None') -> ImportReport:
        text = self._legacy_text or ''
        report = ImportReport(decision=ImportDecision.MIGRATE)
        report.reasons.append('unsigned legacy rule text; integrity and parse options can not be proven')
        if migration_context is not None:
            # 只做预检：证明文本在调用方显式承担的解析选项下可用。
            # 报告绝不携带可激活的规则——必须经 RuleArchive.migrate 重新签名后再导入。
            try:
                _reparse(text, migration_context)
            except errors.EngineError as error:
                report.reasons.append('rule does not parse under the supplied migration context: ' + getattr(error, 'message', str(error)))
                return report
            report.reasons.append('rule parses under the supplied migration context; re-sign via RuleArchive.migrate')
        else:
            report.reasons.append('supply a migration_context to pre-check, then re-export under a trusted key')
        return report

    @staticmethod
    def _check_engine_capabilities(manifest: dict[str, Any]) -> None:
        local = parse_version(ENGINE_VERSION)
        minimum = parse_version(manifest['engine'].get('min_version', '0.0.0'))
        target = parse_version(manifest['engine']['version'])
        if local < minimum:
            raise UnsupportedCapabilityError(
                'archive requires engine >= {0} but local engine is {1}'.format(
                    '.'.join(str(part) for part in minimum), ENGINE_VERSION),
                capability='engine_version'
            )
        if target[0] > local[0]:
            raise UnsupportedCapabilityError(
                'archive was produced by an incompatible newer engine major version: {0} > {1}'.format(
                    manifest['engine']['version'], ENGINE_VERSION),
                capability='engine_version'
            )

    @staticmethod
    def _verify_semantics(manifest: dict[str, Any], rule: 'Rule', context: 'Context') -> list[str]:
        """用重建后的上下文重解析表达式，比对符号集合、符号类型与选项指纹。"""
        reasons: list[str] = []
        declared_symbols = {(entry['scope'], entry['name']): entry for entry in manifest['symbols']}
        actual_refs = collect_symbol_references(rule.statement)
        if {(scope, name) for scope, name in actual_refs} != set(declared_symbols):
            missing = {(scope, name) for scope, name in actual_refs} - set(declared_symbols)
            extra = set(declared_symbols) - {(scope, name) for scope, name in actual_refs}
            if missing:
                reasons.append('manifest is missing symbol references: ' + ', '.join(sorted(name for _, name in missing)))
            if extra:
                reasons.append('manifest declares symbols the expression does not reference: ' + ', '.join(sorted(name for _, name in extra)))
            return reasons

        # 重建一次类型注册表（与 reconstruct_context 相同的输入），用于 symbols/types 段交叉校验
        type_registry: dict[str, _ObjectDataTypeDef] = {}
        decoded_type_map = {
            name: _types.decode_type_definition(payload, type_registry)
            for name, payload in manifest['types'].items()
        }

        for entry in manifest['symbols']:
            scope, name = entry['scope'], entry['name']
            declared_type = _types.decode_type_definition(entry['type'], {})
            actual_type = _symbol_result_type(rule, entry['scope'], entry['name'])
            # 严格结构相等：UNDEFINED 不再与任意类型兼容，防止通过弱类型声明改变规则含义
            if not _types_equal(declared_type, actual_type):
                reasons.append(
                    'symbol {0!r} re-parses to type {1!r} but the archive declares {2!r}'.format(
                        name, _type_display(actual_type), _type_display(declared_type))
                )
            if scope == '' and manifest['context'].get('type_resolver') == _types.TYPE_RESOLVER_MAPPING:
                # symbols 段与 types 段必须相互一致（两个签名覆盖的元数据源不能互相漂移）。
                # default 模式下外部符号本就无声明（类型为 UNDEFINED），无 types 段可比对。
                root_type = decoded_type_map.get(name)
                if root_type is None:
                    reasons.append('symbol {0!r} is not declared in the archive types section'.format(name))
                elif not _types_equal(root_type, declared_type):
                    reasons.append(
                        'symbol {0!r} type disagrees with the types section ({1!r} != {2!r})'.format(
                            name, _type_display(declared_type), _type_display(root_type))
                    )

        # 内建符号必须是本地引擎真正提供的能力，且签名严格一致（引擎能力边界）
        for scope, name in actual_refs:
            if scope == 'built-in':
                local_builtin_type = context.builtins.resolve_type(name)
                if local_builtin_type == DataType.UNDEFINED:
                    reasons.append('archive references built-in symbol {0!r} this engine does not provide'.format(name))
                else:
                    declared_type = _types.decode_type_definition(declared_symbols[(scope, name)]['type'], {})
                    if not _types_equal(local_builtin_type, declared_type):
                        reasons.append('built-in symbol {0!r} has an incompatible local signature'.format(name))
        return reasons

def _symbol_result_type(rule: 'Rule', scope: str, name: str) -> _DataTypeDef:
    from ..ast.expression.resolution import SymbolExpression
    for node in iter_ast_nodes(rule.statement):
        if isinstance(node, SymbolExpression) and (node.scope or '') == scope and node.name == name:
            return node.result_type
    return DataType.UNDEFINED

def _types_equal(a: _DataTypeDef, b: _DataTypeDef) -> bool:
    """严格结构相等：比较规范 JSON 编码。

    不使用 :meth:`DataType.is_compatible`——它把 UNDEFINED 当作通配类型，
    弱声明会借此悄悄放过被改动的符号类型。
    """
    return canonical_encode(_types.encode_type_definition(a)) == canonical_encode(_types.encode_type_definition(b))

def _type_display(definition: _DataTypeDef) -> str:
    return getattr(definition, 'name', repr(definition))

def _reparse(text: str, context: 'Context') -> 'Rule':
    from ..engine.rule import Rule
    return Rule(text, context=context)

def reconstruct_context(manifest: dict[str, Any]) -> 'Context':
    """根据清单重建等价的解析 :class:`~rule_engine.Context`（不含任何业务对象）。"""
    from ..engine.context import Context
    context_section = manifest['context']

    registry: dict[str, _ObjectDataTypeDef] = {}
    type_map: dict[str, _DataTypeDef] = {}
    # 两遍：先登记全部命名 OBJECT，再重建根类型，使前向引用可解析
    for name, payload in manifest['types'].items():
        decoded = _types.decode_type_definition(payload, registry)
        if isinstance(decoded, _ObjectDataTypeDef):
            registry[decoded.name] = decoded
        type_map[name] = decoded

    context = Context(
        regex_flags=_types.decode_regex_flags(context_section['regex_flags']),
        default_timezone=_types.decode_timezone(context_section['default_timezone']),
        default_value=_types.decode_default_value(context_section['default_value']),
        decimal_context=_types.decode_decimal_context(context_section['decimal_context']),
        mapping_attribute_lookup=context_section['mapping_attribute_lookup'],
        resolver=_types.make_resolver(context_section['resolver']),
        type_resolver=_types.make_type_resolver(context_section.get('type_resolver', _types.TYPE_RESOLVER_DEFAULT), type_map),
    )
    return context

class ImportRegistry:
    """记录已接受规则的内容摘要，用于重复导入检测（可持久化为 JSON）。"""
    def __init__(self, entries: dict[str, str] | None = None) -> None:
        self._entries = dict(entries or {})

    def get_digest(self, rule_id: str) -> str | None:
        return self._entries.get(rule_id)

    def remember(self, rule_id: str, digest: str) -> None:
        self._entries[rule_id] = digest

    def to_dict(self) -> dict[str, Any]:
        return dict(self._entries)

    @classmethod
    def from_dict(cls, payload: Any) -> 'ImportRegistry':
        if not isinstance(payload, dict) or not all(isinstance(key, str) and isinstance(value, str) for key, value in payload.items()):
            raise ArchiveFormatError('invalid import registry')
        return cls(payload)

    def save(self, path: str) -> None:
        with open(path, 'w', encoding='utf-8') as file_obj:
            json.dump(self.to_dict(), file_obj, indent=2, sort_keys=True)

    @classmethod
    def load(cls, path: str) -> 'ImportRegistry':
        with open(path, 'r', encoding='utf-8') as file_obj:
            return cls.from_dict(json.load(file_obj))
