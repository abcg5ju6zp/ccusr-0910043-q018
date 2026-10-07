#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  rule_engine/archive/manifest.py
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

"""规则档案的规范清单（manifest）。

清单是签名覆盖的全部内容：规则文本、解析上下文选项、外部符号清单及其
类型声明、类型注册表以及兼容引擎版本。它是**自描述且纯数据**的——不携带
任何 Python 可调用对象，也不携带任何业务数据。
"""

from __future__ import annotations

import datetime
import hashlib
import json
from typing import Any, Iterator

from .. import __version__ as ENGINE_VERSION
from ..ast.base import ExpressionBase, Statement
from ..ast.expression.resolution import SymbolExpression
from ..types import DataType
from ..types.definitions import _DataTypeDef

from . import _types
from .errors import ArchiveFormatError, SchemaExportError

ARCHIVE_FORMAT = 'rule-engine-archive'
MANIFEST_VERSION = 1
FORMAT_VERSION = 1

# 信封与清单中允许出现的全部字段；其余字段一律视为未知扩展。
KNOWN_ENVELOPE_FIELDS = frozenset((
    'archive_format', 'format_version', 'manifest', 'signatures'
))
KNOWN_SIGNATURE_FIELDS = frozenset(('algorithm', 'key_id', 'signature', 'certificate'))
KNOWN_MANIFEST_FIELDS = frozenset((
    'manifest_version', 'created_at', 'rule', 'context', 'symbols', 'types', 'engine', 'extensions'
))
KNOWN_RULE_FIELDS = frozenset(('id', 'text'))
KNOWN_CONTEXT_FIELDS = frozenset((
    'regex_flags', 'default_timezone', 'default_value', 'decimal_context',
    'mapping_attribute_lookup', 'resolver', 'type_resolver'
))
KNOWN_ENGINE_FIELDS = frozenset(('version', 'min_version'))

def canonical_encode(payload: Any) -> bytes:
    """确定性 JSON 编码：排序键、无多余空白、UTF-8。签名与摘要都基于它。"""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
        allow_nan=False
    ).encode('utf-8')

def manifest_digest(manifest: dict[str, Any]) -> str:
    """完整签名材料的摘要（审计用；含时间戳，每次导出唯一）。"""
    return hashlib.sha256(canonical_encode(manifest)).hexdigest()

# 决定规则含义的清单字段；created_at（审计元数据）被刻意排除。
_SEMANTIC_SECTIONS = ('rule', 'context', 'symbols', 'types', 'engine', 'extensions')

def semantic_fingerprint(manifest: dict[str, Any]) -> str:
    """规则语义指纹：只覆盖影响规则含义的部分。

    同一条规则重新导出（时间戳不同）得到相同语义指纹，重复导入保持幂等；
    任何对表达式、解析选项、符号清单、类型声明或扩展的改动都会改变它。
    """
    content = {section: manifest.get(section) for section in _SEMANTIC_SECTIONS}
    return hashlib.sha256(canonical_encode(content)).hexdigest()

################################################################################
# AST 符号遍历
################################################################################
def iter_ast_nodes(node: Any) -> Iterator[Any]:
    """深度优先遍历 AST 节点。

    同时覆盖 ``__slots__``（大多数节点）与实例 ``__dict__``（未声明 slots 的
    二元/控制节点，其 left/right 等属性存在这里）；始终跳过 context 反向引用。
    兼容 tuple/list/set/dict 容器。
    """
    if isinstance(node, (ExpressionBase, Statement)):
        yield node
        seen: set[str] = set()
        for cls in type(node).__mro__:
            for slot in getattr(cls, '__slots__', ()):
                if slot == 'context' or slot in seen:
                    continue
                seen.add(slot)
                try:
                    value = getattr(node, slot)
                except AttributeError:
                    continue
                yield from iter_ast_nodes(value)
        for name, value in vars(node).items():
            if name == 'context' or name in seen:
                continue
            seen.add(name)
            yield from iter_ast_nodes(value)
    elif isinstance(node, (tuple, list, set, frozenset)):
        for item in node:
            yield from iter_ast_nodes(item)
    elif isinstance(node, dict):
        for item in node.values():
            yield from iter_ast_nodes(item)

def collect_symbol_references(statement: Statement) -> set[tuple[str, str]]:
    """收集 (scope, name)；内建符号 scope 为 'built-in'，外部数据符号为 ''。"""
    references: set[tuple[str, str]] = set()
    for node in iter_ast_nodes(statement):
        if isinstance(node, SymbolExpression):
            references.add((node.scope or '', node.name))
    return references

def collect_symbol_types(statement: Statement) -> dict[tuple[str, str], _DataTypeDef]:
    """收集每个符号引用的解析期类型（同一符号多次引用时类型必须一致）。"""
    result: dict[tuple[str, str], _DataTypeDef] = {}
    for node in iter_ast_nodes(statement):
        if isinstance(node, SymbolExpression):
            key = (node.scope or '', node.name)
            result.setdefault(key, node.result_type)
    return result

################################################################################
# 导出：Rule -> manifest
################################################################################
def build_manifest(
        rule: Any,
        *,
        rule_id: str | None = None,
        min_engine_version: str | None = None,
        extensions: dict[str, Any] | None = None,
        created_at: str | None = None
) -> dict[str, Any]:
    """从已解析的 :class:`~rule_engine.Rule` 构造可移植清单。

    :raises SchemaExportError: 规则依赖无法可移植表达的运行期对象
        （自定义 resolver、非 null 默认值、任意时区等）——业务对象永远不会
        被静默写入档案。
    """
    context = rule.context
    type_map = _types.extract_context_type_map(context)
    if type_map is None:
        raise SchemaExportError(
            "the rule's type_resolver is not a portable mapping; build the Context from a dict, "
            "dataclass or sqlalchemy resolver so the symbol schema can be exported",
            capability='type_resolver'
        )
    type_resolver_mode = _types.type_resolver_mode(context)

    encoded_types: dict[str, Any] = {}
    for name, definition in sorted(type_map.items()):
        if not isinstance(name, str):
            raise SchemaExportError('type resolver keys must be strings', capability='type_resolver')
        encoded_types[name] = _types.encode_type_definition(definition)

    symbol_entries: list[dict[str, Any]] = []
    symbol_types = collect_symbol_types(rule.statement)
    for scope, name in sorted(collect_symbol_references(rule.statement)):
        declared = symbol_types[(scope, name)]
        symbol_entries.append({
            'scope': scope,
            'name': name,
            'type': _types.encode_type_definition(declared),
        })

    rule_section: dict[str, Any] = {
        'text': rule.text,
    }
    content_basis = canonical_encode({
        'text': rule.text,
        'context_fingerprint': _context_fingerprint(context, type_map),
    })
    rule_section['id'] = rule_id or hashlib.sha256(content_basis).hexdigest()

    manifest: dict[str, Any] = {
        'manifest_version': MANIFEST_VERSION,
        'created_at': created_at or now_iso(),
        'rule': rule_section,
        'context': {
            'regex_flags': _types.encode_regex_flags(context.regex_flags),
            'default_timezone': _types.encode_timezone(context.default_timezone),
            'default_value': _types.encode_default_value(context.default_value),
            'decimal_context': _types.encode_decimal_context(context.decimal_context),
            'mapping_attribute_lookup': bool(context.mapping_attribute_lookup),
            'resolver': _types.encode_resolver(context),
            'type_resolver': type_resolver_mode,
        },
        'symbols': symbol_entries,
        'types': encoded_types,
        'engine': {
            'version': ENGINE_VERSION,
            'min_version': min_engine_version or _default_min_version(ENGINE_VERSION),
        },
    }
    if extensions:
        manifest['extensions'] = canonical_encode_json(extensions)
    return manifest

def canonical_encode_json(payload: Any) -> Any:
    """扩展必须能确定性编码（用于重复导入的内容寻址）。"""
    # 往返一次，拒绝 set/datetime/NaN 等不可移植内容
    return json.loads(canonical_encode(payload).decode('utf-8'))

def _context_fingerprint(context: Any, type_map: dict[str, _DataTypeDef]) -> Any:
    return {
        'regex_flags': _types.encode_regex_flags(context.regex_flags),
        'default_timezone': _types.encode_timezone(context.default_timezone),
        'default_value': _types.encode_default_value(context.default_value),
        'decimal_context': _types.encode_decimal_context(context.decimal_context),
        'mapping_attribute_lookup': bool(context.mapping_attribute_lookup),
        'resolver': _types.encode_resolver(context),
        'types': {name: _types.encode_type_definition(dt) for name, dt in sorted(type_map.items())},
    }

def _default_min_version(version: str) -> str:
    parts = version.split('.')
    if len(parts) < 2:
        return version
    return '.'.join((parts[0], parts[1], '0'))

def parse_version(version: str) -> tuple[int, int, int]:
    parts = version.split('.')
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        raise ArchiveFormatError('invalid engine version: ' + repr(version))
    return tuple(int(part) for part in parts)  # type: ignore[return-value]

################################################################################
# 导入侧：结构校验
################################################################################
def validate_manifest_shape(manifest: Any) -> None:
    """严格校验清单形状；任何多余字段都按未知扩展处理（在调用方决策）。"""
    if not isinstance(manifest, dict):
        raise ArchiveFormatError('manifest must be an object')
    extra = set(manifest) - KNOWN_MANIFEST_FIELDS
    if extra:
        raise ArchiveFormatError('unknown manifest fields: ' + ', '.join(sorted(extra)))
    if manifest.get('manifest_version') != MANIFEST_VERSION:
        raise ArchiveFormatError('unsupported manifest version', format_version=manifest.get('manifest_version'))
    if not isinstance(manifest.get('created_at'), str):
        raise ArchiveFormatError('manifest created_at must be a string')
    rule = manifest.get('rule')
    if not isinstance(rule, dict) or set(rule) - KNOWN_RULE_FIELDS or not isinstance(rule.get('text'), str) or not isinstance(rule.get('id'), str):
        raise ArchiveFormatError('invalid rule section')
    context = manifest.get('context')
    if not isinstance(context, dict) or set(context) ^ KNOWN_CONTEXT_FIELDS:
        raise ArchiveFormatError('invalid context section')
    if not isinstance(context.get('mapping_attribute_lookup'), bool):
        raise ArchiveFormatError('mapping_attribute_lookup must be a boolean')
    if context.get('default_timezone') not in ('local', 'utc'):
        raise ArchiveFormatError('unsupported default_timezone', capability='default_timezone')
    if context.get('resolver') not in (_types.RESOLVER_ITEM, _types.RESOLVER_ATTRIBUTE):
        raise ArchiveFormatError('unsupported resolver: ' + repr(context.get('resolver')), capability='resolver')
    if context.get('type_resolver') not in (_types.TYPE_RESOLVER_DEFAULT, _types.TYPE_RESOLVER_MAPPING):
        raise ArchiveFormatError('unsupported type_resolver mode', capability='type_resolver')
    symbols = manifest.get('symbols')
    if not isinstance(symbols, list):
        raise ArchiveFormatError('symbols must be a list')
    for entry in symbols:
        if not isinstance(entry, dict) or set(entry) != {'scope', 'name', 'type'}:
            raise ArchiveFormatError('invalid symbol entry')
        if not isinstance(entry['scope'], str) or not isinstance(entry['name'], str):
            raise ArchiveFormatError('invalid symbol entry')
        if entry['scope'] not in ('', 'built-in'):
            raise ArchiveFormatError('unsupported symbol scope: ' + repr(entry['scope']))
        if not isinstance(entry['type'], dict):
            raise ArchiveFormatError('symbol entry type must be an object')
    types = manifest.get('types')
    if not isinstance(types, dict) or not all(isinstance(key, str) for key in types):
        raise ArchiveFormatError('types must be an object keyed by symbol name')
    engine = manifest.get('engine')
    if not isinstance(engine, dict) or set(engine) - KNOWN_ENGINE_FIELDS:
        raise ArchiveFormatError('invalid engine section')
    if 'version' not in engine:
        raise ArchiveFormatError('engine section is missing its version')
    parse_version(engine['version'])
    parse_version(engine.get('min_version', '0.0.0'))
    extensions = manifest.get('extensions', {})
    if not isinstance(extensions, dict):
        raise ArchiveFormatError('extensions must be an object')

def validate_envelope_shape(envelope: Any) -> None:
    if not isinstance(envelope, dict):
        raise ArchiveFormatError('archive envelope must be an object')
    if set(envelope) - KNOWN_ENVELOPE_FIELDS:
        raise ArchiveFormatError('unknown envelope fields: ' + ', '.join(sorted(set(envelope) - KNOWN_ENVELOPE_FIELDS)))
    if envelope.get('archive_format') != ARCHIVE_FORMAT:
        raise ArchiveFormatError('not a rule engine archive: ' + repr(envelope.get('archive_format')), archive_format=envelope.get('archive_format'))
    if not isinstance(envelope.get('format_version'), int) or isinstance(envelope.get('format_version'), bool):
        raise ArchiveFormatError('format_version must be an integer')
    if not isinstance(envelope.get('manifest'), dict):
        raise ArchiveFormatError('manifest must be an object')
    signatures = envelope.get('signatures')
    if not isinstance(signatures, list) or not signatures:
        raise ArchiveFormatError('archive must carry at least one signature')
    for signature in signatures:
        if not isinstance(signature, dict) or set(signature) - KNOWN_SIGNATURE_FIELDS:
            raise ArchiveFormatError('invalid signature entry')
        if signature.get('algorithm') != 'ed25519':
            raise ArchiveFormatError('unsupported signature algorithm: ' + repr(signature.get('algorithm')))
        if not isinstance(signature.get('key_id'), str) or not isinstance(signature.get('signature'), str):
            raise ArchiveFormatError('signature entry is missing key_id or signature')
        if 'certificate' in signature and not isinstance(signature.get('certificate'), dict):
            raise ArchiveFormatError('signature certificate must be an object')

def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
