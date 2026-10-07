#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  rule_engine/archive/format.py
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

from __future__ import annotations

import decimal
import re
from typing import TYPE_CHECKING, Any, Callable

import dateutil.tz

from .. import __version__ as _engine_version
from .. import errors
from ..engine.context import Context

from .canonical import content_digest, is_json_safe

if TYPE_CHECKING:
    from ..engine.rule import Rule

FORMAT_MARKER = 'rule-engine/archive'
"""档案信封的格式标识。"""

CURRENT_FORMAT_VERSION = 1
"""当前实现能够读写的档案格式版本。"""

GRAMMAR_VERSION = 'rule-engine/v5'
"""表达式文本所遵循的语法版本。"""

ENGINE_NAME = 'rule-engine'

#: 允许的上下文选项键。导入时遇到未知键一律视为能力越界，绝不静默忽略。
CONTEXT_OPTION_KEYS = frozenset((
        'regex_flags',
        'default_timezone',
        'mapping_attribute_lookup',
        'default_value',
        'decimal_context',
))

#: 允许出现在档案中的正则标志位（保持为普通 int，避免 IntFlag 的有界取反语义）。
_ALLOWED_REGEX_FLAGS = int(
        re.ASCII | re.DEBUG | re.IGNORECASE | re.LOCALE | re.MULTILINE | re.DOTALL | re.UNICODE | re.VERBOSE | re.TEMPLATE
)

#: 已注册的格式迁移器：MIGRATIONS[from_version](payload) -> 升级一级的 payload。
#: 迁移必须是确定性的，且不得改变规则的求值语义。
MIGRATIONS: dict[int, Callable[[dict[str, Any]], dict[str, Any]]] = {}

#: 已知的扩展及其校验器。未知的关键扩展导致隔离；未知的非关键扩展被剥离并记录，
#: 保证扩展永远不会静默改变规则含义。
KNOWN_EXTENSIONS: dict[str, Callable[[Any], None]] = {}

def register_migration(from_version: int, migrator: Callable[[dict[str, Any]], dict[str, Any]]) -> None:
    """注册从 *from_version* 到 *from_version + 1* 的确定性迁移器。"""
    if from_version < 0 or from_version >= CURRENT_FORMAT_VERSION:
        raise errors.ArchiveError('invalid migration source version: {0}'.format(from_version))
    MIGRATIONS[from_version] = migrator

def register_extension(name: str, validator: Callable[[Any], None]) -> None:
    """注册已知扩展及其数据校验器。校验器在校验失败时抛出异常。"""
    KNOWN_EXTENSIONS[name] = validator

def _version_tuple(text: str) -> tuple[int, ...]:
    parts = text.split('.')
    if not parts or not all(part.isdigit() for part in parts):
        raise ValueError('invalid version: {0!r}'.format(text))
    return tuple(int(part) for part in parts)

def version_satisfies(version: str, minimum: str, maximum: str) -> bool:
    """检查 *version* 是否落在 [minimum, maximum) 区间内（按版本元组比较，短者补零）。"""
    def _pad(parts: tuple[int, ...], length: int) -> tuple[int, ...]:
        return parts + (0,) * (length - len(parts))
    try:
        version_t, minimum_t, maximum_t = _version_tuple(version), _version_tuple(minimum), _version_tuple(maximum)
    except ValueError:
        return False
    length = max(len(version_t), len(minimum_t), len(maximum_t))
    version_t, minimum_t, maximum_t = (_pad(parts, length) for parts in (version_t, minimum_t, maximum_t))
    return minimum_t <= version_t < maximum_t

def compatible_version_range() -> dict[str, str]:
    """当前引擎写出的兼容版本区间：[当前主次版本, 下一主版本)。"""
    major, minor = _version_tuple(_engine_version)[:2]
    return {'min_version': '{0}.{1}'.format(major, minor), 'max_version': '{0}.0'.format(major + 1)}

def serialize_context_options(context: Context) -> dict[str, Any]:
    """
    把 :py:class:`~rule_engine.engine.Context` 的可移植选项序列化为规范化数据。
    仅白名单内的选项会被导出；不可移植的配置（自定义 tzinfo、不可 JSON 化的
    default_value）导致 :py:exc:`~rule_engine.errors.ArchiveExportError`。
    可调用对象（resolver / type_resolver）永不导出——它们属于环境代码而非规则数据。
    """
    timezone = context.default_timezone
    if isinstance(timezone, dateutil.tz.tzutc):
        timezone_name = 'utc'
    elif isinstance(timezone, dateutil.tz.tzlocal):
        timezone_name = 'local'
    else:
        raise errors.ArchiveExportError(
                'default_timezone {0!r} is not portable; only utc and local are supported'.format(timezone)
        )
    default_value = context.default_value
    if default_value is errors.UNDEFINED:
        default_value_data: dict[str, Any] = {'kind': 'undefined'}
    elif is_json_safe(default_value):
        default_value_data = {'kind': 'literal', 'value': default_value}
    else:
        raise errors.ArchiveExportError(
                'default_value of type {0} is not a portable JSON value'.format(type(default_value).__name__)
        )
    decimal_context = context.decimal_context
    return {
            'regex_flags': int(context.regex_flags),
            'default_timezone': timezone_name,
            'mapping_attribute_lookup': bool(context.mapping_attribute_lookup),
            'default_value': default_value_data,
            'decimal_context': {
                    'prec': decimal_context.prec,
                    'rounding': decimal_context.rounding,
                    'emin': decimal_context.Emin,
                    'emax': decimal_context.Emax,
                    'capitals': decimal_context.capitals,
                    'clamp': decimal_context.clamp,
            },
    }

def context_options_to_kwargs(options: dict[str, Any]) -> dict[str, Any]:
    """把序列化的上下文选项还原为 :py:class:`Context` 的关键字参数。"""
    default_value_data = options['default_value']
    if default_value_data['kind'] == 'undefined':
        default_value: Any = errors.UNDEFINED
    else:
        default_value = default_value_data['value']
    decimal_data = options['decimal_context']
    decimal_context = decimal.Context(
            prec=int(decimal_data['prec']),
            rounding=str(decimal_data['rounding']),
            Emin=int(decimal_data['emin']),
            Emax=int(decimal_data['emax']),
            capitals=int(decimal_data['capitals']),
            clamp=int(decimal_data['clamp']),
    )
    return {
            'regex_flags': int(options['regex_flags']),
            'default_timezone': str(options['default_timezone']),
            'mapping_attribute_lookup': bool(options['mapping_attribute_lookup']),
            'default_value': default_value,
            'decimal_context': decimal_context,
    }

def split_symbol_manifest(context: Context) -> dict[str, list[str]]:
    """把上下文中记录的符号集合拆分为内置符号与外部符号两份有序清单。"""
    builtins = sorted(name for name in context.symbols if name in context.builtins)
    external = sorted(name for name in context.symbols if name not in context.builtins)
    return {'builtins': builtins, 'external': external}

def build_payload(rule: 'Rule', extensions: dict[str, Any] | None = None) -> dict[str, Any]:
    """从一条已解析的规则构建档案负载。负载中只包含规则数据，不包含业务对象。"""
    extension_data: dict[str, Any] = {}
    for name, extension in (extensions or {}).items():
        if not isinstance(name, str) or not name:
            raise errors.ArchiveExportError('extension names must be non-empty strings')
        critical = bool(extension.get('critical', False))
        data = extension.get('data')
        if not is_json_safe(data):
            raise errors.ArchiveExportError('extension {0!r} data is not a portable JSON value'.format(name))
        extension_data[name] = {'critical': critical, 'data': data}
    return {
            'engine': dict(compatible_version_range(), name=ENGINE_NAME, exported_by=_engine_version),
            'expression': {'grammar': GRAMMAR_VERSION, 'text': rule.text},
            'context_options': serialize_context_options(rule.context),
            'symbols': split_symbol_manifest(rule.context),
            'extensions': extension_data,
    }

def validate_payload(payload: Any) -> list[str]:
    """
    对档案负载做结构与取值校验，返回问题列表（空列表表示通过）。
    该函数只检查负载自身的一致性，不依赖密钥或外部环境状态。
    """
    problems: list[str] = []
    if not isinstance(payload, dict):
        return ['payload is not an object']

    engine = payload.get('engine')
    if not isinstance(engine, dict):
        problems.append('engine section is missing or not an object')
    else:
        if engine.get('name') != ENGINE_NAME:
            problems.append('engine name {0!r} is not supported'.format(engine.get('name')))
        for key in ('min_version', 'max_version'):
            value = engine.get(key)
            if not isinstance(value, str):
                problems.append('engine.{0} is missing or not a string'.format(key))
            else:
                try:
                    _version_tuple(value)
                except ValueError:
                    problems.append('engine.{0} {1!r} is not a valid version'.format(key, value))

    expression = payload.get('expression')
    if not isinstance(expression, dict):
        problems.append('expression section is missing or not an object')
    else:
        if expression.get('grammar') != GRAMMAR_VERSION:
            problems.append('expression grammar {0!r} is not supported'.format(expression.get('grammar')))
        if not isinstance(expression.get('text'), str):
            problems.append('expression.text is missing or not a string')

    options = payload.get('context_options')
    if not isinstance(options, dict):
        problems.append('context_options section is missing or not an object')
    else:
        unknown = sorted(set(options) - CONTEXT_OPTION_KEYS)
        if unknown:
            problems.append('unknown context option(s): {0}'.format(', '.join(unknown)))
        missing = sorted(CONTEXT_OPTION_KEYS - set(options))
        if missing:
            problems.append('missing context option(s): {0}'.format(', '.join(missing)))
        if not unknown and not missing:
            problems.extend(_validate_context_options(options))

    symbols = payload.get('symbols')
    if not isinstance(symbols, dict):
        problems.append('symbols section is missing or not an object')
    else:
        for key in ('builtins', 'external'):
            entries = symbols.get(key)
            if not isinstance(entries, list) or not all(isinstance(entry, str) for entry in entries):
                problems.append('symbols.{0} is missing or not a list of strings'.format(key))
            elif entries != sorted(entries):
                problems.append('symbols.{0} is not in canonical (sorted) order'.format(key))

    extensions = payload.get('extensions')
    if not isinstance(extensions, dict):
        problems.append('extensions section is missing or not an object')
    else:
        for name, extension in extensions.items():
            if not isinstance(extension, dict) or not isinstance(extension.get('critical'), bool):
                problems.append('extension {0!r} is malformed'.format(name))
            elif not is_json_safe(extension.get('data')):
                problems.append('extension {0!r} data is not a portable JSON value'.format(name))
    return problems

def _validate_context_options(options: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    regex_flags = options['regex_flags']
    if not isinstance(regex_flags, int) or isinstance(regex_flags, bool) or regex_flags < 0:
        problems.append('context_options.regex_flags must be a non-negative integer')
    elif regex_flags & ~_ALLOWED_REGEX_FLAGS:
        problems.append('context_options.regex_flags contains unsupported flag bits: 0x{0:x}'.format(regex_flags & ~_ALLOWED_REGEX_FLAGS))
    if options['default_timezone'] not in ('utc', 'local'):
        problems.append('context_options.default_timezone must be "utc" or "local"')
    if not isinstance(options['mapping_attribute_lookup'], bool):
        problems.append('context_options.mapping_attribute_lookup must be a boolean')
    default_value = options['default_value']
    if not isinstance(default_value, dict) or default_value.get('kind') not in ('undefined', 'literal'):
        problems.append('context_options.default_value must declare kind "undefined" or "literal"')
    elif default_value['kind'] == 'literal' and not is_json_safe(default_value.get('value')):
        problems.append('context_options.default_value literal is not a portable JSON value')
    decimal_data = options['decimal_context']
    if not isinstance(decimal_data, dict):
        problems.append('context_options.decimal_context is not an object')
    else:
        try:
            context_options_to_kwargs(options)
        except (TypeError, ValueError, KeyError, decimal.InvalidOperation) as error:
            problems.append('context_options are not reconstructable: {0}'.format(error))
    return problems

def migrate_payload(payload: dict[str, Any], from_version: int) -> dict[str, Any]:
    """
    沿迁移器链把 *from_version* 的负载逐级迁移到当前格式版本。
    缺少迁移器时抛出 :py:exc:`~rule_engine.errors.ArchiveImportError`，由导入方转为隔离。
    """
    version = from_version
    while version < CURRENT_FORMAT_VERSION:
        migrator = MIGRATIONS.get(version)
        if migrator is None:
            raise errors.ArchiveImportError(
                    'no migration is registered from format version {0} to {1}'.format(version, version + 1)
            )
        payload = migrator(payload)
        if not isinstance(payload, dict):
            raise errors.ArchiveImportError('migration from version {0} did not produce an object'.format(version))
        version += 1
    return payload

def build_envelope(payload: dict[str, Any], signature: dict[str, str], format_version: int = CURRENT_FORMAT_VERSION) -> dict[str, Any]:
    """把负载、内容摘要与签名组装为档案信封。"""
    return {
            'format': FORMAT_MARKER,
            'format_version': format_version,
            'header': {
                    'archive_id': content_digest(payload),
                    'signature': signature,
            },
            'payload': payload,
    }
