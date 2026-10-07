#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  rule_engine/archive/_types.py
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

"""规则类型定义（DataType）与上下文选项的可移植 JSON 编解码。

这里只承载**声明性元数据**：类型结构、正则选项、时区与 decimal 边界等。
任何运行期 Python 对象（dataclass 实例、SQLAlchemy 映射类、自定义 accessor、
自定义 resolver 可调用对象、业务数据）都不会、也不能进入档案。
"""

from __future__ import annotations

import datetime
import decimal
import functools
import re
from typing import Any

import dateutil.tz

from .. import errors
from ..types import DataType
from ..types.definitions import (
    _CollectionDataTypeDef,
    _DATA_TYPE_UNDEFINED,
    _DataTypeDef,
    _FunctionDataTypeDef,
    _MappingDataTypeDef,
    _NullableDataTypeDef,
    _ReferenceDataTypeDef,
)
from ..types._object import _ObjectDataTypeDef

from .errors import ArchiveFormatError, SchemaExportError

# 可移植的正则位掩码名称（数值不进入档案，避免跨平台位值差异）。
_REGEX_FLAG_NAMES = ('ASCII', 'IGNORECASE', 'LOCALE', 'MULTILINE', 'DOTALL', 'UNICODE', 'VERBOSE')

# 可移植的解析期 resolver 名称。
RESOLVER_ITEM = 'item'
RESOLVER_ATTRIBUTE = 'attribute'

# 可移植的类型 resolver 名称。
TYPE_RESOLVER_DEFAULT = 'default'
TYPE_RESOLVER_MAPPING = 'mapping'

# default_value 的可移植标记。
_DEFAULT_VALUE_UNDEFINED = 'UNDEFINED'

def encode_regex_flags(flags: int) -> list[str]:
    """把 re 模块的位掩码选项转换为有序名称列表。"""
    names: list[str] = []
    for name in _REGEX_FLAG_NAMES:
        value = getattr(re, name, 0)
        if value and flags & value:
            names.append(name)
    unknown = flags & ~sum(getattr(re, name, 0) for name in _REGEX_FLAG_NAMES)
    if unknown:
        raise SchemaExportError('can not export unknown regex flag bits: 0x{:x}'.format(unknown), capability='regex_flags')
    return names

def decode_regex_flags(names: Any) -> int:
    """把名称列表还原为 re 位掩码；遇到未知名称抛出能力边界错误。"""
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        raise ArchiveFormatError('regex_flags must be a list of flag names')
    flags = 0
    for name in names:
        if name not in _REGEX_FLAG_NAMES or not hasattr(re, name):
            raise ArchiveFormatError('unknown regex flag: ' + name, capability='regex_flags')
        flags |= getattr(re, name)
    return flags

def encode_timezone(tzinfo: datetime.tzinfo) -> str:
    """把上下文默认时区编码为可移植名称（仅 local / utc）。"""
    if isinstance(tzinfo, dateutil.tz.tzutc):
        return 'utc'
    if isinstance(tzinfo, dateutil.tz.tzlocal):
        return 'local'
    raise SchemaExportError(
        "can not portably export default_timezone {0!r}; only 'local' and 'utc' are portable".format(tzinfo),
        capability='default_timezone'
    )

def decode_timezone(value: Any) -> datetime.tzinfo:
    """还原上下文默认时区。"""
    if value == 'utc':
        return dateutil.tz.tzutc()
    if value == 'local':
        return dateutil.tz.tzlocal()
    raise ArchiveFormatError('unsupported portable timezone: ' + repr(value), capability='default_timezone')

def encode_default_value(value: Any) -> Any:
    """default_value 只允许 UNDEFINED 哨兵与 null；其它值可能是业务数据，拒绝导出。"""
    if value is errors.UNDEFINED:
        return _DEFAULT_VALUE_UNDEFINED
    if value is None:
        return None
    raise SchemaExportError(
        'can not portably export a non-null default_value (business data must not enter an archive)',
        capability='default_value'
    )

def decode_default_value(value: Any) -> Any:
    if value == _DEFAULT_VALUE_UNDEFINED:
        return errors.UNDEFINED
    if value is None:
        return None
    raise ArchiveFormatError('invalid default_value marker: ' + repr(value), capability='default_value')

_ROUNDING_NAMES = {
    decimal.ROUND_CEILING: 'ROUND_CEILING',
    decimal.ROUND_DOWN: 'ROUND_DOWN',
    decimal.ROUND_FLOOR: 'ROUND_FLOOR',
    decimal.ROUND_HALF_DOWN: 'ROUND_HALF_DOWN',
    decimal.ROUND_HALF_EVEN: 'ROUND_HALF_EVEN',
    decimal.ROUND_HALF_UP: 'ROUND_HALF_UP',
    decimal.ROUND_UP: 'ROUND_UP',
    decimal.ROUND_05UP: 'ROUND_05UP',
}
_DECIMAL_TRAP_NAMES = {
    decimal.Clamped: 'Clamped',
    decimal.InvalidOperation: 'InvalidOperation',
    decimal.DivisionByZero: 'DivisionByZero',
    decimal.Inexact: 'Inexact',
    decimal.Rounded: 'Rounded',
    decimal.Subnormal: 'Subnormal',
    decimal.Overflow: 'Overflow',
    decimal.Underflow: 'Underflow',
    decimal.FloatOperation: 'FloatOperation',
}

def encode_decimal_context(context: decimal.Context) -> dict[str, Any]:
    """编码影响规则求值含义的 decimal 上下文（flags 是运行期状态，不导出）。"""
    traps = [name for cls, name in _DECIMAL_TRAP_NAMES.items() if context.traps.get(cls)]
    return {
        'prec': context.prec,
        'rounding': _ROUNDING_NAMES[context.rounding],
        'emin': context.Emin,
        'emax': context.Emax,
        'capitals': context.capitals,
        'clamp': context.clamp,
        'traps': sorted(traps),
    }

def decode_decimal_context(payload: Any) -> decimal.Context:
    if not isinstance(payload, dict):
        raise ArchiveFormatError('decimal_context must be an object', capability='decimal_context')
    try:
        rounding = getattr(decimal, payload['rounding'])
    except (KeyError, AttributeError):
        raise ArchiveFormatError('unknown rounding mode: ' + repr(payload.get('rounding')), capability='decimal_context') from None
    if rounding not in _ROUNDING_NAMES:
        raise ArchiveFormatError('unknown rounding mode: ' + repr(payload['rounding']), capability='decimal_context')
    trap_classes = []
    for name in payload.get('traps', []):
        for cls, cls_name in _DECIMAL_TRAP_NAMES.items():
            if cls_name == name:
                trap_classes.append(cls)
                break
        else:
            raise ArchiveFormatError('unknown decimal trap: ' + name, capability='decimal_context')
    try:
        return decimal.Context(
            prec=payload['prec'],
            rounding=rounding,
            Emin=payload['emin'],
            Emax=payload['emax'],
            capitals=payload['capitals'],
            clamp=payload['clamp'],
            traps=trap_classes
        )
    except KeyError as error:
        raise ArchiveFormatError('decimal_context is missing field: ' + error.args[0], capability='decimal_context') from None

def encode_type_definition(definition: _DataTypeDef, _stack: set[int] | None = None) -> dict[str, Any]:
    """把一个 DataType 定义递归编码为自描述的 JSON 结构。

    OBJECT 只保留名称与属性模式（不含 python_type / accessor / 业务类）；
    递归与自引用通过 REF(name) 表达，解码时在本地注册表中还原。
    *_stack* 记录当前祖先链上的对象 id 以打断自引用循环。
    """
    if _stack is None:
        _stack = set()
    if definition is _DATA_TYPE_UNDEFINED:
        return {'kind': 'UNDEFINED'}
    if DataType.is_type(definition, DataType.OBJECT):
        assert isinstance(definition, _ObjectDataTypeDef)
        if id(definition) in _stack:
            # 自引用（如 Person.friends: ARRAY(Person)）：输出名称引用
            return {'kind': 'REF', 'name': definition.name}
        _stack.add(id(definition))
        try:
            attributes = {
                name: encode_type_definition(attr_type, _stack)
                for name, attr_type in sorted(definition.attributes.items())
            }
        finally:
            _stack.discard(id(definition))
        return {
            'kind': 'OBJECT',
            'name': definition.name,
            'attributes': attributes,
        }
    if isinstance(definition, _NullableDataTypeDef):
        return {'kind': 'NULLABLE', 'inner_type': encode_type_definition(definition.inner_type, _stack)}
    if isinstance(definition, _MappingDataTypeDef):
        return {
            'kind': 'MAPPING',
            'key_type': encode_type_definition(definition.key_type, _stack),
            'value_type': encode_type_definition(definition.value_type, _stack),
        }
    if isinstance(definition, _CollectionDataTypeDef):
        # ARRAY / SET 用各自的类型名区分（SET 不允许 OBJECT 成员的约束在解码重建时自然生效）
        return {'kind': definition.name, 'value_type': encode_type_definition(definition.value_type, _stack)}
    if isinstance(definition, _ReferenceDataTypeDef):
        return {'kind': 'REF', 'name': definition.name}
    if DataType.is_type(definition, DataType.FUNCTION):
        assert isinstance(definition, _FunctionDataTypeDef)
        if definition.argument_types is _DATA_TYPE_UNDEFINED:
            argument_types: list[dict[str, Any]] | None = None
        else:
            assert isinstance(definition.argument_types, tuple)
            argument_types = [encode_type_definition(arg, _stack) for arg in definition.argument_types]
        minimum_arguments = None if definition.minimum_arguments is _DATA_TYPE_UNDEFINED else definition.minimum_arguments
        return {
            'kind': 'FUNCTION',
            'value_name': definition.value_name,
            'return_type': encode_type_definition(definition.return_type, _stack),
            'argument_types': argument_types,
            'minimum_arguments': minimum_arguments,
        }
    # 标量类型：名称即定义（STRING / FLOAT / BOOLEAN / ...）
    if definition.name in DataType and getattr(DataType, definition.name) is definition:
        return {'kind': definition.name}
    raise SchemaExportError('can not export data type definition: ' + repr(definition))

def decode_type_definition(payload: Any, registry: dict[str, _ObjectDataTypeDef]) -> _DataTypeDef:
    """把 JSON 结构还原为 DataType 定义，过程中把命名 OBJECT 登记进 *registry*。"""
    if not isinstance(payload, dict) or not isinstance(payload.get('kind'), str):
        raise ArchiveFormatError('invalid type definition: ' + repr(payload))
    kind = payload['kind']
    if kind == 'UNDEFINED':
        return DataType.UNDEFINED
    if kind == 'OBJECT':
        name = payload.get('name')
        if not isinstance(name, str):
            raise ArchiveFormatError('OBJECT type is missing its name')
        if name in registry:
            # 自引用/循环：返回注册表中的同一个定义（其属性稍后补齐，语义一致）
            return registry[name]
        raw_attributes = payload.get('attributes')
        if not isinstance(raw_attributes, dict):
            raise ArchiveFormatError('OBJECT {0!r} is missing its attributes map'.format(name))
        obj = _ObjectDataTypeDef(name)
        registry[name] = obj
        attributes: dict[str, _DataTypeDef] = {}
        for attr_name, attr_payload in sorted(raw_attributes.items()):
            if not isinstance(attr_name, str):
                raise ArchiveFormatError('OBJECT {0!r} has a non-string attribute name'.format(name))
            attributes[attr_name] = decode_type_definition(attr_payload, registry)
        obj.attributes = attributes
        # 重新跑一次自引用替换，使 REF(__self__)/同名引用归一
        for attr_name, attr_type in tuple(obj.attributes.items()):
            obj.attributes[attr_name] = _substitute_local_references(attr_type, obj)
        return obj
    if kind == 'NULLABLE':
        return DataType.NULLABLE(decode_type_definition(payload.get('inner_type'), registry))
    if kind == 'MAPPING':
        return DataType.MAPPING(
            decode_type_definition(payload.get('key_type'), registry),
            decode_type_definition(payload.get('value_type'), registry)
        )
    if kind in ('ARRAY', 'SET'):
        constructor = getattr(DataType, kind)
        return constructor(decode_type_definition(payload.get('value_type'), registry))
    if kind == 'REF':
        name = payload.get('name')
        if not isinstance(name, str):
            raise ArchiveFormatError('REF type is missing its name')
        return _ReferenceDataTypeDef(name)
    if kind == 'FUNCTION':
        args = payload.get('argument_types')
        if args is None:
            argument_types: tuple[_DataTypeDef, ...] | _DataTypeDef = DataType.UNDEFINED
        elif isinstance(args, list):
            argument_types = tuple(decode_type_definition(arg, registry) for arg in args)
        else:
            raise ArchiveFormatError('FUNCTION argument_types must be a list or null')
        minimum_arguments = payload.get('minimum_arguments')
        if minimum_arguments is None:
            minimum_arguments = DataType.UNDEFINED
        elif not isinstance(minimum_arguments, int) or isinstance(minimum_arguments, bool):
            raise ArchiveFormatError('FUNCTION minimum_arguments must be an integer or null')
        return _FunctionDataTypeDef(
            'FUNCTION',
            _PYTHON_FUNCTION_TYPE,
            value_name=payload.get('value_name'),
            return_type=decode_type_definition(payload.get('return_type'), registry),
            argument_types=argument_types,
            minimum_arguments=minimum_arguments
        )
    try:
        # 标量类型按名称解析
        return DataType.from_name(kind)
    except ValueError:
        raise ArchiveFormatError('unknown data type kind: ' + kind, capability='type:' + kind) from None

def _substitute_local_references(definition: _DataTypeDef, target: _ObjectDataTypeDef) -> _DataTypeDef:
    """解码后把指向封闭对象自身的 REF 归一为 OBJECT 实例（与解析器构造方式一致）。"""
    if isinstance(definition, _ReferenceDataTypeDef):
        if definition.name == target.name:
            return target
        return definition
    if isinstance(definition, _NullableDataTypeDef):
        inner = _substitute_local_references(definition.inner_type, target)
        if inner is definition.inner_type:
            return definition
        return _NullableDataTypeDef('NULLABLE', object, inner_type=inner)
    if isinstance(definition, _MappingDataTypeDef):
        key_type = _substitute_local_references(definition.key_type, target)
        value_type = _substitute_local_references(definition.value_type, target)
        if key_type is definition.key_type and value_type is definition.value_type:
            return definition
        return _MappingDataTypeDef('MAPPING', dict, key_type, value_type)
    if isinstance(definition, _CollectionDataTypeDef):
        value_type = _substitute_local_references(definition.value_type, target)
        if value_type is definition.value_type:
            return definition
        return definition.__class__(definition.name, definition.python_type, value_type=value_type)
    if DataType.is_type(definition, DataType.OBJECT):
        # 嵌套对象已在注册表中独立存在，保持不变
        return definition
    return definition

_PYTHON_FUNCTION_TYPE = type(lambda: None)

def extract_context_type_map(context: Any) -> dict[str, _DataTypeDef] | None:
    """从 dict/dataclass/sqlalchemy 构造的 type_resolver（functools.partial）中抽取类型表。

    这些构造器最终都把 {符号名: 类型定义} 放进 partial 的关键字参数；
    引擎默认 resolver 不声明任何外部符号，导出为空表；任意其它自定义可调用
    resolver 无法静态导出，返回 None 交由上层拒绝。
    """
    from ..engine.context import _default_type_resolver
    resolver = getattr(context, '_Context__type_resolver', None)
    if resolver is _default_type_resolver:
        return {}
    if isinstance(resolver, functools.partial):
        type_map = resolver.keywords.get('type_map')
        if type_map is None and resolver.args:
            type_map = resolver.args[0]
        if isinstance(type_map, dict):
            return dict(type_map)
    return None

def encode_resolver(context: Any) -> str:
    """识别上下文的运行期 item/attribute resolver；自定义可调用对象不可移植。"""
    from ..engine.context import resolve_attribute, resolve_item
    resolver = getattr(context, '_Context__resolver', None)
    if resolver is resolve_item:
        return RESOLVER_ITEM
    if resolver is resolve_attribute:
        return RESOLVER_ATTRIBUTE
    raise SchemaExportError(
        'can not portably export a custom resolver callable; use resolve_item or resolve_attribute',
        capability='resolver'
    )

def make_resolver(name: Any) -> Any:
    from ..engine.context import resolve_attribute, resolve_item
    if name == RESOLVER_ITEM:
        return resolve_item
    if name == RESOLVER_ATTRIBUTE:
        return resolve_attribute
    raise ArchiveFormatError('unknown resolver: ' + repr(name), capability='resolver')

def type_resolver_mode(context: Any) -> str:
    """识别上下文的类型解析模式：default（未知符号→UNDEFINED）或 mapping（声明表）。"""
    from ..engine.context import _default_type_resolver
    resolver = getattr(context, '_Context__type_resolver', None)
    if resolver is _default_type_resolver:
        return TYPE_RESOLVER_DEFAULT
    if isinstance(resolver, functools.partial):
        return TYPE_RESOLVER_MAPPING
    raise SchemaExportError(
        'can not portably export a custom type_resolver callable; use a mapping / dataclass / sqlalchemy resolver',
        capability='type_resolver'
    )

def make_type_resolver(mode: Any, type_map: dict[str, _DataTypeDef]) -> Any:
    """重建类型 resolver；default 模式返回 None 以使用引擎默认（未知符号→UNDEFINED）。"""
    if mode == TYPE_RESOLVER_DEFAULT:
        return None
    if mode == TYPE_RESOLVER_MAPPING:
        return type_map
    raise ArchiveFormatError('unknown type_resolver mode: ' + repr(mode), capability='type_resolver')
