#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  rule_engine/archive/importer.py
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

import base64
import dataclasses
import datetime
import enum
import re
from typing import Any

from .. import __version__ as _engine_version
from .. import errors
from ..engine.context import Context
from ..engine.rule import Rule

from .canonical import canonical_dumps, canonical_loads, content_digest
from .format import (
    CURRENT_FORMAT_VERSION,
    FORMAT_MARKER,
    KNOWN_EXTENSIONS,
    context_options_to_kwargs,
    migrate_payload,
    split_symbol_manifest,
    validate_payload,
    version_satisfies,
)
from .keys import KeyRing

_ARCHIVE_ID_PATTERN = re.compile(r'^sha256:[0-9a-f]{64}$')

class ImportDecision(enum.Enum):
    """导入裁决结果。"""
    ACCEPT = 'accept'
    """完整性与能力边界全部通过，可以物化为规则。"""
    QUARANTINE = 'quarantine'
    """任一验证环节失败，档案被隔离，绝不物化。"""
    MIGRATE = 'migrate'
    """旧格式档案，签名验证通过后经确定性迁移升级，再按当前格式完整验证。"""

@dataclasses.dataclass(frozen=True)
class ImportReport(object):
    """一次导入尝试的完整裁决记录。"""
    decision: ImportDecision
    archive_id: str | None = None
    """所接收档案的内容摘要标识。"""
    reasons: tuple[str, ...] = ()
    """导致隔离或迁移的全部原因，按发现顺序排列。"""
    duplicate: bool = False
    """该档案此前已被导入过，本次为幂等重放，未产生任何状态变化。"""
    migrated_from: int | None = None
    """若发生迁移，记录原始格式版本。"""
    migrated_archive_id: str | None = None
    """迁移后负载的内容摘要标识。"""
    ignored_extensions: tuple[str, ...] = ()
    """被剥离的未知非关键扩展；它们不参与物化，因而不可能改变规则含义。"""
    key_id: str | None = None
    """验证签名所用的密钥标识。"""
    format_version: int | None = None
    _payload: dict[str, Any] | None = dataclasses.field(default=None, repr=False, compare=False)

    @property
    def accepted(self) -> bool:
        """档案是否通过验证（ACCEPT 或 MIGRATE）。"""
        return self.decision in (ImportDecision.ACCEPT, ImportDecision.MIGRATE)

    def materialize(self) -> Rule:
        """
        把通过验证的档案物化为可求值的 :py:class:`~rule_engine.engine.Rule`。
        被隔离的档案调用此方法会抛出 :py:exc:`~rule_engine.errors.ArchiveImportError`。
        """
        if not self.accepted or self._payload is None:
            raise errors.ArchiveImportError(
                    'a quarantined archive cannot be materialized (reasons: {0})'.format('; '.join(self.reasons) or 'none')
            )
        options = context_options_to_kwargs(self._payload['context_options'])
        context = Context(**options)
        return Rule(self._payload['expression']['text'], context=context)

class ArchiveImporter(object):
    """
    规则档案导入器。导入流程按固定顺序执行，任一环节失败即隔离（fail-closed）：

    1. 信封结构（格式标识、格式版本、头部、负载）；
    2. 完整性（内容摘要与签名，签名密钥须未撤销、未过期）；
    3. 能力边界（引擎兼容版本、上下文选项白名单、内置符号能力、扩展关键性）；
    4. 语义复验（按声明的选项重建上下文并重解析表达式，符号清单必须完全一致）。

    重复导入按内容摘要幂等：同一 archive_id 的再次导入返回首次裁决的副本，
    不改变任何状态。撤销密钥后，对应档案的后续导入一律被隔离。
    """
    def __init__(self, key_ring: KeyRing, *, now: datetime.datetime | None = None) -> None:
        self.key_ring = key_ring
        self._now = now
        self._seen: dict[str, ImportReport] = {}

    def import_archive(self, data: bytes | str | dict[str, Any]) -> ImportReport:
        """验证并裁决一份档案，返回 :py:class:`ImportReport`。"""
        report = self._import(data)
        if report.archive_id is not None and report.archive_id in self._seen:
            first = self._seen[report.archive_id]
            return dataclasses.replace(first, duplicate=True)
        if report.archive_id is not None:
            self._seen[report.archive_id] = report
        return report

    def _quarantine(self, reasons: list[str], **kwargs: Any) -> ImportReport:
        return ImportReport(decision=ImportDecision.QUARANTINE, reasons=tuple(reasons), **kwargs)

    def _import(self, data: bytes | str | dict[str, Any]) -> ImportReport:
        # 第 1 步：信封结构
        if isinstance(data, dict):
            envelope: Any = data
        else:
            try:
                envelope = canonical_loads(data)
            except errors.ArchiveImportError as error:
                return self._quarantine([error.message])
        if not isinstance(envelope, dict):
            return self._quarantine(['archive envelope is not an object'])
        if envelope.get('format') != FORMAT_MARKER:
            return self._quarantine(['unrecognized archive format marker: {0!r}'.format(envelope.get('format'))])
        format_version = envelope.get('format_version')
        if not isinstance(format_version, int) or isinstance(format_version, bool) or format_version < 0:
            return self._quarantine(['archive format_version is missing or invalid'])
        if format_version > CURRENT_FORMAT_VERSION:
            return self._quarantine(
                    ['archive format version {0} is newer than supported version {1}'.format(format_version, CURRENT_FORMAT_VERSION)],
                    format_version=format_version
            )
        header = envelope.get('header')
        payload = envelope.get('payload')
        if not isinstance(header, dict) or not isinstance(payload, dict):
            return self._quarantine(['archive header or payload is missing or malformed'], format_version=format_version)

        # 第 2 步：完整性（内容摘要 + 签名）
        archive_id = header.get('archive_id')
        if not isinstance(archive_id, str) or not _ARCHIVE_ID_PATTERN.match(archive_id):
            return self._quarantine(['archive_id is missing or malformed'], format_version=format_version)
        if content_digest(payload) != archive_id:
            return self._quarantine(
                    ['payload digest does not match archive_id; the archive was modified after signing'],
                    archive_id=archive_id, format_version=format_version
            )
        signature = header.get('signature')
        if not isinstance(signature, dict):
            return self._quarantine(['signature is missing or malformed'], archive_id=archive_id, format_version=format_version)
        kid, algorithm, value = signature.get('kid'), signature.get('algorithm'), signature.get('value')
        if not (isinstance(kid, str) and isinstance(algorithm, str) and isinstance(value, str)):
            return self._quarantine(['signature fields are missing or malformed'], archive_id=archive_id, format_version=format_version)
        key = self.key_ring.get(kid)
        if key is None:
            return self._quarantine(
                    ['signature key {0} is not in the local trust key ring'.format(kid)],
                    archive_id=archive_id, key_id=kid, format_version=format_version
            )
        status = key.status(now=self._now)
        if status in ('revoked', 'expired'):
            return self._quarantine(
                    ['signature key {0} is {1}'.format(kid, status)],
                    archive_id=archive_id, key_id=kid, format_version=format_version
            )
        if algorithm != key.algorithm:
            return self._quarantine(
                    ['signature algorithm {0!r} does not match key {1} algorithm {2!r}'.format(algorithm, kid, key.algorithm)],
                    archive_id=archive_id, key_id=kid, format_version=format_version
            )
        try:
            signature_bytes = base64.b64decode(value.encode('ascii'), validate=True)
        except (ValueError, TypeError):
            return self._quarantine(['signature value is not valid base64'], archive_id=archive_id, key_id=kid, format_version=format_version)
        if not key.verify(canonical_dumps(payload), signature_bytes):
            return self._quarantine(
                    ['signature verification failed; the archive was modified after signing'],
                    archive_id=archive_id, key_id=kid, format_version=format_version
            )

        # 旧格式：先在原始负载上完成完整性验证，再做确定性迁移
        migrated_from: int | None = None
        if format_version < CURRENT_FORMAT_VERSION:
            try:
                payload = migrate_payload(payload, format_version)
            except errors.ArchiveImportError as error:
                return self._quarantine(
                        [error.message], archive_id=archive_id, key_id=kid, format_version=format_version
                )
            migrated_from = format_version

        # 第 3 步：能力边界
        problems = validate_payload(payload)
        if problems:
            return self._quarantine(
                    problems, archive_id=archive_id, key_id=kid, format_version=format_version, migrated_from=migrated_from
            )
        engine = payload['engine']
        if not version_satisfies(_engine_version, engine['min_version'], engine['max_version']):
            return self._quarantine(
                    ['engine version {0} is outside the archive compatibility range [{1}, {2})'.format(
                            _engine_version, engine['min_version'], engine['max_version']
                    )],
                    archive_id=archive_id, key_id=kid, format_version=format_version, migrated_from=migrated_from
            )
        options_kwargs = context_options_to_kwargs(payload['context_options'])
        probe_context = Context(**options_kwargs)
        missing_builtins = sorted(name for name in payload['symbols']['builtins'] if name not in probe_context.builtins)
        if missing_builtins:
            return self._quarantine(
                    ['archive requires builtin symbol(s) not provided by this engine: {0}'.format(', '.join(missing_builtins))],
                    archive_id=archive_id, key_id=kid, format_version=format_version, migrated_from=migrated_from
            )
        ignored_extensions: list[str] = []
        extension_problems: list[str] = []
        kept_extensions: dict[str, Any] = {}
        for name, extension in payload['extensions'].items():
            validator = KNOWN_EXTENSIONS.get(name)
            if validator is None:
                if extension['critical']:
                    extension_problems.append('unknown critical extension: {0!r}'.format(name))
                else:
                    ignored_extensions.append(name)
                continue
            try:
                validator(extension.get('data'))
            except Exception as error:
                extension_problems.append('extension {0!r} failed validation: {1}'.format(name, error))
            else:
                kept_extensions[name] = extension
        if extension_problems:
            return self._quarantine(
                    extension_problems, archive_id=archive_id, key_id=kid, format_version=format_version, migrated_from=migrated_from
            )
        # 被剥离的扩展不进入物化负载，保证未知扩展无法静默改变规则含义
        payload = dict(payload, extensions=kept_extensions)

        # 第 4 步：语义复验——按声明的选项重解析表达式，符号清单必须完全一致
        try:
            probe_rule = Rule(payload['expression']['text'], context=probe_context)
        except errors.EngineError as error:
            return self._quarantine(
                    ['expression failed to parse under the declared context options: {0}'.format(error.message)],
                    archive_id=archive_id, key_id=kid, format_version=format_version, migrated_from=migrated_from
            )
        actual_symbols = split_symbol_manifest(probe_context)
        if actual_symbols != payload['symbols']:
            return self._quarantine(
                    ['declared symbol manifest does not match the expression (declared: {0!r}, actual: {1!r})'.format(
                            payload['symbols'], actual_symbols
                    )],
                    archive_id=archive_id, key_id=kid, format_version=format_version, migrated_from=migrated_from
            )

        decision = ImportDecision.MIGRATE if migrated_from is not None else ImportDecision.ACCEPT
        return ImportReport(
                decision=decision,
                archive_id=archive_id,
                migrated_from=migrated_from,
                migrated_archive_id=content_digest(payload) if migrated_from is not None else None,
                ignored_extensions=tuple(sorted(ignored_extensions)),
                key_id=kid,
                format_version=format_version,
                _payload=payload,
        )
