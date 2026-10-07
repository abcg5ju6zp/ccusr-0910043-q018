#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  rule_engine/archive/exporter.py
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
from typing import TYPE_CHECKING, Any

from .. import errors

from .canonical import canonical_dumps
from .format import CURRENT_FORMAT_VERSION, build_envelope, build_payload, validate_payload
from .keys import KeyRing

if TYPE_CHECKING:
    from ..engine.rule import Rule

def export_rule(
        rule: 'Rule',
        key_ring: KeyRing,
        *,
        extensions: dict[str, Any] | None = None,
        format_version: int = CURRENT_FORMAT_VERSION
) -> bytes:
    """
    把一条规则导出为签名的可移植档案（规范化 JSON 字节）。
    档案只包含表达式文本、上下文选项、符号清单、兼容版本与扩展声明，
    不包含任何业务对象；解析器、类型解析器等环境代码由导入方自行提供。
    """
    if format_version != CURRENT_FORMAT_VERSION:
        raise errors.ArchiveExportError(
                'cannot export format version {0}; this implementation writes version {1}'.format(
                        format_version, CURRENT_FORMAT_VERSION
                )
        )
    payload = build_payload(rule, extensions=extensions)
    problems = validate_payload(payload)
    if problems:
        raise errors.ArchiveExportError('refusing to export an invalid payload: {0}'.format('; '.join(problems)))
    key = key_ring.active_key()
    payload_bytes = canonical_dumps(payload)
    signature = {
            'kid': key.kid,
            'algorithm': key.algorithm,
            'value': base64.b64encode(key.sign(payload_bytes)).decode('ascii'),
    }
    envelope = build_envelope(payload, signature, format_version=format_version)
    return canonical_dumps(envelope)
