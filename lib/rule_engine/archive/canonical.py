#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  rule_engine/archive/canonical.py
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

import hashlib
import json
import math
from typing import Any

from .. import errors

def canonical_dumps(value: Any) -> bytes:
    """
    将档案数据序列化为规范字节形式。相同的逻辑内容必须产生完全相同的字节序列，
    以便内容摘要与签名可以跨环境复现。规范为：UTF-8 编码、对象键按码点排序、
    无冗余空白、浮点仅允许有限值。
    """
    return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(',', ':'),
    ).encode('utf-8')

def canonical_loads(data: bytes | str) -> Any:
    """解析档案字节，并拒绝非规范的数值（NaN / Infinity 会被拒绝）。"""
    def _reject_constant(name: str) -> Any:
        raise errors.ArchiveImportError('non-finite number {0!r} is not permitted in an archive'.format(name))
    try:
        return json.loads(data, parse_constant=_reject_constant)
    except json.JSONDecodeError as error:
        raise errors.ArchiveImportError('archive is not valid JSON: {0}'.format(error)) from error

def content_digest(payload: Any) -> str:
    """计算规范化内容的摘要，作为档案的内容寻址标识（archive_id）。"""
    return 'sha256:' + hashlib.sha256(canonical_dumps(payload)).hexdigest()

def is_json_scalar(value: Any) -> bool:
    """判断值是否为 JSON 标量（字符串、有限数值、布尔或 None）。"""
    if value is None or isinstance(value, (str, bool)):
        return True
    if isinstance(value, int):
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    return False

def is_json_safe(value: Any, _depth: int = 0) -> bool:
    """
    判断值是否可以无损地表示为规范化 JSON。档案只允许携带此类数据，
    从而保证导出内容中不会夹带业务对象（任意 Python 对象、可调用对象等）。
    """
    if _depth > 32:
        return False
    if is_json_scalar(value):
        return True
    if isinstance(value, (list, tuple)):
        return all(is_json_safe(item, _depth + 1) for item in value)
    if isinstance(value, dict):
        return all(
                isinstance(key, str) and is_json_safe(item, _depth + 1)
                for key, item in value.items()
        )
    return False
