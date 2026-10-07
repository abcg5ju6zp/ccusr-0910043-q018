#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  rule_engine/archive/__init__.py
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

"""
可移植规则档案：把规则（表达式文本、上下文选项、符号清单、兼容版本）规范化
序列化并用本地信任密钥签名，以便在测试环境与隔离生产环境之间安全转交。

- 导出：:py:func:`export_rule` 产出规范化、带签名的档案字节，不包含业务对象；
- 导入：:py:class:`ArchiveImporter` 依次验证信封结构、完整性（摘要 + 签名）、
  能力边界（引擎版本、选项白名单、内置符号、扩展关键性）与语义复验，
  然后裁决为 ACCEPT / QUARANTINE / MIGRATE；
- 密钥：:py:class:`KeyRing` 支持生成、轮换（retire 旧密钥）与撤销（fail-closed）；
- 幂等：重复导入同一 archive_id 返回首次裁决的副本，不改变任何状态。
"""

from .canonical import canonical_dumps, canonical_loads, content_digest
from .exporter import export_rule
from .format import (
    CURRENT_FORMAT_VERSION,
    FORMAT_MARKER,
    GRAMMAR_VERSION,
    build_payload,
    register_extension,
    register_migration,
    validate_payload,
)
from .importer import ArchiveImporter, ImportDecision, ImportReport
from .keys import (
    ALGORITHM_ED25519,
    ALGORITHM_HMAC_SHA256,
    SUPPORTED_ALGORITHMS,
    KeyRing,
    TrustKey,
)

__all__ = (
    'ALGORITHM_ED25519',
    'ALGORITHM_HMAC_SHA256',
    'ArchiveImporter',
    'CURRENT_FORMAT_VERSION',
    'FORMAT_MARKER',
    'GRAMMAR_VERSION',
    'ImportDecision',
    'ImportReport',
    'KeyRing',
    'SUPPORTED_ALGORITHMS',
    'TrustKey',
    'build_payload',
    'canonical_dumps',
    'canonical_loads',
    'content_digest',
    'export_rule',
    'register_extension',
    'register_migration',
    'validate_payload',
)
