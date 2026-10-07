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

"""可移植、签名的规则档案（测试环境 → 隔离生产环境）。

档案是一份自描述 JSON 信封：规范清单（表达式、解析上下文选项、符号清单、
类型注册表、兼容引擎版本）外加一个或多个本地信任密钥的 Ed25519 签名。
导入时按固定流水线做完整性验证与能力边界检查，输出
:class:`~rule_engine.archive.ImportDecision`（接受 / 隔离 / 迁移），
任何异常输入都不能悄悄改变规则含义。
"""

from .archive import ImportDecision, ImportRegistry, ImportReport, RuleArchive, SignatureInfo
from .errors import (
    ArchiveError,
    ArchiveFormatError,
    ArchiveIntegrityError,
    DuplicateRuleError,
    RevokedKeyError,
    SchemaExportError,
    UnknownKeyError,
    UnsupportedCapabilityError,
    UnverifiedArchiveError,
)
from .keys import LocalKeyring, SigningKey, TrustedKey

__all__ = (
    'ArchiveError',
    'ArchiveFormatError',
    'ArchiveIntegrityError',
    'DuplicateRuleError',
    'ImportDecision',
    'ImportRegistry',
    'ImportReport',
    'LocalKeyring',
    'RevokedKeyError',
    'RuleArchive',
    'SchemaExportError',
    'SignatureInfo',
    'SigningKey',
    'TrustedKey',
    'UnknownKeyError',
    'UnsupportedCapabilityError',
    'UnverifiedArchiveError',
)
