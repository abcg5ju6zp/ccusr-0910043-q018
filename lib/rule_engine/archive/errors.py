#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  rule_engine/archive/errors.py
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

from ..errors import EngineError

class ArchiveError(EngineError):
    """规则档案相关错误的基类。"""

class ArchiveFormatError(ArchiveError):
    """档案结构不符合任何受支持的档案格式（信封、清单字段缺失或类型错误等）。"""
    def __init__(self, message: str = '', *, archive_format: str | None = None, format_version: int | None = None, capability: str | None = None) -> None:
        super().__init__(message)
        self.archive_format = archive_format
        """档案格式标识（当格式本身可识别时）。"""
        self.format_version = format_version
        """档案格式版本（当版本字段可读取时）。"""
        self.capability = capability
        """无法解析的具体能力名称（当结构错误与能力相关时）。"""

class ArchiveIntegrityError(ArchiveError):
    """签名验证失败或负载摘要不匹配，档案内容不可信。"""

class UnverifiedArchiveError(ArchiveError):
    """档案没有携带任何可在本地信任密钥环中通过验证的签名。"""

class UnknownKeyError(ArchiveError):
    """签名密钥既不在受信密钥环中，也没有合法的受信背书。"""
    def __init__(self, message: str = '', *, key_id: str | None = None) -> None:
        super().__init__(message)
        self.key_id = key_id
        """无法识别的信任密钥标识。"""

class RevokedKeyError(ArchiveError):
    """签名密钥已被本地密钥环撤销，档案必须被隔离。"""
    def __init__(self, message: str = '', *, key_id: str | None = None) -> None:
        super().__init__(message)
        self.key_id = key_id
        """已撤销的信任密钥标识。"""

class UnsupportedCapabilityError(ArchiveError):
    """档案声明的能力（解析选项、类型结构或引擎版本）超出本地环境边界。"""
    def __init__(self, message: str = '', *, capability: str | None = None) -> None:
        super().__init__(message)
        self.capability = capability
        """超出边界的具体能力名称。"""

class DuplicateRuleError(ArchiveError):
    """档案中的规则标识与已存在规则冲突且内容不一致。"""
    def __init__(self, message: str = '', *, rule_id: str | None = None) -> None:
        super().__init__(message)
        self.rule_id = rule_id
        """冲突的规则标识。"""

class SchemaExportError(ArchiveError):
    """规则依赖的类型信息无法导出为可移植声明（例如依赖运行期业务对象）。"""
    def __init__(self, message: str = '', *, capability: str | None = None) -> None:
        super().__init__(message)
        self.capability = capability
        """无法可移植导出的具体能力名称。"""
