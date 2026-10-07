#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  rule_engine/archive/keys.py
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

"""本地信任密钥环。

信任根是**本地**的：每个环境持有自己的 Ed25519 签名密钥与受信公钥集合，
不存在中心化发证机构。密钥通过以下方式轮换：

1. 新环境在本地 :meth:`LocalKeyring.generate` 生成密钥对；
2. 新公钥通过带外渠道安装到导入方的密钥环（:meth:`LocalKeyring.add_public_key`）；
3. 过渡期内新旧密钥同时受信，旧密钥签过的档案仍可验证；
4. 过渡完成后 :meth:`LocalKeyring.revoke` 撤销旧密钥——此后任何仅由旧密钥
   背书的档案一律不得激活，只能隔离。

可选地，档案可以携带一张由**当前受信、未撤销**密钥签发的新密钥背书证书，
导入策略显式开启 ``allow_certified_keys`` 后才生效；该信任链不隐式持久化，
锚点密钥被撤销时其全部背书立即失效。
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import os
from typing import Any, Iterator

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .errors import ArchiveFormatError, RevokedKeyError, UnknownKeyError

KEYRING_VERSION = 1
SIGNATURE_ALGORITHM = 'ed25519'

@dataclasses.dataclass(frozen=True)
class TrustedKey:
    """密钥环中的一个受信公钥条目。"""
    key_id: str
    """公钥标识：原始公钥字节的 SHA-256（十六进制）。"""
    public_key: ed25519.Ed25519PublicKey
    label: str | None = None
    revoked: bool = False

    def to_entry(self) -> dict[str, Any]:
        return {
            'key_id': self.key_id,
            'algorithm': SIGNATURE_ALGORITHM,
            'public_key': self.public_bytes_pem(),
            'revoked': self.revoked,
            'label': self.label,
        }

    @classmethod
    def from_entry(cls, entry: Any) -> 'TrustedKey':
        if not isinstance(entry, dict):
            raise ArchiveFormatError('key entry must be an object')
        if entry.get('algorithm') != SIGNATURE_ALGORITHM:
            raise ArchiveFormatError('unsupported key algorithm: ' + repr(entry.get('algorithm')))
        try:
            public_key = serialization.load_pem_public_key(entry['public_key'].encode('utf-8'))
        except (KeyError, ValueError, TypeError) as error:
            raise ArchiveFormatError('invalid public key PEM') from error
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            raise ArchiveFormatError('only Ed25519 public keys are supported')
        key_id = entry.get('key_id')
        expected = key_identifier(public_key)
        if key_id != expected:
            raise ArchiveFormatError('key entry identifier does not match its public key')
        label = entry.get('label')
        if label is not None and not isinstance(label, str):
            raise ArchiveFormatError('key label must be a string or null')
        return cls(key_id=expected, public_key=public_key, label=label, revoked=bool(entry.get('revoked', False)))

    def public_bytes_pem(self) -> str:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

class SigningKey:
    """本地持有的 Ed25519 签名密钥（私钥从不出现在档案中）。"""
    __slots__ = ('_private_key',)

    def __init__(self, private_key: ed25519.Ed25519PrivateKey) -> None:
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise TypeError('signing key must be an Ed25519 private key')
        self._private_key = private_key

    @classmethod
    def generate(cls) -> 'SigningKey':
        return cls(ed25519.Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, pem_data: bytes | str) -> 'SigningKey':
        if isinstance(pem_data, str):
            pem_data = pem_data.encode('utf-8')
        try:
            private_key = serialization.load_pem_private_key(pem_data, password=None)
        except ValueError as error:
            raise ArchiveFormatError('invalid signing key PEM') from error
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise ArchiveFormatError('only Ed25519 private keys are supported')
        return cls(private_key)

    def to_pem(self) -> bytes:
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    @classmethod
    def load(cls, path: str) -> 'SigningKey':
        with open(path, 'rb') as file_obj:
            return cls.from_pem(file_obj.read())

    def save(self, path: str) -> None:
        """以 0600 权限把私钥写入 *path*（已存在则整体替换）。"""
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, self.to_pem())
        finally:
            os.close(fd)

    @property
    def key_id(self) -> str:
        return key_identifier(self.public_key)

    @property
    def public_key(self) -> ed25519.Ed25519PublicKey:
        return self._private_key.public_key()

    def public_pem(self) -> str:
        return TrustedKey(self.key_id, self.public_key).public_bytes_pem()

    def sign(self, payload: bytes) -> bytes:
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError('payload must be bytes')
        return self._private_key.sign(bytes(payload))

    def issue_certificate(self, certified: 'TrustedKey') -> dict[str, Any]:
        """为另一把公钥签发背书证书（用于密钥轮换的显式过渡）。"""
        body = certificate_body(anchor_key_id=self.key_id, certified_key=certified.public_key)
        signature = self.sign(_canonical_bytes(body))
        return {
            'algorithm': SIGNATURE_ALGORITHM,
            'anchor_key_id': self.key_id,
            'certified_key_id': certified.key_id,
            'public_key': certified.public_bytes_pem(),
            'signature': base64.b64encode(signature).decode('ascii'),
        }

def key_identifier(public_key: ed25519.Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return hashlib.sha256(raw).hexdigest()

def certificate_body(*, anchor_key_id: str, certified_key: ed25519.Ed25519PublicKey) -> dict[str, Any]:
    pem = TrustedKey(key_identifier(certified_key), certified_key).public_bytes_pem()
    return {
        'type': 'rule-engine-key-certificate/v1',
        'anchor_key_id': anchor_key_id,
        'certified_key_id': key_identifier(certified_key),
        'public_key': pem,
    }

def _canonical_bytes(payload: Any) -> bytes:
    # 延迟导入以避免模块级循环
    from .manifest import canonical_encode
    return canonical_encode(payload)

class LocalKeyring:
    """单个环境的本地受信公钥集合，支持安装、轮换与撤销。"""
    def __init__(self, keys: 'set[TrustedKey] | dict[str, TrustedKey] | None' = None) -> None:
        if keys is None:
            self._keys: dict[str, TrustedKey] = {}
        elif isinstance(keys, dict):
            self._keys = dict(keys)
        else:
            self._keys = {key.key_id: key for key in keys}

    def __len__(self) -> int:
        return len(self._keys)

    def __iter__(self) -> Iterator[TrustedKey]:
        return iter(self._keys.values())

    def __contains__(self, key_id: object) -> bool:
        return isinstance(key_id, str) and key_id in self._keys

    def get(self, key_id: str) -> TrustedKey | None:
        return self._keys.get(key_id)

    def is_trusted(self, key_id: str) -> bool:
        key = self._keys.get(key_id)
        return key is not None and not key.revoked

    def add_public_key(self, public_key: ed25519.Ed25519PublicKey | str | bytes, *, label: str | None = None) -> TrustedKey:
        """安装一把受信公钥（轮换流程的带外安装步骤）。

        已撤销的同标识密钥不能通过重新安装恢复信任（撤销是单向操作）；
        只能更新未撤销密钥的标签，或先删除后重新走带外安装流程。
        """
        if isinstance(public_key, str):
            public_key = public_key.encode('utf-8')
        if isinstance(public_key, bytes):
            try:
                loaded = serialization.load_pem_public_key(public_key)
            except ValueError as error:
                raise ArchiveFormatError('invalid public key PEM') from error
        else:
            loaded = public_key
        if not isinstance(loaded, ed25519.Ed25519PublicKey):
            raise ArchiveFormatError('only Ed25519 public keys are supported')
        key_id = key_identifier(loaded)
        existing = self._keys.get(key_id)
        if existing is not None:
            if existing.revoked:
                raise RevokedKeyError(
                    'key has been revoked and can not be re-installed without explicit removal: ' + key_id,
                    key_id=key_id
                )
            entry = TrustedKey(key_id, loaded, label=label, revoked=False)
        else:
            entry = TrustedKey(key_id, loaded, label=label, revoked=False)
        self._keys[key_id] = entry
        return entry

    def remove(self, key_id: str) -> None:
        """彻底移除一个密钥条目（含其撤销标记）；移除后重新安装视为全新信任决定。"""
        if key_id not in self._keys:
            raise UnknownKeyError('no such trusted key: ' + key_id, key_id=key_id)
        del self._keys[key_id]

    def add_signing_key(self, signing_key: SigningKey, *, label: str | None = None) -> TrustedKey:
        return self.add_public_key(signing_key.public_key, label=label)

    def revoke(self, key_id: str) -> None:
        """撤销密钥；撤销是单向的本地状态，无法通过重新导入档案恢复。"""
        key = self._keys.get(key_id)
        if key is None:
            raise UnknownKeyError('no such trusted key: ' + key_id, key_id=key_id)
        if not key.revoked:
            self._keys[key_id] = dataclasses.replace(key, revoked=True)

    def verify(self, payload: bytes, signature: bytes, key_id: str) -> TrustedKey:
        """验证 *key_id* 对 *payload* 的签名，返回受信密钥条目。

        :raises UnknownKeyError: 密钥不在本地密钥环中。
        :raises RevokedKeyError: 密钥已被撤销。
        :raises ArchiveIntegrityError: 签名不匹配。
        """
        from .errors import ArchiveIntegrityError
        key = self._keys.get(key_id)
        if key is None:
            raise UnknownKeyError('unsigned by a locally trusted key: ' + key_id, key_id=key_id)
        if key.revoked:
            raise RevokedKeyError('the signing key has been revoked: ' + key_id, key_id=key_id)
        try:
            key.public_key.verify(signature, bytes(payload))
        except InvalidSignature:
            raise ArchiveIntegrityError('signature verification failed for key ' + key_id) from None
        return key

    def verify_certificate(self, certificate: Any) -> TrustedKey:
        """验证一张背书证书，返回被背书的临时受信公钥（不写入密钥环）。"""
        from .errors import ArchiveIntegrityError
        if not isinstance(certificate, dict) or certificate.get('algorithm') != SIGNATURE_ALGORITHM:
            raise ArchiveFormatError('invalid key certificate')
        anchor_key_id = certificate.get('anchor_key_id')
        if not isinstance(anchor_key_id, str):
            raise ArchiveFormatError('invalid key certificate anchor')
        anchor = self._keys.get(anchor_key_id)
        if anchor is None:
            raise UnknownKeyError('certificate anchor is not trusted', key_id=anchor_key_id)
        if anchor.revoked:
            raise RevokedKeyError('certificate anchor key has been revoked', key_id=anchor.key_id)
        try:
            public_pem = certificate['public_key'].encode('utf-8')
            certified = serialization.load_pem_public_key(public_pem)
            signature = base64.b64decode(certificate['signature'])
        except (KeyError, ValueError, TypeError, AttributeError) as error:
            raise ArchiveFormatError('malformed key certificate') from error
        if not isinstance(certified, ed25519.Ed25519PublicKey):
            raise ArchiveFormatError('certified key must be Ed25519')
        certified_id = key_identifier(certified)
        if certified_id != certificate.get('certified_key_id'):
            raise ArchiveIntegrityError('certified key identifier mismatch')
        body = certificate_body(anchor_key_id=anchor.key_id, certified_key=certified)
        try:
            anchor.public_key.verify(signature, _canonical_bytes(body))
        except InvalidSignature:
            raise ArchiveIntegrityError('certificate signature verification failed') from None
        return TrustedKey(certified_id, certified, label='certified-by:' + anchor.key_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            'keyring_version': KEYRING_VERSION,
            'keys': [key.to_entry() for key in sorted(self._keys.values(), key=lambda item: item.key_id)],
        }

    @classmethod
    def from_dict(cls, payload: Any) -> 'LocalKeyring':
        if not isinstance(payload, dict) or payload.get('keyring_version') != KEYRING_VERSION:
            raise ArchiveFormatError('unsupported keyring version')
        entries = payload.get('keys')
        if not isinstance(entries, list):
            raise ArchiveFormatError('keyring keys must be a list')
        return cls({entry.key_id: entry for entry in (TrustedKey.from_entry(item) for item in entries)})

    def save(self, path: str) -> None:
        """以 0600 权限把密钥环写入 *path*。"""
        data = json.dumps(self.to_dict(), indent=2, sort_keys=True).encode('utf-8')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)

    @classmethod
    def load(cls, path: str) -> 'LocalKeyring':
        with open(path, 'r', encoding='utf-8') as file_obj:
            return cls.from_dict(json.load(file_obj))
