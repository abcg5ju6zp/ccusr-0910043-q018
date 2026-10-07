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

from __future__ import annotations

import base64
import dataclasses
import datetime
import hashlib
import hmac
import secrets
from typing import Any

from .. import errors

ALGORITHM_HMAC_SHA256 = 'hmac-sha256'
ALGORITHM_ED25519 = 'ed25519'
SUPPORTED_ALGORITHMS = (ALGORITHM_HMAC_SHA256, ALGORITHM_ED25519)

def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode('ascii')

def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode('ascii'), validate=True)

def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(tz=datetime.timezone.utc)

def _to_iso(moment: datetime.datetime) -> str:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.timezone.utc)
    return moment.astimezone(datetime.timezone.utc).isoformat()

def _from_iso(text: str) -> datetime.datetime:
    moment = datetime.datetime.fromisoformat(text)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.timezone.utc)
    return moment

def _load_ed25519() -> Any:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        raise errors.ArchiveError(
                'the ed25519 algorithm requires the "cryptography" package; '
                'use {0!r} or install cryptography'.format(ALGORITHM_HMAC_SHA256)
        )
    return Ed25519PrivateKey

@dataclasses.dataclass
class TrustKey(object):
    """
    本地信任密钥。密钥由本环境生成并持有，用于签名与验证规则档案。
    生命周期：active（可签名可验证）→ retired（仅验证，轮换后）→ revoked（拒绝一切验证）。
    """
    kid: str
    algorithm: str
    material: bytes
    """密钥材料。hmac-sha256 为对称密钥；ed25519 为私钥种子。属于敏感数据，仅在本地信任库中保存。"""
    created_at: str
    expires_at: str | None = None
    retired: bool = False
    revoked: bool = False

    @classmethod
    def generate(
            cls,
            algorithm: str = ALGORITHM_HMAC_SHA256,
            *,
            expires_at: datetime.datetime | None = None,
            now: datetime.datetime | None = None
    ) -> 'TrustKey':
        """生成新的本地信任密钥。"""
        if algorithm == ALGORITHM_HMAC_SHA256:
            material = secrets.token_bytes(32)
        elif algorithm == ALGORITHM_ED25519:
            material = _load_ed25519().generate().private_bytes_raw()
        else:
            raise errors.ArchiveError('unsupported signature algorithm: {0!r}'.format(algorithm))
        kid = 'k-' + hashlib.sha256(material).hexdigest()[:24]
        return cls(
                kid=kid,
                algorithm=algorithm,
                material=material,
                created_at=_to_iso(now or _utcnow()),
                expires_at=None if expires_at is None else _to_iso(expires_at),
        )

    @property
    def public_material(self) -> bytes:
        """可公开的验证材料。hmac-sha256 为对称算法，验证材料即密钥本身，不得对外分发。"""
        if self.algorithm == ALGORITHM_ED25519:
            private_key = _load_ed25519().from_private_bytes(self.material)
            return private_key.public_key().public_bytes_raw()
        return self.material

    def status(self, now: datetime.datetime | None = None) -> str:
        """返回密钥在当前时刻的状态：revoked / expired / retired / active。"""
        if self.revoked:
            return 'revoked'
        if self.expires_at is not None and _from_iso(self.expires_at) <= (now or _utcnow()):
            return 'expired'
        if self.retired:
            return 'retired'
        return 'active'

    def sign(self, payload: bytes) -> bytes:
        """对规范化的档案负载字节签名。"""
        if self.revoked:
            raise errors.ArchiveExportError('refusing to sign with revoked key {0}'.format(self.kid))
        if self.algorithm == ALGORITHM_HMAC_SHA256:
            return hmac.new(self.material, payload, hashlib.sha256).digest()
        if self.algorithm == ALGORITHM_ED25519:
            return _load_ed25519().from_private_bytes(self.material).sign(payload)
        raise errors.ArchiveError('unsupported signature algorithm: {0!r}'.format(self.algorithm))

    def verify(self, payload: bytes, signature: bytes) -> bool:
        """验证签名，不抛出异常，验证失败返回 False。"""
        if self.algorithm == ALGORITHM_HMAC_SHA256:
            expected = hmac.new(self.material, payload, hashlib.sha256).digest()
            return hmac.compare_digest(expected, signature)
        if self.algorithm == ALGORITHM_ED25519:
            try:
                public_key = _load_ed25519().from_private_bytes(self.material).public_key()
                public_key.verify(signature, payload)
                return True
            except Exception:
                return False
        return False

    def to_dict(self) -> dict[str, Any]:
        """序列化为可持久化的字典。包含密钥材料，必须按敏感数据保管。"""
        return {
                'kid': self.kid,
                'algorithm': self.algorithm,
                'material': _b64e(self.material),
                'created_at': self.created_at,
                'expires_at': self.expires_at,
                'retired': self.retired,
                'revoked': self.revoked,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> 'TrustKey':
        """从字典恢复密钥，并对字段做严格校验。"""
        try:
            key = cls(
                    kid=str(data['kid']),
                    algorithm=str(data['algorithm']),
                    material=_b64d(str(data['material'])),
                    created_at=str(data['created_at']),
                    expires_at=None if data.get('expires_at') is None else str(data['expires_at']),
                    retired=bool(data.get('retired', False)),
                    revoked=bool(data.get('revoked', False)),
            )
        except (KeyError, ValueError, TypeError) as error:
            raise errors.ArchiveError('invalid trust key record: {0}'.format(error)) from error
        if key.algorithm not in SUPPORTED_ALGORITHMS:
            raise errors.ArchiveError('unsupported signature algorithm: {0!r}'.format(key.algorithm))
        return key

class KeyRing(object):
    """
    本地信任密钥环，管理签名密钥的生成、轮换与撤销。
    轮换产生新的 active 密钥并把旧的 active 密钥降级为 retired（仅可验证旧档案）；
    撤销则立即让对应密钥的一切验证失败（fail-closed）。
    """
    def __init__(self, keys: list[TrustKey] | None = None, active_kid: str | None = None) -> None:
        self._keys: dict[str, TrustKey] = {}
        self.active_kid: str | None = None
        for key in keys or []:
            self.add(key)
        if active_kid is not None:
            if active_kid not in self._keys:
                raise errors.ArchiveError('active kid {0} is not present in the key ring'.format(active_kid))
            self.active_kid = active_kid

    def __contains__(self, kid: str) -> bool:
        return kid in self._keys

    def __len__(self) -> int:
        return len(self._keys)

    @property
    def kids(self) -> tuple[str, ...]:
        return tuple(sorted(self._keys))

    def add(self, key: TrustKey) -> None:
        """把密钥加入密钥环；首个加入的密钥自动成为 active。"""
        if key.kid in self._keys:
            raise errors.ArchiveError('duplicate key id: {0}'.format(key.kid))
        self._keys[key.kid] = key
        if self.active_kid is None:
            self.active_kid = key.kid

    def get(self, kid: str) -> TrustKey | None:
        return self._keys.get(kid)

    def active_key(self) -> TrustKey:
        """返回当前用于签名的 active 密钥。"""
        if self.active_kid is None:
            raise errors.ArchiveExportError('the key ring has no active signing key')
        key = self._keys[self.active_kid]
        if key.revoked:
            raise errors.ArchiveExportError('the active signing key {0} has been revoked'.format(key.kid))
        return key

    def generate(
            self,
            algorithm: str = ALGORITHM_HMAC_SHA256,
            *,
            expires_at: datetime.datetime | None = None,
            now: datetime.datetime | None = None
    ) -> TrustKey:
        """生成新密钥并设为 active；已有的 active 密钥被降级为 retired。"""
        key = TrustKey.generate(algorithm, expires_at=expires_at, now=now)
        if self.active_kid is not None:
            self._keys[self.active_kid].retired = True
        self._keys[key.kid] = key
        self.active_kid = key.kid
        return key

    def rotate(self, **kwargs: Any) -> TrustKey:
        """轮换签名密钥，等价于 :py:meth:`generate`。旧密钥保持可验证直到被撤销或过期。"""
        return self.generate(**kwargs)

    def revoke(self, kid: str) -> None:
        """撤销密钥。撤销后该密钥的签名一律验证失败，导入方必须拒绝或隔离对应档案。"""
        if kid not in self._keys:
            raise errors.ArchiveError('unknown key id: {0}'.format(kid))
        self._keys[kid].revoked = True

    def to_dict(self) -> dict[str, Any]:
        """序列化整个密钥环。包含密钥材料，必须按敏感数据保管。"""
        return {
                'active_kid': self.active_kid,
                'keys': [self._keys[kid].to_dict() for kid in sorted(self._keys)],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> 'KeyRing':
        """从字典恢复密钥环。"""
        try:
            keys = [TrustKey.from_dict(item) for item in data['keys']]
            active_kid = data.get('active_kid')
        except (KeyError, TypeError) as error:
            raise errors.ArchiveError('invalid key ring record: {0}'.format(error)) from error
        return cls(keys=keys, active_kid=None if active_kid is None else str(active_kid))
