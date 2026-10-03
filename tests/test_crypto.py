"""加密原语的单元测试。"""

from __future__ import annotations

import os

import pytest

from ulocker import crypto as C
from ulocker.errors import IntegrityError, ULockerError

from conftest import FAST_ARGON2, FAST_SCRYPT


class TestKdf:
    def test_argon2id_is_deterministic(self) -> None:
        salt = C.random_bytes(C.SALT_LEN)
        a = C.derive_kek("hunter2", salt, C.KDF_ARGON2ID, FAST_ARGON2)
        b = C.derive_kek("hunter2", salt, C.KDF_ARGON2ID, FAST_ARGON2)
        assert a == b
        assert len(a) == C.KEY_LEN

    def test_scrypt_is_deterministic(self) -> None:
        salt = C.random_bytes(C.SALT_LEN)
        a = C.derive_kek("hunter2", salt, C.KDF_SCRYPT, FAST_SCRYPT)
        b = C.derive_kek("hunter2", salt, C.KDF_SCRYPT, FAST_SCRYPT)
        assert a == b

    def test_different_salt_gives_different_key(self) -> None:
        a = C.derive_kek("same", C.random_bytes(16), C.KDF_ARGON2ID, FAST_ARGON2)
        b = C.derive_kek("same", C.random_bytes(16), C.KDF_ARGON2ID, FAST_ARGON2)
        assert a != b

    def test_different_password_gives_different_key(self) -> None:
        salt = C.random_bytes(16)
        a = C.derive_kek("one", salt, C.KDF_ARGON2ID, FAST_ARGON2)
        b = C.derive_kek("two", salt, C.KDF_ARGON2ID, FAST_ARGON2)
        assert a != b

    def test_independent_kdfs_disagree(self) -> None:
        """同一个口令用不同 KDF 派生出的结果不应相同。"""
        salt = C.random_bytes(16)
        argon = C.derive_kek("pw", salt, C.KDF_ARGON2ID, FAST_ARGON2)
        scrypt = C.derive_kek("pw", salt, C.KDF_SCRYPT, FAST_SCRYPT)
        assert argon != scrypt

    def test_unknown_kdf_rejected(self) -> None:
        with pytest.raises(ULockerError):
            C.derive_kek("pw", C.random_bytes(16), 99, {})

    def test_short_salt_rejected(self) -> None:
        with pytest.raises(ULockerError):
            C.derive_kek("pw", b"abc", C.KDF_ARGON2ID, FAST_ARGON2)

    def test_bad_scrypt_n_rejected(self) -> None:
        with pytest.raises(ULockerError):
            C.derive_kek("pw", C.random_bytes(16), C.KDF_SCRYPT, {"n": 15, "r": 8, "p": 1})

    def test_resolve_kdf(self) -> None:
        assert C.resolve_kdf("argon2id") == C.KDF_ARGON2ID
        assert C.resolve_kdf("Scrypt") == C.KDF_SCRYPT
        assert C.resolve_kdf("2") == C.KDF_SCRYPT
        with pytest.raises(ULockerError):
            C.resolve_kdf("bcrypt")


class TestKdfParams:
    def test_new_params_contains_salt(self) -> None:
        params = C.new_kdf_params(C.KDF_ARGON2ID)
        salt = C.kdf_salt(params)
        assert len(salt) == C.SALT_LEN
        assert params["time_cost"] == C.DEFAULT_ARGON2ID["time_cost"]

    def test_overrides_apply(self) -> None:
        params = C.new_kdf_params(C.KDF_ARGON2ID, {"time_cost": 7, "parallelism": None})
        assert params["time_cost"] == 7
        assert params["parallelism"] == C.DEFAULT_ARGON2ID["parallelism"]

    def test_salt_is_fresh_each_time(self) -> None:
        assert C.kdf_salt(C.new_kdf_params(C.KDF_SCRYPT)) != C.kdf_salt(
            C.new_kdf_params(C.KDF_SCRYPT)
        )

    def test_missing_salt_rejected(self) -> None:
        with pytest.raises(ULockerError):
            C.kdf_salt({})

    def test_unknown_kdf_id(self) -> None:
        with pytest.raises(ULockerError):
            C.new_kdf_params(42)


class TestSubkeys:
    def test_index_key_differs_from_kek(self) -> None:
        kek = C.random_bytes(32)
        index_key = C.derive_index_key(kek)
        assert index_key != kek
        assert len(index_key) == C.KEY_LEN

    def test_index_key_is_deterministic(self) -> None:
        kek = C.random_bytes(32)
        assert C.derive_index_key(kek) == C.derive_index_key(kek)


class TestAead:
    def test_roundtrip(self) -> None:
        key = C.random_bytes(32)
        nonce = C.random_bytes(C.NONCE_LEN)
        plain = b"top secret payload"
        ct = C.aead_encrypt(key, nonce, plain, b"aad")
        assert C.aead_decrypt(key, nonce, ct, b"aad") == plain

    def test_ciphertext_differs_from_plaintext(self) -> None:
        key = C.random_bytes(32)
        plain = b"A" * 64
        ct = C.aead_encrypt(key, C.random_bytes(12), plain)
        assert plain not in ct

    def test_tampered_ciphertext_rejected(self) -> None:
        key = C.random_bytes(32)
        nonce = C.random_bytes(12)
        ct = bytearray(C.aead_encrypt(key, nonce, b"important", b""))
        ct[0] ^= 0x01
        with pytest.raises(IntegrityError):
            C.aead_decrypt(key, nonce, bytes(ct), b"")

    def test_wrong_aad_rejected(self) -> None:
        key = C.random_bytes(32)
        nonce = C.random_bytes(12)
        ct = C.aead_encrypt(key, nonce, b"data", b"right")
        with pytest.raises(IntegrityError):
            C.aead_decrypt(key, nonce, ct, b"wrong")

    def test_wrong_key_rejected(self) -> None:
        nonce = C.random_bytes(12)
        ct = C.aead_encrypt(C.random_bytes(32), nonce, b"data")
        with pytest.raises(IntegrityError):
            C.aead_decrypt(C.random_bytes(32), nonce, ct)

    def test_custom_error_type(self) -> None:
        from ulocker.errors import WrongPasswordError

        nonce = C.random_bytes(12)
        ct = C.aead_encrypt(C.random_bytes(32), nonce, b"data")
        with pytest.raises(WrongPasswordError):
            C.aead_decrypt(
                C.random_bytes(32), nonce, ct, err=WrongPasswordError, msg="nope"
            )


class TestHelpers:
    def test_b64_roundtrip(self) -> None:
        raw = os.urandom(40)
        assert C.b64d(C.b64e(raw)) == raw

    def test_b64_invalid(self) -> None:
        with pytest.raises(ULockerError):
            C.b64d("!!!not base64!!!")

    def test_random_bytes_length(self) -> None:
        assert len(C.random_bytes(17)) == 17
        assert C.random_bytes(8) != C.random_bytes(8)

    def test_new_data_key_is_32_bytes(self) -> None:
        assert len(C.new_data_key()) == 32

    def test_constants_sane(self) -> None:
        assert C.CHUNK_SIZE == 1 << 20
        assert C.GCM_TAG_LEN == 16
        assert C.MAGIC == b"ULOCKERV"
        assert C.RECORD_HEADER_LEN == 16
