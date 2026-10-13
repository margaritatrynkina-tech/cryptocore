from __future__ import annotations

import pytest

from src.csprng import (
    BLOCK_SIZE,
    KEY_SIZE,
    CSPRNGError,
    generate_random_bytes,
    generate_key,
    generate_iv,
)


class TestGenerateRandomBytes:
    def test_length(self):
        for n in [0, 1, 15, 16, 17, 32, 100, 1000, 4096]:
            assert len(generate_random_bytes(n)) == n

    def test_zero_returns_empty(self):
        assert generate_random_bytes(0) == b""

    def test_returns_bytes(self):
        result = generate_random_bytes(16)
        assert isinstance(result, bytes)

    def test_negative_raises(self):
        with pytest.raises(ValueError):
            generate_random_bytes(-1)

    def test_negative_large_raises(self):
        with pytest.raises(ValueError):
            generate_random_bytes(-1000)

    def test_non_int_raises(self):
        with pytest.raises(TypeError):
            generate_random_bytes("16")
        with pytest.raises(TypeError):
            generate_random_bytes(16.5)
        with pytest.raises(TypeError):
            generate_random_bytes(None)

    def test_bool_rejected(self):
        with pytest.raises(TypeError):
            generate_random_bytes(True)
        with pytest.raises(TypeError):
            generate_random_bytes(False)

    def test_two_calls_differ(self):
        a = generate_random_bytes(32)
        b = generate_random_bytes(32)
        assert a != b

    def test_not_all_zeros(self):
        result = generate_random_bytes(64)
        assert result != b"\x00" * 64


class TestKeyUniqueness:

    def test_1000_unique_keys(self):
        key_set = set()
        num_keys = 1000
        for _ in range(num_keys):
            key = generate_random_bytes(KEY_SIZE)
            key_hex = key.hex()
            assert key_hex not in key_set, f"Duplicate key: {key_hex}"
            key_set.add(key_hex)
        assert len(key_set) == num_keys

    def test_1000_unique_ivs(self):
        iv_set = set()
        for _ in range(1000):
            iv = generate_random_bytes(BLOCK_SIZE)
            iv_set.add(iv.hex())
        assert len(iv_set) == 1000


class TestBasicDistribution:

    def test_mean_hamming_weight_near_half(self):
        data = generate_random_bytes(10000)
        total_bits = len(data) * 8
        ones = sum(bin(b).count("1") for b in data)
        ratio = ones / total_bits
        # 10000 bytes = 80000 bits
        assert 0.48 <= ratio <= 0.52, f"Hamming ratio {ratio:.4f} out of range"

    def test_all_byte_values_appear(self):
        data = generate_random_bytes(4096)
        seen = set(data)
        assert len(seen) == 256


class TestGenerateKey:
    def test_default_size(self):
        assert len(generate_key()) == KEY_SIZE

    def test_custom_size(self):
        assert len(generate_key(32)) == 32
        assert len(generate_key(8)) == 8

    def test_returns_bytes(self):
        assert isinstance(generate_key(), bytes)


class TestGenerateIv:
    def test_size(self):
        assert len(generate_iv()) == BLOCK_SIZE

    def test_returns_bytes(self):
        assert isinstance(generate_iv(), bytes)

    def test_unique(self):
        ivs = {generate_iv() for _ in range(100)}
        assert len(ivs) == 100


class TestErrorHandling:
    def test_csprng_error_is_exception(self):
        assert issubclass(CSPRNGError, Exception)

    def test_monkeypatched_failure_raises(self, monkeypatch):
        import src.csprng as csprng_module

        def broken_urandom(n):
            raise OSError("simulated failure")

        monkeypatch.setattr(csprng_module.os, "urandom", broken_urandom)

        with pytest.raises(CSPRNGError):
            generate_random_bytes(16)