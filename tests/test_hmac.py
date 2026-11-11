import pytest
from src.mac.hmac import HMAC


class TestHMACRFC4231:
    # Test Case 1
    def test_case_1(self):
        key = bytes.fromhex("0b" * 20)
        data = b"Hi There"
        expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        assert HMAC(key).hexdigest(data) == expected

    # Test Case 2
    def test_case_2(self):
        key = b"Jefe"
        data = b"what do ya want for nothing?"
        expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        assert HMAC(key).hexdigest(data) == expected

    # Test Case 3
    def test_case_3(self):
        key = bytes.fromhex("aa" * 20)
        data = bytes.fromhex("dd" * 50)
        expected = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        assert HMAC(key).hexdigest(data) == expected

    # Test Case 4
    def test_case_4(self):
        key = bytes.fromhex("0102030405060708090a0b0c0d0e0f10111213141516171819")
        data = bytes.fromhex("cd" * 50)
        expected = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
        assert HMAC(key).hexdigest(data) == expected


class TestHMACKeySizes:
    def test_short_key(self):
        key = b"shortkey"
        data = b"data"
        # Should work (padded with zeros)
        assert len(HMAC(key).hexdigest(data)) == 64

    def test_block_size_key(self):
        key = b"A" * 64
        data = b"data"
        assert len(HMAC(key).hexdigest(data)) == 64

    def test_long_key(self):
        key = b"B" * 100  # > 64 bytes
        data = b"data"
        # Should work (hashed first)
        assert len(HMAC(key).hexdigest(data)) == 64


class TestHMACEmpty:
    def test_empty_message(self):
        key = b"key"
        # Well-known HMAC-SHA256 value for empty string with key "key"
        expected = "5d5d139563c95b5967b9bd9a8c9b233a9dedb45072794cd232dc1b74832607d0"
        assert HMAC(key).hexdigest(b"") == expected


class TestHMACStream:
    def test_streaming_matches_in_memory(self):
        from src.mac.hmac import HMACStream
        key = b"secret"
        data = b"A" * 1000

        # In memory
        expected = HMAC(key).hexdigest(data)

        # Streaming
        streamer = HMACStream(key)
        for i in range(0, len(data), 7):
            streamer.update(data[i:i + 7])

        assert streamer.hexdigest() == expected