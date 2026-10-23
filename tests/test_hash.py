import pytest
from src.hash import get_hasher


class TestSHA256:
    def test_empty_string(self):
        h = get_hasher("sha256")
        assert h.hexdigest() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_abc(self):
        h = get_hasher("sha256")
        h.update(b"abc")
        assert h.hexdigest() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    def test_long_nist_vector(self):
        msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        h = get_hasher("sha256")
        h.update(msg)
        assert h.hexdigest() == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"

    def test_chunked_input(self):
        data = b"a" * 1000
        h1 = get_hasher("sha256")
        h1.update(data)
        h2 = get_hasher("sha256")
        for i in range(0, len(data), 7):
            h2.update(data[i:i+7])
        assert h1.hexdigest() == h2.hexdigest()

    def test_avalanche_effect(self):
        h1 = get_hasher("sha256")
        h1.update(b"Hello, world!")
        h2 = get_hasher("sha256")
        h2.update(b"Hello, world?")  # 1 bit changed (last char)

        bin1 = bin(int(h1.hexdigest(), 16))[2:].zfill(256)
        bin2 = bin(int(h2.hexdigest(), 16))[2:].zfill(256)
        diff = sum(a != b for a, b in zip(bin1, bin2))
        assert 100 < diff < 156, f"Avalanche effect weak: {diff} bits changed"


class TestSHA3_256:
    def test_empty_string(self):
        h = get_hasher("sha3-256")
        assert h.hexdigest() == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"

    def test_abc(self):
        h = get_hasher("sha3-256")
        h.update(b"abc")
        assert h.hexdigest() == "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"


class TestRegistry:
    def test_unknown_algorithm(self):
        with pytest.raises(ValueError):
            get_hasher("md5")