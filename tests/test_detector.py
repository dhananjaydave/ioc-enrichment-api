import pytest

from ioc_enrichment.detector import detect_type, hash_algorithm


@pytest.mark.parametrize(
    "indicator,expected",
    [
        ("8.8.8.8", "ip"),
        ("2001:4860:4860::8888", "ip"),
        ("example.com", "domain"),
        ("sub.example.co.uk", "domain"),
        ("https://example.com/path?x=1", "url"),
        ("http://example.com", "url"),
        ("5d41402abc4b2a76b9719d911017c592", "hash"),  # md5
        ("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", "hash"),  # sha1
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "hash"),  # sha256
    ],
)
def test_detect_type(indicator, expected):
    assert detect_type(indicator) == expected


def test_detect_type_rejects_garbage():
    with pytest.raises(ValueError):
        detect_type("not a real indicator !!!")


def test_hash_algorithm():
    assert hash_algorithm("5d41402abc4b2a76b9719d911017c592") == "md5"
    assert hash_algorithm("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d") == "sha1"
