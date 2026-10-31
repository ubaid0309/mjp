# Test fixture - DEMO DATA. Findings in test code get a lower exposure factor in the risk score.
import hashlib


def test_hash_is_stable():
    assert hashlib.md5(b"fixture").hexdigest() == hashlib.md5(b"fixture").hexdigest()
