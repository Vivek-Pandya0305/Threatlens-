import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.main import normalize

def test_ipv4():
    assert normalize("198.51.100.10")[1] == "ipv4"

def test_domain_lowercase():
    assert normalize("EXAMPLE.TEST", "domain")[0] == "example.test"

def test_url_strips_fragment():
    assert normalize("https://Example.test/path#frag", "url")[0] == "https://example.test/path"

def test_hash():
    assert normalize("a"*64, "sha256")[1] == "sha256"
