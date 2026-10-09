import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import pytest
from analyzer import analyze_url

def test_normal_https():
    assert analyze_url("https://example.com/page")["risk_category"] == "Low Risk"
def test_normal_http():
    assert analyze_url("http://example.com")["risk_score"] == 5
@pytest.mark.parametrize("u", ["", "http://", "javascript:alert(1)", "file:///etc/passwd",
                               "data:text/html,x", "chrome://settings", "http://[bad"])
def test_rejected(u):
    with pytest.raises(ValueError): analyze_url(u)
def test_misleading_subdomain():
    assert analyze_url("https://paypal.secure-login.example.com/")["risk_score"] >= 25
def test_userinfo():
    assert analyze_url("https://paypal.com@evil.example/")["risk_score"] >= 25
def test_ip():
    assert analyze_url("http://192.168.0.1:8080/")["risk_score"] >= 45
def test_encoding():
    r = analyze_url("https://example.com/%252e%252e/a")
    assert any("encoded" in f["text"] for f in r["findings"])
def test_never_claims_verified():
    assert analyze_url("https://example.com")["threat_intel"]["status"] == "not_configured"
