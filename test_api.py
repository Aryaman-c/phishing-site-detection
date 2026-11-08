import os
import sys
from app import app, URLRequest, predict_url, health_check

def test_endpoints():
    print("Testing FastAPI Backend Endpoints...")
    
    # 1. Test Health endpoint
    health_coro = health_check()
    try:
        health_coro.send(None)
    except StopIteration as e:
        health_res = e.value
    print("1. Health Endpoint Check:", health_res)
    assert health_res["status"] == "healthy"
    assert health_res["model"] == "RandomForestClassifier"

    # 2. Test Safe URL Prediction
    safe_req = URLRequest(url="https://www.google.com")
    coro_safe = predict_url(safe_req)
    try:
        coro_safe.send(None)
    except StopIteration as e:
        safe_res = e.value
    print("\n2. Safe URL Result:", safe_res)
    assert safe_res.prediction == "safe"
    assert safe_res.is_phishing is False
    assert safe_res.confidence >= 90.0
    assert safe_res.latency_ms < 50.0

    # 3. Test Phishing URL Prediction
    phish_url = "http://paypal-verification.account-security-alert.xyz/update-login.php?user=1"
    phish_req = URLRequest(url=phish_url)
    coro_phish = predict_url(phish_req)
    try:
        coro_phish.send(None)
    except StopIteration as e:
        phish_res = e.value
    print("\n3. Phishing URL Result:", phish_res)
    assert phish_res.prediction == "phishing"
    assert phish_res.is_phishing is True
    assert phish_res.confidence >= 90.0
    assert phish_res.latency_ms < 50.0

    print("\nAll FastAPI inference tests PASSED successfully (latency < 50ms verified)!")

if __name__ == '__main__':
    test_endpoints()
