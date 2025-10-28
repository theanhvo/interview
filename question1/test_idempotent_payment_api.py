import pytest
import httpx
import asyncio
import time
import uuid
from fastapi.testclient import TestClient
from idempotent_payment_api import app, idempotency_store, PaymentRequest

# Test client setup
client = TestClient(app)

# Test data
TEST_PAYMENT = {
    "amount": 100.0,
    "currency": "USD",
    "recipient": "merchant1",
    "reference": "test-payment-001"
}
IDEMPOTENCY_KEY = "idempotency_key"
IDEMPOTENCY_HEADER = {"Idempotency-Key": IDEMPOTENCY_KEY}

@pytest.fixture(autouse=True)
def clear_store():
    """Clear the idempotency store before each test"""
    with idempotency_store._global_lock:
        idempotency_store._store.clear()
        idempotency_store._locks.clear()

def test_create_payment():
    """Test creating a new payment"""
    response = client.post(
        "/payments",
        json=TEST_PAYMENT,
        headers=IDEMPOTENCY_HEADER
    )
    assert response.status_code == 201
    assert response.json()["status"] == "completed"
    assert response.json()["amount"] == TEST_PAYMENT["amount"]
    assert response.json()["currency"] == TEST_PAYMENT["currency"]
    assert "transaction_id" in response.json()

def test_idempotent_request():
    """Test idempotency with same key and same request"""
    # First request
    response1 = client.post(
        "/payments",
        json=TEST_PAYMENT,
        headers=IDEMPOTENCY_HEADER
    )
    assert response1.status_code == 201
    
    # Second request with same key
    response2 = client.post(
        "/payments",
        json=TEST_PAYMENT,
        headers=IDEMPOTENCY_HEADER
    )
    assert response2.status_code == 201
    assert response1.json() == response2.json()  # Same response

def test_idempotent_different_request():
    """Test idempotency key reuse with different request parameters"""
    # First request
    client.post(
        "/payments",
        json=TEST_PAYMENT,
        headers=IDEMPOTENCY_HEADER
    )
    
    # Second request with different parameters
    different_payment = TEST_PAYMENT.copy()
    different_payment["amount"] = 200.0
    response = client.post(
        "/payments",
        json=different_payment,
        headers=IDEMPOTENCY_HEADER
    )
    assert response.status_code == 422
    assert "different request parameters" in response.json()["detail"]

def test_concurrent_requests():
    """Test concurrent requests with same idempotency key"""
    import threading
    
    key = str(uuid.uuid4())
    request_data = {
        "amount": 100.0,
        "currency": "USD",
        "recipient": "test@example.com",
        "reference": "test-123"
    }
    
    results = []
    errors = []
    
    def make_request():
        try:
            response = client.post(
                "/payments",
                json=request_data,
                headers={"Idempotency-Key": key}
            )
            results.append(response.json()["transaction_id"])
        except Exception as e:
            errors.append(str(e))
    
    # Create multiple threads
    threads = []
    for _ in range(5):
        thread = threading.Thread(target=make_request)
        threads.append(thread)
        thread.start()
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    
    # All responses should have the same transaction ID
    assert len(set(results)) == 1, "All requests should return the same transaction ID"
    assert len(results) == 5, "All requests should complete successfully"
    assert len(errors) == 0, "No requests should fail"

def test_expiration():
    """Test idempotency key expiration"""
    # Create a test store with short expiration
    from idempotent_payment_api import IdempotencyStore
    from datetime import timedelta
    
    test_store = IdempotencyStore(expiry_hours=0)  # 0 hours for testing
    test_store._expiry_time = timedelta(seconds=1)  # 1 second expiration
    
    # Temporarily replace the global store
    original_store = idempotency_store
    import idempotent_payment_api
    idempotent_payment_api.idempotency_store = test_store

    try:
        # Make first request
        response1 = client.post(
            "/payments",
            json=TEST_PAYMENT,
            headers=IDEMPOTENCY_HEADER
        )
        assert response1.status_code == 201
        first_transaction_id = response1.json()["transaction_id"]
        
        # Wait for expiration
        time.sleep(1.5)  # Wait for key to expire
        
        # Make second request with same key - should create new transaction
        response2 = client.post(
            "/payments",
            json=TEST_PAYMENT,
            headers=IDEMPOTENCY_HEADER
        )
        assert response2.status_code == 201
        second_transaction_id = response2.json()["transaction_id"]
        assert second_transaction_id != first_transaction_id, "Expired key should allow new transaction"
        
    finally:
        # Restore original store
        idempotent_payment_api.idempotency_store = original_store

def test_missing_idempotency_key():
    """Test request without idempotency key"""
    response = client.post(
        "/payments",
        json=TEST_PAYMENT
    )
    assert response.status_code == 400