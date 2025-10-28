"""
Idempotent Payment API

A FastAPI-based payment processing system that implements idempotency keys
to ensure safe retry of payment operations without duplicate processing.
"""

from fastapi import FastAPI, HTTPException, Header, status
from pydantic import BaseModel, Field, validator
from typing import Optional, Dict, Any, Literal
from enum import Enum
import uuid
import asyncio
from datetime import datetime, timedelta
import threading
import time
import logging
from contextlib import contextmanager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Idempotent Payment API",
    description="Payment processing API with idempotency key support",
    version="1.0.0"
)


class PaymentStatus(str, Enum):
    """Payment status enumeration"""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class RequestStatus(str, Enum):
    """Request processing status enumeration"""
    PROCESSING = "processing"
    COMPLETED = "completed"
    ERROR = "error"


class PaymentRequest(BaseModel):
    """Payment request model with validation"""
    amount: float = Field(..., gt=0, description="Payment amount (must be positive)")
    currency: str = Field(..., min_length=3, max_length=3, description="Currency code (ISO 4217)")
    recipient: str = Field(..., min_length=1, description="Payment recipient identifier")
    reference: str = Field(..., min_length=1, description="Payment reference")

    @validator('currency')
    def validate_currency(cls, v):
        """Validate currency code format"""
        return v.upper()

    @validator('amount')
    def validate_amount(cls, v):
        """Validate amount precision (max 2 decimal places)"""
        if round(v, 2) != v:
            raise ValueError('Amount must have at most 2 decimal places')
        return v


class PaymentResponse(BaseModel):
    """Payment response model"""
    transaction_id: str = Field(..., description="Unique transaction identifier")
    status: PaymentStatus = Field(..., description="Payment status")
    amount: float = Field(..., description="Payment amount")
    currency: str = Field(..., description="Currency code")
    timestamp: datetime = Field(..., description="Transaction timestamp")

class IdempotencyRecord(BaseModel):
    """Model for idempotency record storage"""
    request: PaymentRequest
    response: Optional[Any] = None
    status: RequestStatus
    created_at: datetime
    expires_at: datetime


class IdempotencyStore:
    """
    Thread-safe storage for idempotency keys with automatic expiration.
    
    This class manages the storage and retrieval of payment requests and responses
    associated with idempotency keys, ensuring thread safety through per-key locking.
    """
    
    def __init__(self, expiry_hours: int = 24):
        """
        Initialize the idempotency store.
        
        Args:
            expiry_hours: Number of hours after which keys expire (default: 24)
        """
        self._store: Dict[str, IdempotencyRecord] = {}
        self._locks: Dict[str, threading.Lock] = {}
        self._global_lock = threading.Lock()
        self._expiry_time = timedelta(hours=expiry_hours)
        logger.info(f"IdempotencyStore initialized with {expiry_hours}h expiry")
    
    @contextmanager
    def _get_key_lock(self, key: str):
        """
        Context manager for key-specific locking.
        
        Args:
            key: The idempotency key to lock
            
        Yields:
            threading.Lock: The lock for the specified key
        """
        # Use global lock to safely create/access key-specific locks
        with self._global_lock:
            if key not in self._locks:
                self._locks[key] = threading.Lock()
            key_lock = self._locks[key]
        
        # Use the key-specific lock
        with key_lock:
            yield key_lock
    
    def store_request(self, key: str, request: PaymentRequest) -> None:
        """
        Store a new payment request with processing status.
        
        Args:
            key: Unique idempotency key
            request: Payment request to store
            
        Raises:
            ValueError: If key already exists
        """
        with self._get_key_lock(key):
            if key in self._store:
                raise ValueError(f"Idempotency key '{key}' already exists")
            
            now = datetime.now()
            record = IdempotencyRecord(
                request=request,
                status=RequestStatus.PROCESSING,
                created_at=now,
                expires_at=now + self._expiry_time
            )
            self._store[key] = record
            logger.info(f"Stored new request for key: {key}")
    
    def store_response(self, key: str, response: PaymentResponse) -> None:
        """
        Store the successful response for a completed request.
        
        Args:
            key: Idempotency key
            response: Payment response to store
            
        Raises:
            KeyError: If key doesn't exist
        """
        with self._get_key_lock(key):
            if key not in self._store:
                raise KeyError(f"Idempotency key '{key}' not found")
            
            self._store[key].response = response
            self._store[key].status = RequestStatus.COMPLETED
            logger.info(f"Stored response for key: {key}")
    
    def store_error(self, key: str, error_detail: str) -> None:
        """
        Store an error response for a failed request.
        
        Args:
            key: Idempotency key
            error_detail: Error message to store
            
        Raises:
            KeyError: If key doesn't exist
        """
        with self._get_key_lock(key):
            if key not in self._store:
                raise KeyError(f"Idempotency key '{key}' not found")
            
            self._store[key].response = {"detail": error_detail}
            self._store[key].status = RequestStatus.ERROR
            logger.info(f"Stored error for key: {key}")
    
    def get(self, key: str) -> Optional[IdempotencyRecord]:
        """
        Retrieve stored data for an idempotency key.
        
        Args:
            key: Idempotency key to lookup
            
        Returns:
            IdempotencyRecord if found and not expired, None otherwise
        """
        # Clean expired keys periodically
        self._clean_expired()
        
        with self._get_key_lock(key):
            record = self._store.get(key)
            if record and record.expires_at < datetime.now():
                # Key expired, remove it
                del self._store[key]
                return None
            return record
    
    def _clean_expired(self) -> None:
        """
        Remove expired keys from storage.
        
        This method is called periodically to clean up expired entries.
        """
        current_time = datetime.now()
        expired_keys = []
        
        # First pass: identify expired keys (minimize lock time)
        with self._global_lock:
            for key, record in self._store.items():
                if record.expires_at < current_time:
                    expired_keys.append(key)
        
        # Second pass: remove expired keys
        for key in expired_keys:
            with self._get_key_lock(key):
                # Double-check expiration under lock
                if key in self._store and self._store[key].expires_at < current_time:
                    del self._store[key]
                    logger.debug(f"Cleaned expired key: {key}")
        
        # Clean up unused locks
        if expired_keys:
            with self._global_lock:
                for key in expired_keys:
                    if key in self._locks and key not in self._store:
                        del self._locks[key]
            
            if expired_keys:
                logger.info(f"Cleaned {len(expired_keys)} expired keys")
    
    def get_stats(self) -> Dict[str, int]:
        """
        Get storage statistics.
        
        Returns:
            Dictionary with storage statistics
        """
        with self._global_lock:
            total_keys = len(self._store)
            processing_count = sum(1 for r in self._store.values() 
                                 if r.status == RequestStatus.PROCESSING)
            completed_count = sum(1 for r in self._store.values() 
                                if r.status == RequestStatus.COMPLETED)
            error_count = sum(1 for r in self._store.values() 
                            if r.status == RequestStatus.ERROR)
            
        return {
            "total_keys": total_keys,
            "processing": processing_count,
            "completed": completed_count,
            "errors": error_count
        }

# Global store instance
idempotency_store = IdempotencyStore()


class PaymentProcessor:
    """
    Payment processing service with error simulation capabilities.
    
    In a real implementation, this would integrate with actual payment gateways.
    """
    
    def __init__(self, failure_rate: float = 0.0):
        """
        Initialize payment processor.
        
        Args:
            failure_rate: Probability of payment failure (0.0 to 1.0) for testing
        """
        self.failure_rate = failure_rate
    
    async def process_payment(self, request: PaymentRequest) -> PaymentResponse:
        """
        Process a payment request asynchronously.
        
        Args:
            request: Payment request to process
            
        Returns:
            PaymentResponse: Successful payment response
            
        Raises:
            HTTPException: If payment processing fails
        """
        logger.info(f"Processing payment: {request.amount} {request.currency} to {request.recipient}")
        
        # Simulate processing time (network latency, validation, etc.)
        await asyncio.sleep(0.1)
        
        # Simulate payment failure for testing
        import random
        if random.random() < self.failure_rate:
            error_msg = f"Payment failed for amount {request.amount} {request.currency}"
            logger.error(error_msg)
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail=error_msg
            )
        
        # Generate unique transaction ID
        transaction_id = str(uuid.uuid4())
        
        # Create successful response
        response = PaymentResponse(
            transaction_id=transaction_id,
            status=PaymentStatus.COMPLETED,
            amount=request.amount,
            currency=request.currency,
            timestamp=datetime.now()
        )
        
        logger.info(f"Payment completed: {transaction_id}")
        return response


# Global payment processor instance
payment_processor = PaymentProcessor()

# 
# Main payment endpoint with idempotency key support.
# 
# This endpoint processes payment requests while ensuring idempotency through
# the use of idempotency keys. It handles concurrent requests, caches responses,
# and provides appropriate error handling for various failure scenarios.
#
@app.post(
    "/payments",
    response_model=PaymentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Process Payment",
    description="Process a payment with idempotency key support",
    responses={
        201: {"description": "Payment processed successfully"},
        400: {"description": "Bad request - invalid parameters or missing idempotency key"},
        402: {"description": "Payment required - payment processing failed"},
        422: {"description": "Unprocessable entity - idempotency key conflict"},
        429: {"description": "Too many requests - rate limit exceeded"}
    }
)
async def create_payment(
    request: PaymentRequest,
    idempotency_key: Optional[str] = Header(
        None, 
        alias="Idempotency-Key",
        description="Unique key to ensure idempotent payment processing"
    )
) -> PaymentResponse:
    """
    Process a payment request with idempotency guarantees.
    
    Args:
        request: Payment request containing amount, currency, recipient, and reference
        idempotency_key: Unique key to prevent duplicate payment processing
        
    Returns:
        PaymentResponse: Payment result with transaction ID and status
        
    Raises:
        HTTPException: Various HTTP errors for different failure scenarios
    """
    # Validate idempotency key presence
    if not idempotency_key:
        logger.warning("Payment request missing idempotency key")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Idempotency-Key header is required for payment processing"
        )
    
    # Validate idempotency key format (basic validation)
    if len(idempotency_key.strip()) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Idempotency-Key cannot be empty"
        )
    
    logger.info(f"Processing payment request with key: {idempotency_key}")
    
    # Check for existing request with this key
    stored_record = idempotency_store.get(idempotency_key)
    
    if stored_record:
        # Verify request consistency
        if stored_record.request.dict() != request.dict():
            logger.warning(f"Idempotency key conflict for key: {idempotency_key}")
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Idempotency key reused with different request parameters"
            )
        
        # Handle different stored states
        if stored_record.status == RequestStatus.PROCESSING:
            # Wait for processing to complete with timeout
            max_wait_time = 30.0  # 30 seconds timeout
            wait_interval = 0.1   # 100ms polling interval
            total_waited = 0.0
            
            logger.info(f"Waiting for concurrent processing to complete: {idempotency_key}")
            
            while stored_record.status == RequestStatus.PROCESSING and total_waited < max_wait_time:
                await asyncio.sleep(wait_interval)
                total_waited += wait_interval
                stored_record = idempotency_store.get(idempotency_key)
                
                if not stored_record:
                    # Record was cleaned up, break and reprocess
                    break
            
            # Check if we timed out
            if stored_record and stored_record.status == RequestStatus.PROCESSING:
                logger.error(f"Timeout waiting for processing: {idempotency_key}")
                raise HTTPException(
                    status_code=status.HTTP_408_REQUEST_TIMEOUT,
                    detail="Request processing timeout - please retry"
                )
        
        # Return cached response if available
        if stored_record and stored_record.response:
            if stored_record.status == RequestStatus.ERROR:
                # Re-raise stored error
                error_detail = stored_record.response.get("detail", "Unknown error")
                logger.info(f"Returning cached error for key: {idempotency_key}")
                raise HTTPException(
                    status_code=status.HTTP_402_PAYMENT_REQUIRED,
                    detail=error_detail
                )
            elif stored_record.status == RequestStatus.COMPLETED:
                # Return successful cached response
                logger.info(f"Returning cached response for key: {idempotency_key}")
                return stored_record.response
    
    # Process new request
    try:
        # Store the request as processing
        idempotency_store.store_request(idempotency_key, request)
        
        # Process the payment
        response = await payment_processor.process_payment(request)
        
        # Store successful response
        idempotency_store.store_response(idempotency_key, response)
        
        logger.info(f"Payment processed successfully: {response.transaction_id}")
        return response
        
    except HTTPException:
        # Re-raise HTTP exceptions (from payment processor)
        raise
    except ValueError as e:
        # Handle idempotency store errors
        logger.error(f"Idempotency store error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Concurrent request processing conflict: {str(e)}"
        )
    except Exception as e:
        # Handle unexpected errors
        error_msg = f"Payment processing failed: {str(e)}"
        logger.error(error_msg)
        
        # Store error in idempotency store
        try:
            idempotency_store.store_error(idempotency_key, str(e))
        except Exception as store_error:
            logger.error(f"Failed to store error: {store_error}")
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during payment processing"
        )


# 
# Health check endpoint for monitoring and load balancer health checks.
#
@app.get("/health", summary="Health Check")
async def health_check():
    """
    Health check endpoint.
    
    Returns:
        dict: Service health status and statistics
    """
    stats = idempotency_store.get_stats()
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "idempotency_store": stats
    }

# 
# Comprehensive test suite for the idempotent payment API.
# 
# These tests verify all aspects of idempotency behavior including
# successful payments, error handling, concurrent requests, and edge cases.
#
if __name__ == "__main__":
    import pytest
    import requests
    from fastapi.testclient import TestClient
    import threading
    
    client = TestClient(app)
    
    def test_successful_payment():
        """Test successful payment with idempotency key"""
        key = str(uuid.uuid4())
        request_data = {
            "amount": 100.50,
            "currency": "USD",
            "recipient": "test@example.com",
            "reference": "test-123"
        }
        
        # First request
        response1 = client.post(
            "/payments",
            json=request_data,
            headers={"Idempotency-Key": key}
        )
        assert response1.status_code == 201  # Updated to match new status code
        data1 = response1.json()
        transaction_id = data1["transaction_id"]
        assert data1["status"] == "completed"
        assert data1["amount"] == 100.50
        assert data1["currency"] == "USD"
        
        # Second request with same key should return cached response
        response2 = client.post(
            "/payments",
            json=request_data,
            headers={"Idempotency-Key": key}
        )
        assert response2.status_code == 201
        data2 = response2.json()
        assert data2["transaction_id"] == transaction_id
        assert data2 == data1  # Exact same response
    
    def test_different_requests_same_key():
        """Test error when same key is used with different requests"""
        key = str(uuid.uuid4())
        request1 = {
            "amount": 100.0,
            "currency": "USD",
            "recipient": "test1@example.com",
            "reference": "test-123"
        }
        request2 = {
            "amount": 200.0,  # Different amount
            "currency": "USD",
            "recipient": "test1@example.com",
            "reference": "test-123"
        }
        
        # First request
        response1 = client.post(
            "/payments",
            json=request1,
            headers={"Idempotency-Key": key}
        )
        assert response1.status_code == 201
        
        # Second request with same key but different data should fail
        response2 = client.post(
            "/payments",
            json=request2,
            headers={"Idempotency-Key": key}
        )
        assert response2.status_code == 422
        assert "different request parameters" in response2.json()["detail"]
    
    def test_concurrent_requests():
        """Test handling of concurrent requests with same idempotency key"""
        
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
    
    def test_missing_idempotency_key():
        """Test error when idempotency key is missing"""
        request_data = {
            "amount": 100.0,
            "currency": "USD",
            "recipient": "test@example.com",
            "reference": "test-123"
        }
        
        response = client.post("/payments", json=request_data)
        assert response.status_code == 400
    
    def test_key_expiration():
        """Test that keys expire after the specified time"""
        # Create a store with short expiration for testing
        test_store = IdempotencyStore(expiry_hours=0)  # 0 hours for testing
        test_store._expiry_time = timedelta(seconds=1)  # 1 second expiration
        
        key = str(uuid.uuid4())
        request = PaymentRequest(
            amount=100.0,
            currency="USD",
            recipient="test@example.com",
            reference="test-123"
        )
        
        # Store request
        test_store.store_request(key, request)
        
        # Verify it's stored
        assert test_store.get(key) is not None
        
        # Wait for expiration
        time.sleep(1.1)
        
        # Verify it's expired
        assert test_store.get(key) is None
    
    # Run all tests
    test_successful_payment()
    print("✓ Test successful payment passed")
    
    test_different_requests_same_key()
    print("✓ Test different requests with same key passed")
    
    test_concurrent_requests()
    print("✓ Test concurrent requests passed")
    
    test_missing_idempotency_key()
    print("✓ Test missing idempotency key passed")
    
    test_key_expiration()
    print("✓ Test key expiration passed")
    
    print("\nAll tests passed! 🎉")