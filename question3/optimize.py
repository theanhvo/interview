import logging
import time
import uuid
import hashlib
import json
from decimal import Decimal
from typing import Protocol, Optional, Dict, Any
from enum import Enum
from datetime import datetime, timedelta
from threading import Lock

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

STRIPE_TX_PREFIX = "stripe-tx"
MOMO_TX_PREFIX = "momo-tx"
CAKE_TX_PREFIX = "cake-tx"


class PaymentStatus(Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    REFUNDED = "refunded"


class PaymentProcessingError(Exception):
    def __init__(self, message: str, error_code: str = None):
        super().__init__(message)
        self.error_code = error_code


class EmailSendingError(Exception):
    def __init__(self, message: str, error_code: str = None):
        super().__init__(message)
        self.error_code = error_code


class ValidationError(Exception):
    def __init__(self, message: str, field: str = None):
        super().__init__(message)
        self.field = field


class DuplicateTransactionError(Exception):
    def __init__(self, message: str, idempotency_key: str, original_tx_id: str):
        super().__init__(message)
        self.idempotency_key = idempotency_key
        self.original_tx_id = original_tx_id


class PaymentProcessor(Protocol):
    def process_payment(self, amount: Decimal, card_number: str, idempotency_key: str) -> str: ...


class StripePaymentProcessor:
    def __init__(self, api_key: str = "sk_test_123"):
        self.api_key = api_key
        
    def process_payment(self, amount: Decimal, card_number: str, idempotency_key: str) -> str:
        try:
            masked_card = f"****-****-****-{card_number[-4:]}"
            logger.info(f"Connecting to Stripe API...")
            logger.info(f"Processing payment of ${amount} with card {masked_card}")
            logger.info(f"Using idempotency key: {idempotency_key}")
            
            # In a real implementation, we would pass the idempotency key to Stripe API
            # stripe.PaymentIntent.create(amount=amount, currency="usd", idempotency_key=idempotency_key)
            
            # Generate unique transaction ID that includes amount to ensure different transactions get different IDs
            # This is just for testing - in production, the payment gateway would generate the ID
            amount_str = str(amount).replace('.', '')
            return f"{STRIPE_TX_PREFIX}-{amount_str}-{int(time.time())}"
        except Exception as e:
            raise PaymentProcessingError(f"Error processing payment: {str(e)}")


class EmailSender:
    def send_confirmation(self, email: str, tx_id: str, amount: Decimal) -> None:
        try:
            logger.info(f"Sending payment confirmation email to {email}")
        except Exception as e:
            raise EmailSendingError(f"Error sending email: {str(e)}")


class IdempotencyStore:
    """Thread-safe storage for idempotency keys with automatic expiration."""
    
    def __init__(self, expiry_hours: int = 24):
        self._store: Dict[str, Dict[str, Any]] = {}
        self._lock = Lock()
        self._expiry_time = timedelta(hours=expiry_hours)
        logger.info(f"IdempotencyStore initialized with {expiry_hours}h expiry")
    
    def store_transaction(self, key: str, tx_id: str) -> None:
        """Store transaction ID with idempotency key"""
        with self._lock:
            self._store[key] = {
                "tx_id": tx_id,
                "created_at": datetime.now(),
                "expires_at": datetime.now() + self._expiry_time
            }
            logger.info(f"Stored transaction {tx_id} with idempotency key: {key}")
    
    def get_transaction(self, key: str) -> Optional[str]:
        """Get transaction ID for idempotency key if exists and not expired"""
        with self._lock:
            record = self._store.get(key)
            if not record:
                return None
                
            if record["expires_at"] < datetime.now():
                # Key expired, remove it
                del self._store[key]
                logger.info(f"Idempotency key expired: {key}")
                return None
                
            logger.info(f"Found existing transaction for key {key}: {record['tx_id']}")
            return record["tx_id"]


class TransactionService:
    def __init__(self, payment_processor: PaymentProcessor, email_sender: EmailSender):
        self.payment_processor = payment_processor
        self.email_sender = email_sender
        self.idempotency_store = IdempotencyStore()

    def _generate_idempotency_key(self, amount: Decimal, card_number: str, email: str) -> str:
        """Generate deterministic idempotency key from transaction parameters"""
        # Create a string representation of the transaction details
        tx_data = f"{amount}:{card_number[-4:]}:{email}:{datetime.now().strftime('%Y-%m-%d')}"
        # Generate SHA-256 hash
        return hashlib.sha256(tx_data.encode()).hexdigest()

    def process_transaction(self, amount: Decimal, card_number: str, email: str, 
                           idempotency_key: str = None) -> str:
        """Process transaction with idempotency guarantee to prevent double charges."""
        # Generate idempotency key if not provided
        if not idempotency_key:
            idempotency_key = self._generate_idempotency_key(amount, card_number, email)
            logger.info(f"Generated idempotency key: {idempotency_key}")
        
        # Check for existing transaction with this key
        existing_tx_id = self.idempotency_store.get_transaction(idempotency_key)
        if existing_tx_id:
            logger.info(f"Returning cached transaction: {existing_tx_id}")
            return existing_tx_id
        
        # Process new transaction
        tx_id = self.payment_processor.process_payment(amount, card_number, idempotency_key)
        
        # Store in idempotency store
        self.idempotency_store.store_transaction(idempotency_key, tx_id)
        
        # Send confirmation email
        self.email_sender.send_confirmation(email, tx_id, amount)
        
        return tx_id


def main():
    payment_processor = StripePaymentProcessor()
    email_sender = EmailSender()
    service = TransactionService(payment_processor, email_sender)
    
    # Test case 1: First transaction
    try:
        tx_id1 = service.process_transaction(
            Decimal("85.88"), "8923-5678-8302-1923", "customer@example.com"
        )
        logger.info(f"First transaction completed successfully: {tx_id1}")
        
        # Test case 2: Duplicate transaction with same parameters (should return same tx_id)
        tx_id2 = service.process_transaction(
            Decimal("85.88"), "8923-5678-8302-1923", "customer@example.com"
        )
        logger.info(f"Second transaction completed successfully: {tx_id2}")
        assert tx_id1 == tx_id2, "Idempotency key not working - different transaction IDs returned"
        logger.info("✅ Idempotency check passed - same transaction ID returned")
        
        # Test case 3: Different parameters should generate different idempotency key
        tx_id3 = service.process_transaction(
            Decimal("100.00"), "8923-5678-8302-1923", "customer@example.com"
        )
        logger.info(f"Third transaction (different amount) completed successfully: {tx_id3}")
        assert tx_id1 != tx_id3, "Different transactions should have different IDs"
        logger.info("✅ Different transaction parameters generated different IDs")
        
        # Verify the transaction IDs contain the correct amounts
        assert "8588" in tx_id1, f"First transaction ID should contain amount 85.88: {tx_id1}"
        assert "10000" in tx_id3, f"Third transaction ID should contain amount 100.00: {tx_id3}"
        logger.info("✅ Transaction IDs correctly include amount information")
        
    except (PaymentProcessingError, EmailSendingError, ValueError, DuplicateTransactionError) as e:
        logger.error(f"Transaction failed: {e}")
    except AssertionError as e:
        logger.error(f"Test failed: {e}")
        
    # Test case 4: Explicit idempotency key
    try:
        custom_key = "custom-idempotency-key-123"
        tx_id4 = service.process_transaction(
            Decimal("50.00"), "1234-5678-9012-3456", "new@example.com", 
            idempotency_key=custom_key
        )
        logger.info(f"Transaction with custom key completed: {tx_id4}")
        
        # Should return same ID when using same custom key
        tx_id5 = service.process_transaction(
            Decimal("50.00"), "1234-5678-9012-3456", "new@example.com", 
            idempotency_key=custom_key
        )
        assert tx_id4 == tx_id5, "Custom idempotency key not working"
        logger.info("✅ Custom idempotency key test passed")
        
    except (PaymentProcessingError, EmailSendingError, ValueError) as e:
        logger.error(f"Custom key transaction failed: {e}")
    except AssertionError as e:
        logger.error(f"Custom key test failed: {e}")


if __name__ == "__main__":
    main()
