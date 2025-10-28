# Question 3


```python
import time

class StripePaymentProcessor:
    def process_stripe_payment(self, amount, card_number): 
        print(f"Connecting to Stripe API...") 
        print(f"Processing ${amount} payment with Stripe") 
        return f"stripe-tx-{int(time.time())}"

class EmailSender:
    def send_confirmation(self, email, tx_id, amount):
        print(f"Sending payment confirmation to {email}") 

class TransactionService:
    def __init__(self):
        self.stripe_processor = StripePaymentProcessor() 
        self.email_sender = EmailSender()

    def process_transaction(self, amount, card_number, email):
        tx_id = self.stripe_processor.process_stripe_payment(amount, card_number) 
        self.email_sender.send_confirmation(email, tx_id, amount)
        return tx_id

# Main Application
def main():
    service = TransactionService()
    tx_id = service.process_transaction(99.99, "dummy-number", "customer@example.com") 
    if __name__ == "__main__":
        main()
```

## Code Review Analysis

### **Critical Issue: Absence of Error Handling**
The most significant architectural flaw is the complete lack of error handling mechanisms. The current implementation assumes all operations (payment processing, email sending) will always succeed, which is unrealistic in production environments. Third-party APIs like Stripe can fail, network connectivity can be interrupted, or email servers may be unavailable.

### **Architectural Problem: Hard-coded Dependencies**
The `TransactionService` creates its own dependencies within the constructor, which creates several issues:
- **Testing Challenges**: Unable to mock dependencies for isolated unit testing
- **Implementation Flexibility**: Difficult to substitute Stripe with alternative payment providers
- **Configuration Management**: Cannot configure dependencies externally

### **SOLID Principle Violation: Tight Coupling**
The current design violates the **Open/Closed Principle**:
- Adding new payment providers (Momo, Cake, ZaloPay, VNPay) requires direct modification of `TransactionService`
- Switching from Stripe to another provider necessitates code changes
- System cannot be extended without modifying existing code

### **Security Risk: No Idempotency Protection**
The payment processing lacks idempotency protection, creating a serious risk of double charging customers:
- Network interruptions could lead to duplicate payment attempts
- Client retries could result in multiple charges for the same transaction
- No mechanism to identify and prevent duplicate payment processing

**Recommended Solution**: Implement **Dependency Injection**, **Interface/Protocol abstraction**, and **Idempotency Key Pattern** to decouple business logic from specific implementations and prevent duplicate transactions.

## Optimized Implementation

### **Key Improvements Implemented:**

1. **Comprehensive Error Handling**: Custom exceptions with proper try-catch blocks
2. **Dependency Injection**: Constructor injection replacing hard-coded dependencies
3. **Interface Segregation**: Protocol-based abstraction for PaymentProcessor
4. **Type Safety**: Decimal usage for monetary values with complete type annotations
5. **Security Enhancement**: Card number masking for sensitive data protection
6. **Professional Logging**: Structured logging replacing print statements
7. **Extensibility**: Easy integration of new payment providers without code modification
8. **Idempotency Implementation**: Protection against duplicate transactions using idempotency keys

```python
import logging
import time
import uuid
import hashlib
from decimal import Decimal
from typing import Protocol, Optional, Dict, Any
from datetime import datetime, timedelta
from threading import Lock

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

STRIPE_TX_PREFIX = "stripe-tx"


class PaymentProcessingError(Exception):
    def __init__(self, message: str, error_code: str = None):
        super().__init__(message)
        self.error_code = error_code


class EmailSendingError(Exception):
    def __init__(self, message: str, error_code: str = None):
        super().__init__(message)
        self.error_code = error_code


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
            
            return f"{STRIPE_TX_PREFIX}-{int(time.time())}"
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
    
    try:
        # First transaction
        tx_id1 = service.process_transaction(
            Decimal("85.88"), "8923-5678-8302-1923", "customer@example.com"
        )
        logger.info(f"Transaction completed successfully: {tx_id1}")
        
        # Duplicate transaction attempt (should return same tx_id)
        tx_id2 = service.process_transaction(
            Decimal("85.88"), "8923-5678-8302-1923", "customer@example.com"
        )
        logger.info(f"Duplicate transaction returned: {tx_id2}")
        
    except (PaymentProcessingError, EmailSendingError, ValueError) as e:
        logger.error(f"Transaction failed: {e}")


if __name__ == "__main__":
    main()
```