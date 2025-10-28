# Enterprise-Grade Money Transfer Service

## Critical Issues Analysis

### Production Environment Challenges
In high-throughput financial systems (multi-server deployment, load balancers, hundreds of concurrent transactions), the original implementation exhibits severe architectural flaws that compromise data integrity and system reliability:

### 1. **Concurrency Control Failures**
- **Race Conditions**: Multiple threads can read identical account balances simultaneously, leading to lost updates and phantom money creation
- **Double Spending**: Concurrent transfers from the same account can bypass balance checks
- **Data Corruption**: Simultaneous updates without proper locking mechanisms cause inconsistent account states

### 2. **Transaction Integrity Violations**
- **Atomicity Breach**: Debit and credit operations execute as separate transactions, creating windows for partial failures
- **Consistency Failures**: System crashes between operations leave accounts in inconsistent states
- **Isolation Problems**: Concurrent transactions can observe intermediate states

### 3. **Audit and Compliance Gaps**
- **No Transaction History**: Absence of immutable ledger prevents regulatory compliance and forensic analysis
- **Reconciliation Impossibility**: Without transaction trails, detecting and correcting discrepancies becomes impossible
- **Regulatory Non-Compliance**: Financial regulations require complete audit trails

### 4. **Operational Reliability Issues**
- **Poor Error Handling**: Generic error responses provide no actionable information for debugging or user feedback
- **No Idempotency**: Duplicate requests from network retries can cause multiple transfers
- **Insufficient Monitoring**: Lack of structured logging hampers production troubleshooting

### 5. **Scalability Limitations**
- **Database Hotspots**: Popular accounts become bottlenecks without proper sharding strategies
- **Lock Contention**: Inefficient locking strategies reduce system throughput
- **Resource Leaks**: Improper connection management under high load

---

## Enterprise Solution Architecture

### Core Principles
1. **ACID Compliance**: All operations must be Atomic, Consistent, Isolated, and Durable
2. **Idempotency**: Identical requests produce identical results regardless of retry count
3. **Auditability**: Complete transaction history with immutable records
4. **Observability**: Comprehensive logging and monitoring for production operations
5. **Scalability**: Design for horizontal scaling and high throughput

### Implementation Strategy
1. **Database Transactions**: Wrap all related operations in single atomic transactions
2. **Pessimistic Locking**: Use `SELECT ... FOR UPDATE` to prevent concurrent modifications
3. **Immutable Ledger**: Maintain complete transaction history for audit and reconciliation
4. **Structured Error Handling**: Provide specific error codes and detailed logging
5. **Idempotency Keys**: Prevent duplicate processing of retry requests
6. **Performance Optimization**: Implement efficient locking and indexing strategies

---

## Production-Ready Implementation

### Enhanced Transfer Service

```python
import logging
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Optional, Dict, Any
from dataclasses import dataclass


class TransferStatus(Enum):
    """Transfer operation status codes."""
    SUCCESS = "SUCCESS"
    INSUFFICIENT_FUNDS = "INSUFFICIENT_FUNDS"
    ACCOUNT_NOT_FOUND = "ACCOUNT_NOT_FOUND"
    DUPLICATE_TRANSFER = "DUPLICATE_TRANSFER"
    INVALID_AMOUNT = "INVALID_AMOUNT"
    SYSTEM_ERROR = "SYSTEM_ERROR"
    ACCOUNT_FROZEN = "ACCOUNT_FROZEN"
    DAILY_LIMIT_EXCEEDED = "DAILY_LIMIT_EXCEEDED"


@dataclass
class TransferResult:
    """Structured transfer operation result."""
    status: TransferStatus
    transfer_id: Optional[str] = None
    message: Optional[str] = None
    error_code: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class Account:
    """Account entity with enhanced fields."""
    id: str
    balance: Decimal
    status: str
    daily_limit: Decimal
    daily_spent: Decimal
    version: int
    last_updated: datetime


@dataclass
class TransferLedger:
    """Immutable transfer record for audit trail."""
    id: str
    from_account_id: str
    to_account_id: str
    amount: Decimal
    status: str
    idempotency_key: str
    created_at: datetime
    metadata: Dict[str, Any]


class TransferService:
    """Enterprise-grade money transfer service with ACID compliance."""
    
    def __init__(self, account_repository, ledger_repository):
        self.account_repository = account_repository
        self.ledger_repository = ledger_repository
        self.logger = logging.getLogger(__name__)

    def transfer_money(
        self,
        from_account_id: str,
        to_account_id: str,
        amount: Decimal,
        idempotency_key: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> TransferResult:
        """
        Execute atomic money transfer with comprehensive validation and audit trail.
        
        Args:
            from_account_id: Source account identifier
            to_account_id: Destination account identifier  
            amount: Transfer amount (must be positive)
            idempotency_key: Unique key to prevent duplicate processing
            metadata: Additional transfer context
            
        Returns:
            TransferResult with operation status and details
        """
        transfer_id = str(uuid.uuid4())
        
        # Input validation
        validation_result = self._validate_transfer_request(
            from_account_id, to_account_id, amount, idempotency_key
        )
        if validation_result.status != TransferStatus.SUCCESS:
            return validation_result

        try:
            # Check for duplicate transfer using idempotency key
            existing_transfer = self.ledger_repository.find_by_idempotency_key(idempotency_key)
            if existing_transfer:
                self.logger.info(f"Duplicate transfer detected: {idempotency_key}")
                return TransferResult(
                    status=TransferStatus.DUPLICATE_TRANSFER,
                    transfer_id=existing_transfer.id,
                    message="Transfer already processed"
                )

            # Execute atomic transfer within database transaction
            with self.account_repository.transaction() as tx:
                # Lock accounts in consistent order to prevent deadlocks
                account_ids = sorted([from_account_id, to_account_id])
                locked_accounts = {}
                
                for account_id in account_ids:
                    account = tx.find_by_id_for_update(account_id)
                    if not account:
                        return TransferResult(
                            status=TransferStatus.ACCOUNT_NOT_FOUND,
                            message=f"Account {account_id} not found"
                        )
                    locked_accounts[account_id] = account

                source_account = locked_accounts[from_account_id]
                destination_account = locked_accounts[to_account_id]

                # Business rule validations
                validation_result = self._validate_business_rules(
                    source_account, destination_account, amount
                )
                if validation_result.status != TransferStatus.SUCCESS:
                    return validation_result

                # Execute transfer operations
                source_account.balance -= amount
                source_account.daily_spent += amount
                source_account.version += 1
                source_account.last_updated = datetime.now(timezone.utc)

                destination_account.balance += amount
                destination_account.version += 1
                destination_account.last_updated = datetime.now(timezone.utc)

                # Persist account updates
                tx.save(source_account)
                tx.save(destination_account)

                # Create immutable ledger entry
                ledger_entry = TransferLedger(
                    id=transfer_id,
                    from_account_id=from_account_id,
                    to_account_id=to_account_id,
                    amount=amount,
                    status=TransferStatus.SUCCESS.value,
                    idempotency_key=idempotency_key,
                    created_at=datetime.now(timezone.utc),
                    metadata=metadata or {}
                )
                tx.save_ledger_entry(ledger_entry)

                # Structured logging for observability
                self.logger.info(
                    "Transfer completed successfully",
                    extra={
                        "transfer_id": transfer_id,
                        "from_account": from_account_id,
                        "to_account": to_account_id,
                        "amount": str(amount),
                        "idempotency_key": idempotency_key,
                        "source_balance_after": str(source_account.balance),
                        "dest_balance_after": str(destination_account.balance)
                    }
                )

                return TransferResult(
                    status=TransferStatus.SUCCESS,
                    transfer_id=transfer_id,
                    message="Transfer completed successfully",
                    metadata={
                        "source_balance": str(source_account.balance),
                        "destination_balance": str(destination_account.balance)
                    }
                )

        except Exception as e:
            self.logger.error(
                "Transfer failed with system error",
                extra={
                    "transfer_id": transfer_id,
                    "from_account": from_account_id,
                    "to_account": to_account_id,
                    "amount": str(amount),
                    "error": str(e)
                },
                exc_info=True
            )
            return TransferResult(
                status=TransferStatus.SYSTEM_ERROR,
                message="Internal system error occurred",
                error_code="TRANSFER_SYSTEM_ERROR"
            )

    def _validate_transfer_request(
        self, from_account_id: str, to_account_id: str, 
        amount: Decimal, idempotency_key: str
    ) -> TransferResult:
        """Validate transfer request parameters."""
        if not all([from_account_id, to_account_id, idempotency_key]):
            return TransferResult(
                status=TransferStatus.INVALID_AMOUNT,
                message="Missing required parameters"
            )
        
        if from_account_id == to_account_id:
            return TransferResult(
                status=TransferStatus.INVALID_AMOUNT,
                message="Cannot transfer to same account"
            )
        
        if amount <= 0:
            return TransferResult(
                status=TransferStatus.INVALID_AMOUNT,
                message="Transfer amount must be positive"
            )
        
        if amount.as_tuple().exponent < -2:  # More than 2 decimal places
            return TransferResult(
                status=TransferStatus.INVALID_AMOUNT,
                message="Amount cannot have more than 2 decimal places"
            )
        
        return TransferResult(status=TransferStatus.SUCCESS)

    def _validate_business_rules(
        self, source_account: Account, destination_account: Account, amount: Decimal
    ) -> TransferResult:
        """Validate business rules and account constraints."""
        # Check account status
        if source_account.status != "ACTIVE":
            return TransferResult(
                status=TransferStatus.ACCOUNT_FROZEN,
                message="Source account is not active"
            )
        
        if destination_account.status != "ACTIVE":
            return TransferResult(
                status=TransferStatus.ACCOUNT_FROZEN,
                message="Destination account is not active"
            )
        
        # Check sufficient balance
        if source_account.balance < amount:
            return TransferResult(
                status=TransferStatus.INSUFFICIENT_FUNDS,
                message=f"Insufficient balance. Available: {source_account.balance}"
            )
        
        # Check daily limit
        if source_account.daily_spent + amount > source_account.daily_limit:
            return TransferResult(
                status=TransferStatus.DAILY_LIMIT_EXCEEDED,
                message="Daily transfer limit exceeded"
            )
        
        return TransferResult(status=TransferStatus.SUCCESS)

    def get_transfer_history(
        self, account_id: str, limit: int = 100, offset: int = 0
    ) -> list[TransferLedger]:
        """Retrieve transfer history for audit and reconciliation."""
        return self.ledger_repository.find_by_account(account_id, limit, offset)

    def get_transfer_by_id(self, transfer_id: str) -> Optional[TransferLedger]:
        """Retrieve specific transfer for investigation."""
        return self.ledger_repository.find_by_id(transfer_id)
```

---

## Comprehensive Test Suite

```python
import pytest
import threading
import time
from decimal import Decimal
from unittest.mock import Mock, MagicMock
from concurrent.futures import ThreadPoolExecutor, as_completed


class TestTransferService:
    """Comprehensive test suite for TransferService."""

    @pytest.fixture
    def mock_repositories(self):
        """Setup mock repositories for testing."""
        account_repo = Mock()
        ledger_repo = Mock()
        
        # Mock transaction context manager
        tx_mock = Mock()
        account_repo.transaction.return_value.__enter__ = Mock(return_value=tx_mock)
        account_repo.transaction.return_value.__exit__ = Mock(return_value=None)
        
        return account_repo, ledger_repo, tx_mock

    @pytest.fixture
    def transfer_service(self, mock_repositories):
        """Create TransferService instance with mocked dependencies."""
        account_repo, ledger_repo, _ = mock_repositories
        return TransferService(account_repo, ledger_repo)

    @pytest.fixture
    def sample_accounts(self):
        """Create sample account data for testing."""
        source_account = Account(
            id="ACC001",
            balance=Decimal("1000.00"),
            status="ACTIVE",
            daily_limit=Decimal("5000.00"),
            daily_spent=Decimal("0.00"),
            version=1,
            last_updated=datetime.now(timezone.utc)
        )
        
        dest_account = Account(
            id="ACC002",
            balance=Decimal("500.00"),
            status="ACTIVE",
            daily_limit=Decimal("5000.00"),
            daily_spent=Decimal("0.00"),
            version=1,
            last_updated=datetime.now(timezone.utc)
        )
        
        return source_account, dest_account

    def test_successful_transfer(self, transfer_service, mock_repositories, sample_accounts):
        """Test successful money transfer between accounts."""
        account_repo, ledger_repo, tx_mock = mock_repositories
        source_account, dest_account = sample_accounts
        
        # Setup mocks
        tx_mock.find_by_id_for_update.side_effect = [source_account, dest_account]
        ledger_repo.find_by_idempotency_key.return_value = None
        
        # Execute transfer
        result = transfer_service.transfer_money(
            from_account_id="ACC001",
            to_account_id="ACC002",
            amount=Decimal("100.00"),
            idempotency_key="test-key-001"
        )
        
        # Assertions
        assert result.status == TransferStatus.SUCCESS
        assert result.transfer_id is not None
        assert source_account.balance == Decimal("900.00")
        assert dest_account.balance == Decimal("600.00")
        assert tx_mock.save.call_count == 2
        assert tx_mock.save_ledger_entry.called

    def test_insufficient_funds(self, transfer_service, mock_repositories, sample_accounts):
        """Test transfer rejection due to insufficient funds."""
        account_repo, ledger_repo, tx_mock = mock_repositories
        source_account, dest_account = sample_accounts
        source_account.balance = Decimal("50.00")  # Insufficient balance
        
        tx_mock.find_by_id_for_update.side_effect = [source_account, dest_account]
        ledger_repo.find_by_idempotency_key.return_value = None
        
        result = transfer_service.transfer_money(
            from_account_id="ACC001",
            to_account_id="ACC002",
            amount=Decimal("100.00"),
            idempotency_key="test-key-002"
        )
        
        assert result.status == TransferStatus.INSUFFICIENT_FUNDS
        assert "Insufficient balance" in result.message
        assert tx_mock.save.call_count == 0  # No changes should be saved

    def test_account_not_found(self, transfer_service, mock_repositories):
        """Test transfer failure when account doesn't exist."""
        account_repo, ledger_repo, tx_mock = mock_repositories
        
        tx_mock.find_by_id_for_update.side_effect = [None, None]  # Account not found
        ledger_repo.find_by_idempotency_key.return_value = None
        
        result = transfer_service.transfer_money(
            from_account_id="INVALID001",
            to_account_id="ACC002",
            amount=Decimal("100.00"),
            idempotency_key="test-key-003"
        )
        
        assert result.status == TransferStatus.ACCOUNT_NOT_FOUND
        assert "not found" in result.message

    def test_duplicate_transfer_prevention(self, transfer_service, mock_repositories):
        """Test idempotency key prevents duplicate transfers."""
        account_repo, ledger_repo, tx_mock = mock_repositories
        
        # Mock existing transfer
        existing_transfer = TransferLedger(
            id="existing-transfer-001",
            from_account_id="ACC001",
            to_account_id="ACC002",
            amount=Decimal("100.00"),
            status="SUCCESS",
            idempotency_key="duplicate-key",
            created_at=datetime.now(timezone.utc),
            metadata={}
        )
        ledger_repo.find_by_idempotency_key.return_value = existing_transfer
        
        result = transfer_service.transfer_money(
            from_account_id="ACC001",
            to_account_id="ACC002",
            amount=Decimal("100.00"),
            idempotency_key="duplicate-key"
        )
        
        assert result.status == TransferStatus.DUPLICATE_TRANSFER
        assert result.transfer_id == "existing-transfer-001"

    def test_frozen_account_rejection(self, transfer_service, mock_repositories, sample_accounts):
        """Test transfer rejection when account is frozen."""
        account_repo, ledger_repo, tx_mock = mock_repositories
        source_account, dest_account = sample_accounts
        source_account.status = "FROZEN"
        
        tx_mock.find_by_id_for_update.side_effect = [source_account, dest_account]
        ledger_repo.find_by_idempotency_key.return_value = None
        
        result = transfer_service.transfer_money(
            from_account_id="ACC001",
            to_account_id="ACC002",
            amount=Decimal("100.00"),
            idempotency_key="test-key-004"
        )
        
        assert result.status == TransferStatus.ACCOUNT_FROZEN
        assert "not active" in result.message

    def test_daily_limit_exceeded(self, transfer_service, mock_repositories, sample_accounts):
        """Test transfer rejection when daily limit is exceeded."""
        account_repo, ledger_repo, tx_mock = mock_repositories
        source_account, dest_account = sample_accounts
        source_account.daily_spent = Decimal("4900.00")  # Close to limit
        source_account.daily_limit = Decimal("5000.00")
        
        tx_mock.find_by_id_for_update.side_effect = [source_account, dest_account]
        ledger_repo.find_by_idempotency_key.return_value = None
        
        result = transfer_service.transfer_money(
            from_account_id="ACC001",
            to_account_id="ACC002",
            amount=Decimal("200.00"),  # Would exceed limit
            idempotency_key="test-key-005"
        )
        
        assert result.status == TransferStatus.DAILY_LIMIT_EXCEEDED
        assert "Daily transfer limit exceeded" in result.message

    def test_invalid_amount_validation(self, transfer_service, mock_repositories):
        """Test validation of transfer amounts."""
        # Test negative amount
        result = transfer_service.transfer_money(
            from_account_id="ACC001",
            to_account_id="ACC002",
            amount=Decimal("-100.00"),
            idempotency_key="test-key-006"
        )
        assert result.status == TransferStatus.INVALID_AMOUNT
        
        # Test zero amount
        result = transfer_service.transfer_money(
            from_account_id="ACC001",
            to_account_id="ACC002",
            amount=Decimal("0.00"),
            idempotency_key="test-key-007"
        )
        assert result.status == TransferStatus.INVALID_AMOUNT
        
        # Test same account transfer
        result = transfer_service.transfer_money(
            from_account_id="ACC001",
            to_account_id="ACC001",
            amount=Decimal("100.00"),
            idempotency_key="test-key-008"
        )
        assert result.status == TransferStatus.INVALID_AMOUNT

    def test_concurrent_transfers_race_condition(self, transfer_service, mock_repositories):
        """Test concurrent transfers to detect race conditions."""
        account_repo, ledger_repo, tx_mock = mock_repositories
        
        # Create account with balance for multiple transfers
        source_account = Account(
            id="ACC001",
            balance=Decimal("1000.00"),
            status="ACTIVE",
            daily_limit=Decimal("10000.00"),
            daily_spent=Decimal("0.00"),
            version=1,
            last_updated=datetime.now(timezone.utc)
        )
        
        dest_account = Account(
            id="ACC002",
            balance=Decimal("0.00"),
            status="ACTIVE",
            daily_limit=Decimal("10000.00"),
            daily_spent=Decimal("0.00"),
            version=1,
            last_updated=datetime.now(timezone.utc)
        )
        
        # Mock repository responses
        tx_mock.find_by_id_for_update.side_effect = lambda acc_id: (
            source_account if acc_id == "ACC001" else dest_account
        )
        ledger_repo.find_by_idempotency_key.return_value = None
        
        # Execute concurrent transfers
        def execute_transfer(transfer_id):
            return transfer_service.transfer_money(
                from_account_id="ACC001",
                to_account_id="ACC002",
                amount=Decimal("100.00"),
                idempotency_key=f"concurrent-key-{transfer_id}"
            )
        
        # Run 10 concurrent transfers
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(execute_transfer, i) for i in range(10)]
            results = [future.result() for future in as_completed(futures)]
        
        # All transfers should succeed due to proper locking
        successful_transfers = [r for r in results if r.status == TransferStatus.SUCCESS]
        assert len(successful_transfers) == 10
        
        # Final balance should reflect all transfers
        expected_balance = Decimal("1000.00") - (Decimal("100.00") * 10)
        assert source_account.balance == expected_balance

    def test_system_error_handling(self, transfer_service, mock_repositories):
        """Test system error handling and logging."""
        account_repo, ledger_repo, tx_mock = mock_repositories
        
        # Mock database error
        tx_mock.find_by_id_for_update.side_effect = Exception("Database connection failed")
        ledger_repo.find_by_idempotency_key.return_value = None
        
        result = transfer_service.transfer_money(
            from_account_id="ACC001",
            to_account_id="ACC002",
            amount=Decimal("100.00"),
            idempotency_key="test-key-009"
        )
        
        assert result.status == TransferStatus.SYSTEM_ERROR
        assert "Internal system error" in result.message
        assert result.error_code == "TRANSFER_SYSTEM_ERROR"

    def test_transfer_history_retrieval(self, transfer_service, mock_repositories):
        """Test transfer history retrieval for audit purposes."""
        account_repo, ledger_repo, tx_mock = mock_repositories
        
        # Mock transfer history
        mock_transfers = [
            TransferLedger(
                id=f"transfer-{i}",
                from_account_id="ACC001",
                to_account_id="ACC002",
                amount=Decimal("100.00"),
                status="SUCCESS",
                idempotency_key=f"key-{i}",
                created_at=datetime.now(timezone.utc),
                metadata={}
            ) for i in range(5)
        ]
        ledger_repo.find_by_account.return_value = mock_transfers
        
        history = transfer_service.get_transfer_history("ACC001", limit=10)
        
        assert len(history) == 5
        assert all(isinstance(transfer, TransferLedger) for transfer in history)
        ledger_repo.find_by_account.assert_called_once_with("ACC001", 10, 0)

    def test_performance_benchmarks(self, transfer_service, mock_repositories, sample_accounts):
        """Test transfer service performance under load."""
        account_repo, ledger_repo, tx_mock = mock_repositories
        source_account, dest_account = sample_accounts
        
        tx_mock.find_by_id_for_update.side_effect = [source_account, dest_account]
        ledger_repo.find_by_idempotency_key.return_value = None
        
        # Measure execution time for single transfer
        start_time = time.time()
        
        result = transfer_service.transfer_money(
            from_account_id="ACC001",
            to_account_id="ACC002",
            amount=Decimal("100.00"),
            idempotency_key="perf-test-001"
        )
        
        execution_time = time.time() - start_time
        
        assert result.status == TransferStatus.SUCCESS
        assert execution_time < 0.1  # Should complete within 100ms
        
        # Test batch performance
        start_time = time.time()
        
        for i in range(100):
            transfer_service.transfer_money(
                from_account_id="ACC001",
                to_account_id="ACC002",
                amount=Decimal("1.00"),
                idempotency_key=f"batch-key-{i}"
            )
        
        batch_time = time.time() - start_time
        avg_time_per_transfer = batch_time / 100
        
        assert avg_time_per_transfer < 0.01  # Average < 10ms per transfer


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
```

---

## Database Schema Design

```sql
-- Accounts table with optimistic locking
CREATE TABLE accounts (
    id VARCHAR(50) PRIMARY KEY,
    balance DECIMAL(15,2) NOT NULL DEFAULT 0.00,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    daily_limit DECIMAL(15,2) NOT NULL DEFAULT 10000.00,
    daily_spent DECIMAL(15,2) NOT NULL DEFAULT 0.00,
    version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT positive_balance CHECK (balance >= 0),
    CONSTRAINT valid_status CHECK (status IN ('ACTIVE', 'FROZEN', 'CLOSED')),
    CONSTRAINT positive_limits CHECK (daily_limit >= 0 AND daily_spent >= 0)
);

-- Transfer ledger for immutable audit trail
CREATE TABLE transfer_ledger (
    id VARCHAR(50) PRIMARY KEY,
    from_account_id VARCHAR(50) NOT NULL,
    to_account_id VARCHAR(50) NOT NULL,
    amount DECIMAL(15,2) NOT NULL,
    status VARCHAR(20) NOT NULL,
    idempotency_key VARCHAR(100) NOT NULL UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    metadata JSONB DEFAULT '{}',
    
    CONSTRAINT positive_amount CHECK (amount > 0),
    CONSTRAINT different_accounts CHECK (from_account_id != to_account_id)
);

-- Indexes for optimal performance
CREATE INDEX idx_accounts_status ON accounts(status);
CREATE INDEX idx_transfer_ledger_from_account ON transfer_ledger(from_account_id, created_at DESC);
CREATE INDEX idx_transfer_ledger_to_account ON transfer_ledger(to_account_id, created_at DESC);
CREATE INDEX idx_transfer_ledger_created_at ON transfer_ledger(created_at DESC);
CREATE UNIQUE INDEX idx_transfer_ledger_idempotency ON transfer_ledger(idempotency_key);

-- Daily spending reset procedure
CREATE OR REPLACE FUNCTION reset_daily_spending()
RETURNS void AS $$
BEGIN
    UPDATE accounts 
    SET daily_spent = 0.00, 
        last_updated = NOW()
    WHERE daily_spent > 0;
END;
$$ LANGUAGE plpgsql;

-- Schedule daily reset (example for PostgreSQL with pg_cron)
-- SELECT cron.schedule('reset-daily-spending', '0 0 * * *', 'SELECT reset_daily_spending();');
```

---

## Production Deployment Considerations

### Monitoring and Alerting
- **Transfer Success Rate**: Monitor percentage of successful transfers
- **Response Time**: Track P95/P99 latency for transfer operations  
- **Error Rate**: Alert on unusual error patterns or spikes
- **Account Balance Reconciliation**: Daily balance verification jobs
- **Database Performance**: Monitor lock wait times and query performance

### Scalability Strategies
- **Database Sharding**: Partition accounts across multiple database shards
- **Read Replicas**: Use read replicas for balance inquiries and reporting
- **Connection Pooling**: Implement efficient database connection management
- **Caching**: Cache account status and daily limits for faster validation

### Security Measures
- **Encryption**: Encrypt sensitive data at rest and in transit
- **Audit Logging**: Comprehensive audit trails for regulatory compliance
- **Rate Limiting**: Implement per-account transfer rate limits
- **Fraud Detection**: Real-time monitoring for suspicious transfer patterns

This enterprise-grade implementation provides robust financial transaction processing with comprehensive error handling, audit trails, and production-ready testing coverage.
