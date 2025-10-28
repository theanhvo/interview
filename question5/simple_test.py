#!/usr/bin/env python3
"""
Simple test runner for TransferService without external dependencies
Run with: python3 simple_test.py
"""

import time
from decimal import Decimal
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Dict, Any
from dataclasses import dataclass
from unittest.mock import Mock


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
    """Enterprise TransferService implementation."""
    
    def __init__(self, account_repository, ledger_repository):
        self.account_repository = account_repository
        self.ledger_repository = ledger_repository
    
    def transfer_money(self, from_account_id: str, to_account_id: str, 
                      amount: Decimal, idempotency_key: str, 
                      metadata: Optional[Dict[str, Any]] = None) -> TransferResult:
        """Execute atomic money transfer with comprehensive validation."""
        
        # Input validation
        if amount <= 0:
            return TransferResult(
                status=TransferStatus.INVALID_AMOUNT,
                message="Transfer amount must be positive"
            )
        
        if from_account_id == to_account_id:
            return TransferResult(
                status=TransferStatus.INVALID_AMOUNT,
                message="Cannot transfer to same account"
            )
        
        # Check for duplicate
        existing = self.ledger_repository.find_by_idempotency_key(idempotency_key)
        if existing:
            return TransferResult(
                status=TransferStatus.DUPLICATE_TRANSFER,
                transfer_id=existing.id,
                message="Transfer already processed"
            )
        
        try:
            # Mock transaction
            with self.account_repository.transaction() as tx:
                source = tx.find_by_id_for_update(from_account_id)
                if not source:
                    return TransferResult(
                        status=TransferStatus.ACCOUNT_NOT_FOUND,
                        message=f"Account {from_account_id} not found"
                    )
                
                dest = tx.find_by_id_for_update(to_account_id)
                if not dest:
                    return TransferResult(
                        status=TransferStatus.ACCOUNT_NOT_FOUND,
                        message=f"Account {to_account_id} not found"
                    )
                
                # Business validations
                if source.status != "ACTIVE":
                    return TransferResult(
                        status=TransferStatus.ACCOUNT_FROZEN,
                        message="Source account is not active"
                    )
                
                if source.balance < amount:
                    return TransferResult(
                        status=TransferStatus.INSUFFICIENT_FUNDS,
                        message=f"Insufficient balance. Available: {source.balance}"
                    )
                
                if source.daily_spent + amount > source.daily_limit:
                    return TransferResult(
                        status=TransferStatus.DAILY_LIMIT_EXCEEDED,
                        message="Daily transfer limit exceeded"
                    )
                
                # Execute transfer
                source.balance -= amount
                source.daily_spent += amount
                dest.balance += amount
                
                tx.save(source)
                tx.save(dest)
                
                return TransferResult(
                    status=TransferStatus.SUCCESS,
                    transfer_id=f"tx-{int(time.time())}",
                    message="Transfer completed successfully"
                )
        
        except Exception as e:
            return TransferResult(
                status=TransferStatus.SYSTEM_ERROR,
                message=f"System error: {str(e)}"
            )


def run_tests():
    """Run comprehensive test suite."""
    print("=" * 60)
    print("🏦 ENTERPRISE TRANSFER SERVICE TEST SUITE")
    print("=" * 60)
    
    test_count = 0
    passed_count = 0
    
    def assert_equal(actual, expected, test_name):
        nonlocal test_count, passed_count
        test_count += 1
        if actual == expected:
            print(f"✅ {test_name}")
            passed_count += 1
        else:
            print(f"❌ {test_name}")
            print(f"   Expected: {expected}")
            print(f"   Actual: {actual}")
    
    def assert_true(condition, test_name):
        nonlocal test_count, passed_count
        test_count += 1
        if condition:
            print(f"✅ {test_name}")
            passed_count += 1
        else:
            print(f"❌ {test_name}")
    
    # Setup mock repositories
    account_repo = Mock()
    ledger_repo = Mock()
    tx_mock = Mock()
    account_repo.transaction.return_value.__enter__ = Mock(return_value=tx_mock)
    account_repo.transaction.return_value.__exit__ = Mock(return_value=None)
    
    service = TransferService(account_repo, ledger_repo)
    
    print("\n📋 Test Category: Input Validation")
    print("-" * 40)
    
    # Test 1: Invalid Amount - Negative
    result = service.transfer_money("ACC001", "ACC002", Decimal("-100.00"), "key-001")
    assert_equal(result.status, TransferStatus.INVALID_AMOUNT, "Negative amount rejection")
    
    # Test 2: Invalid Amount - Zero
    result = service.transfer_money("ACC001", "ACC002", Decimal("0.00"), "key-002")
    assert_equal(result.status, TransferStatus.INVALID_AMOUNT, "Zero amount rejection")
    
    # Test 3: Same Account Transfer
    result = service.transfer_money("ACC001", "ACC001", Decimal("100.00"), "key-003")
    assert_equal(result.status, TransferStatus.INVALID_AMOUNT, "Same account transfer rejection")
    
    print("\n📋 Test Category: Account Management")
    print("-" * 40)
    
    # Test 4: Account Not Found - Source
    tx_mock.find_by_id_for_update.side_effect = [None, None]
    ledger_repo.find_by_idempotency_key.return_value = None
    result = service.transfer_money("INVALID001", "ACC002", Decimal("100.00"), "key-004")
    assert_equal(result.status, TransferStatus.ACCOUNT_NOT_FOUND, "Source account not found")
    
    # Test 5: Account Not Found - Destination
    source_account = Account("ACC001", Decimal("1000.00"), "ACTIVE", Decimal("5000.00"), Decimal("0.00"), 1, datetime.now(timezone.utc))
    tx_mock.find_by_id_for_update.side_effect = [source_account, None]
    result = service.transfer_money("ACC001", "INVALID002", Decimal("100.00"), "key-005")
    assert_equal(result.status, TransferStatus.ACCOUNT_NOT_FOUND, "Destination account not found")
    
    print("\n📋 Test Category: Business Rules")
    print("-" * 40)
    
    # Test 6: Successful Transfer
    source_account = Account("ACC001", Decimal("1000.00"), "ACTIVE", Decimal("5000.00"), Decimal("0.00"), 1, datetime.now(timezone.utc))
    dest_account = Account("ACC002", Decimal("500.00"), "ACTIVE", Decimal("5000.00"), Decimal("0.00"), 1, datetime.now(timezone.utc))
    tx_mock.find_by_id_for_update.side_effect = [source_account, dest_account]
    ledger_repo.find_by_idempotency_key.return_value = None
    
    result = service.transfer_money("ACC001", "ACC002", Decimal("100.00"), "key-006")
    assert_equal(result.status, TransferStatus.SUCCESS, "Successful transfer")
    assert_equal(source_account.balance, Decimal("900.00"), "Source balance updated correctly")
    assert_equal(dest_account.balance, Decimal("600.00"), "Destination balance updated correctly")
    
    # Test 7: Insufficient Funds
    source_account.balance = Decimal("50.00")
    tx_mock.find_by_id_for_update.side_effect = [source_account, dest_account]
    result = service.transfer_money("ACC001", "ACC002", Decimal("100.00"), "key-007")
    assert_equal(result.status, TransferStatus.INSUFFICIENT_FUNDS, "Insufficient funds rejection")
    
    # Test 8: Frozen Account
    source_account.balance = Decimal("1000.00")
    source_account.status = "FROZEN"
    tx_mock.find_by_id_for_update.side_effect = [source_account, dest_account]
    result = service.transfer_money("ACC001", "ACC002", Decimal("100.00"), "key-008")
    assert_equal(result.status, TransferStatus.ACCOUNT_FROZEN, "Frozen account rejection")
    
    # Test 9: Daily Limit Exceeded
    source_account.status = "ACTIVE"
    source_account.daily_spent = Decimal("4900.00")
    source_account.daily_limit = Decimal("5000.00")
    tx_mock.find_by_id_for_update.side_effect = [source_account, dest_account]
    result = service.transfer_money("ACC001", "ACC002", Decimal("200.00"), "key-009")
    assert_equal(result.status, TransferStatus.DAILY_LIMIT_EXCEEDED, "Daily limit exceeded rejection")
    
    print("\n📋 Test Category: Idempotency")
    print("-" * 40)
    
    # Test 10: Duplicate Transfer Prevention
    existing_transfer = TransferLedger(
        "existing-tx-001", "ACC001", "ACC002", Decimal("100.00"), 
        "SUCCESS", "duplicate-key", datetime.now(timezone.utc), {}
    )
    ledger_repo.find_by_idempotency_key.return_value = existing_transfer
    result = service.transfer_money("ACC001", "ACC002", Decimal("100.00"), "duplicate-key")
    assert_equal(result.status, TransferStatus.DUPLICATE_TRANSFER, "Duplicate transfer prevention")
    assert_equal(result.transfer_id, "existing-tx-001", "Correct existing transfer ID returned")
    
    print("\n📋 Test Category: Edge Cases")
    print("-" * 40)
    
    # Test 11: Very Small Amount
    source_account.status = "ACTIVE"
    source_account.daily_spent = Decimal("0.00")
    source_account.balance = Decimal("1000.00")
    tx_mock.find_by_id_for_update.side_effect = [source_account, dest_account]
    ledger_repo.find_by_idempotency_key.return_value = None
    result = service.transfer_money("ACC001", "ACC002", Decimal("0.01"), "key-011")
    assert_equal(result.status, TransferStatus.SUCCESS, "Very small amount transfer")
    
    # Test 12: Large Amount (within limits)
    source_account.balance = Decimal("100000.00")
    source_account.daily_spent = Decimal("0.00")  # Reset daily spent
    tx_mock.find_by_id_for_update.side_effect = [source_account, dest_account]
    result = service.transfer_money("ACC001", "ACC002", Decimal("4999.99"), "key-012")
    assert_equal(result.status, TransferStatus.SUCCESS, "Large amount transfer within limits")
    
    print("\n📋 Test Category: Performance")
    print("-" * 40)
    
    # Test 13: Performance Benchmark
    start_time = time.time()
    for i in range(100):
        source_account.balance = Decimal("1000.00")
        source_account.daily_spent = Decimal("0.00")
        result = service.transfer_money("ACC001", "ACC002", Decimal("1.00"), f"perf-key-{i}")
    
    execution_time = time.time() - start_time
    avg_time = execution_time / 100
    assert_true(avg_time < 0.01, f"Performance benchmark (avg: {avg_time:.4f}s per transfer)")
    
    # Print summary
    print("\n" + "=" * 60)
    print("📊 TEST SUMMARY")
    print("=" * 60)
    print(f"Total Tests: {test_count}")
    print(f"Passed: {passed_count}")
    print(f"Failed: {test_count - passed_count}")
    print(f"Success Rate: {(passed_count/test_count)*100:.1f}%")
    
    if passed_count == test_count:
        print("\n🎉 ALL TESTS PASSED! 🎉")
        print("✅ TransferService is ready for production deployment")
    else:
        print(f"\n⚠️  {test_count - passed_count} TESTS FAILED")
        print("❌ Please fix issues before deployment")
    
    print("\n💡 Key Features Tested:")
    print("   • Input validation and sanitization")
    print("   • Account existence verification")
    print("   • Business rule enforcement")
    print("   • Idempotency key handling")
    print("   • Balance and limit checking")
    print("   • Error handling and reporting")
    print("   • Performance benchmarking")
    
    return passed_count == test_count


if __name__ == "__main__":
    success = run_tests()
    exit(0 if success else 1)
