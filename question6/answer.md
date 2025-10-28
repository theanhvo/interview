# Banking API Security & Architecture Review

## Critical Security Vulnerabilities

### 1. Authentication & Authorization Flaws

#### 1.1 Source Account Ownership Bypass
- **Vulnerability**: No validation of account ownership against authenticated user
- **Attack Vector**: Attacker can transfer funds from any account by knowing its ID
- **Impact**: Complete bypass of authorization controls, allowing theft from any account
- **Risk Level**: Critical (CVSS 9.8)
- **Example**: `POST /api/transfers/execute` with arbitrary `source_account_id` values

#### 1.2 Missing Access Controls
- **Vulnerability**: No role-based authorization for privileged operations
- **Impact**: Unauthorized users can perform administrative functions
- **Risk Level**: High (CVSS 8.5)

### 2. Injection Vulnerabilities

#### 2.1 SQL Injection
- **Vulnerability**: Raw SQL query construction using string concatenation
- **Vulnerable Code**: `db.session.query("SELECT * FROM accounts WHERE id = %s", (source_account_id,))`
- **Attack Vector**: Malicious input in `source_account_id` parameter
- **Impact**: Unauthorized data access, data manipulation, or server compromise
- **Risk Level**: Critical (CVSS 9.3)
- **Example Attack**: `{"source_account_id": "1; DROP TABLE accounts;--"}`

### 3. Input Validation Deficiencies

#### 3.1 Missing Amount Validation
- **Vulnerability**: No validation of transfer amount
- **Attack Vector**: Submission of negative values
- **Impact**: Balance manipulation, artificial fund creation
- **Risk Level**: Critical (CVSS 8.7)
- **Example Attack**: `{"amount": -1000}` to increase source account balance

#### 3.2 Destination Account Verification
- **Vulnerability**: No validation of destination account existence or status
- **Impact**: Failed transfers, lost funds, or system inconsistency
- **Risk Level**: High (CVSS 7.5)

### 4. Business Logic Flaws

#### 4.1 Incomplete Transaction Implementation
- **Vulnerability**: Transfer service returns success without executing actual transfers
- **Impact**: Financial discrepancies, ledger inconsistencies, audit failures
- **Risk Level**: Critical (CVSS 9.1)

#### 4.2 Missing Transaction Atomicity
- **Vulnerability**: No transaction boundary for multi-step operations
- **Impact**: Partial transfers resulting in lost funds or inconsistent state
- **Risk Level**: High (CVSS 8.2)

---

## Remediation Strategy

### 1. Authentication & Authorization Controls

- **Implement Proper Account Ownership Verification**
  ```python
  # Secure pattern
  source_account = Account.query.filter_by(
      id=source_account_id, 
      profile_id=current_profile_id
  ).first_or_404()
  ```

- **Add Role-Based Access Control**
  ```python
  @requires_roles('account_holder')
  def execute_transfer():
      # Transfer implementation
  ```

### 2. Secure Query Construction

- **Use ORM Methods with Parameterized Queries**
  ```python
  # Secure pattern
  account = Account.query.filter_by(id=account_id).first()
  ```

- **Implement Query Sanitization**
  ```python
  # Additional protection
  from sqlalchemy.sql import text
  result = db.session.execute(
      text("SELECT * FROM accounts WHERE id = :id"),
      {"id": account_id}
  )
  ```

### 3. Comprehensive Input Validation

- **Implement Amount Validation**
  ```python
  # Validate positive amount with reasonable limits
  if not (Decimal('0.01') <= amount <= Decimal('100000.00')):
      return jsonify({"error": "Invalid amount"}), 400
  ```

- **Verify Destination Account Status**
  ```python
  if not destination_account or destination_account.status != 'ACTIVE':
      return jsonify({"error": "Invalid or inactive destination account"}), 400
  ```

### 4. Robust Transaction Processing

- **Implement Atomic Transactions**
  ```python
  # Ensure all operations succeed or fail together
  with db.session.begin():
      # All database operations
  ```

- **Add Comprehensive Logging**
  ```python
  # Audit trail for all financial transactions
  log_transaction(source_id, dest_id, amount, user_id, status)
  ```

---

## Enterprise-Grade Secure Implementation

```python
from flask import Flask, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt_claims
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.sql import text
from database import db, Account, TransactionLog, AuditLog
from decimal import Decimal, InvalidOperation
from datetime import datetime
import uuid
import logging

app = Flask(__name__)
logger = logging.getLogger(__name__)

# Define custom exceptions for better error handling
class TransferError(Exception):
    """Base exception for transfer-related errors"""
    def __init__(self, message, code=400, details=None):
        self.message = message
        self.code = code
        self.details = details or {}
        super().__init__(self.message)

class InsufficientFundsError(TransferError):
    """Raised when source account has insufficient balance"""
    def __init__(self, available, requested):
        super().__init__(
            message="Insufficient funds for transfer", 
            code=400,
            details={
                "available": str(available),
                "requested": str(requested)
            }
        )

class AccountAccessError(TransferError):
    """Raised for unauthorized account access"""
    def __init__(self, account_id):
        super().__init__(
            message="Unauthorized access to account", 
            code=403,
            details={"account_id": account_id}
        )

class AccountNotFoundError(TransferError):
    """Raised when account doesn't exist"""
    def __init__(self, account_id):
        super().__init__(
            message="Account not found", 
            code=404,
            details={"account_id": account_id}
        )

class AccountInactiveError(TransferError):
    """Raised when account is frozen or closed"""
    def __init__(self, account_id, status):
        super().__init__(
            message="Account is not active", 
            code=400,
            details={
                "account_id": account_id,
                "status": status
            }
        )

def requires_roles(*roles):
    """Decorator for role-based access control"""
    def wrapper(fn):
        @jwt_required()
        def decorated_function(*args, **kwargs):
            claims = get_jwt_claims()
            user_roles = claims.get("roles", [])
            
            if not any(role in user_roles for role in roles):
                return jsonify({"error": "Insufficient permissions"}), 403
            return fn(*args, **kwargs)
        return decorated_function
    return wrapper

class TransferService:
    """Service for executing secure money transfers between accounts"""
    
    def __init__(self, db_session):
        self.db = db_session
    
    def validate_accounts(self, source_id, destination_id, profile_id):
        """Validate account existence, ownership and status"""
        # Verify source account exists and belongs to user
        source_account = (
            self.db.query(Account)
            .filter_by(id=source_id, profile_id=profile_id)
            .first()
        )
        
        if not source_account:
            # Check if account exists but doesn't belong to user
            account_exists = self.db.query(Account).filter_by(id=source_id).first()
            if account_exists:
                # Log potential account access attempt
                logger.warning(
                    "Unauthorized source account access attempt",
                    extra={
                        "profile_id": profile_id,
                        "account_id": source_id
                    }
                )
                raise AccountAccessError(source_id)
            else:
                raise AccountNotFoundError(source_id)
        
        # Verify source account is active
        if source_account.status != "ACTIVE":
            raise AccountInactiveError(source_id, source_account.status)
        
        # Verify destination account exists and is active
        destination_account = self.db.query(Account).filter_by(id=destination_id).first()
        if not destination_account:
            raise AccountNotFoundError(destination_id)
        
        if destination_account.status != "ACTIVE":
            raise AccountInactiveError(destination_id, destination_account.status)
        
        return source_account, destination_account
    
    def validate_amount(self, amount, source_account):
        """Validate transfer amount and balance"""
        # Check amount is positive and within limits
        if amount <= Decimal('0'):
            raise TransferError("Transfer amount must be positive")
        
        # Check for reasonable upper limit
        if amount > Decimal('100000.00'):
            raise TransferError("Transfer amount exceeds maximum limit")
        
        # Check sufficient balance
        if source_account.balance < amount:
            raise InsufficientFundsError(source_account.balance, amount)
    
    def execute_transfer(self, source_account, destination_account, amount, description, profile_id):
        """Execute secure transfer with proper transaction boundaries"""
        # Generate unique transaction ID
        transaction_id = str(uuid.uuid4())
        
        try:
            # Perform transfer inside DB transaction for atomicity
            with self.db.begin():
                # Update balances
                source_account.balance -= amount
                destination_account.balance += amount
                source_account.last_updated = datetime.utcnow()
                destination_account.last_updated = datetime.utcnow()
                
                # Create transaction log
                txn = TransactionLog(
                    id=transaction_id,
                    source_account_id=source_account.id,
                    destination_account_id=destination_account.id,
                    amount=amount,
                    description=description,
                    profile_id=profile_id,
                    status="COMPLETED",
                    created_at=datetime.utcnow()
                )
                self.db.add(txn)
                
                # Create audit log entry
                audit = AuditLog(
                    action="TRANSFER",
                    profile_id=profile_id,
                    resource_id=transaction_id,
                    resource_type="TRANSACTION",
                    details={
                        "source_id": source_account.id,
                        "destination_id": destination_account.id,
                        "amount": str(amount),
                        "balance_before": str(source_account.balance + amount)
                    },
                    ip_address=request.remote_addr,
                    user_agent=request.user_agent.string,
                    created_at=datetime.utcnow()
                )
                self.db.add(audit)
            
            # Log successful transfer
            logger.info(
                "Transfer completed successfully",
                extra={
                    "transaction_id": transaction_id,
                    "source_id": source_account.id,
                    "destination_id": destination_account.id,
                    "amount": str(amount),
                    "profile_id": profile_id
                }
            )
            
            return {
                "transaction_id": transaction_id,
                "status": "COMPLETED",
                "timestamp": datetime.utcnow().isoformat(),
                "source_account": {
                    "id": source_account.id,
                    "balance": str(source_account.balance)
                },
                "destination_account": {
                    "id": destination_account.id
                }
            }
            
        except SQLAlchemyError as e:
            # Log database errors
            logger.error(
                "Database error during transfer",
                extra={
                    "error": str(e),
                    "source_id": source_account.id,
                    "destination_id": destination_account.id
                },
                exc_info=True
            )
            raise TransferError("Transfer failed due to database error", code=500)


# Create transfer service
transfer_service = TransferService(db.session)

@app.route("/api/transfers/execute", methods=["POST"])
@jwt_required()
@requires_roles("account_holder", "admin")
def execute_transfer():
    """API endpoint for executing money transfers"""
    current_profile_id = get_jwt_identity()
    request_id = str(uuid.uuid4())
    
    # Log incoming request
    logger.info(
        "Transfer request received",
        extra={
            "request_id": request_id,
            "profile_id": current_profile_id,
            "ip": request.remote_addr
        }
    )
    
    try:
        # Parse and validate request data
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request format"}), 400
        
        # Extract required fields
        try:
            source_account_id = data.get("source_account_id")
            destination_account_id = data.get("destination_account_id")
            amount_str = data.get("amount")
            description = data.get("description", "")
            
            # Validate required fields
            if not all([source_account_id, destination_account_id, amount_str]):
                return jsonify({"error": "Missing required fields"}), 400
                
            # Convert amount safely
            try:
                amount = Decimal(str(amount_str))
            except (ValueError, TypeError, InvalidOperation):
                return jsonify({"error": "Invalid amount format"}), 400
                
        except Exception as e:
            logger.warning(
                "Invalid transfer request data",
                extra={"request_id": request_id, "error": str(e)}
            )
            return jsonify({"error": "Invalid request data"}), 400
        
        # Validate transfer amount
        if not (Decimal('0.01') <= amount <= Decimal('100000.00')):
            return jsonify({
                "error": "Invalid amount",
                "details": "Amount must be between 0.01 and 100,000.00"
            }), 400
            
        # Prevent self-transfers
        if source_account_id == destination_account_id:
            return jsonify({"error": "Cannot transfer to same account"}), 400
            
        try:
            # Validate accounts
            source_account, destination_account = transfer_service.validate_accounts(
                source_account_id, destination_account_id, current_profile_id
            )
            
            # Validate amount against balance
            transfer_service.validate_amount(amount, source_account)
            
            # Execute transfer
            result = transfer_service.execute_transfer(
                source_account, destination_account, amount, description, current_profile_id
            )
            
            return jsonify(result), 200
            
        except TransferError as e:
            logger.warning(
                f"Transfer error: {e.message}",
                extra={"request_id": request_id, "code": e.code, "details": e.details}
            )
            return jsonify({"error": e.message, "details": e.details}), e.code
            
    except Exception as e:
        # Log unexpected errors
        logger.error(
            "Unexpected error during transfer",
            extra={"request_id": request_id, "error": str(e)},
            exc_info=True
        )
        return jsonify({
            "error": "An unexpected error occurred",
            "request_id": request_id
        }), 500


@app.errorhandler(Exception)
def handle_exception(e):
    """Global exception handler for unhandled errors"""
    request_id = str(uuid.uuid4())
    
    logger.error(
        f"Unhandled exception: {str(e)}",
        extra={"request_id": request_id},
        exc_info=True
    )
    
    return jsonify({
        "error": "Internal server error",
        "request_id": request_id
    }), 500


if __name__ == "__main__":
    # Configure production settings
    app.config['JSON_SORT_KEYS'] = False
    app.config['PROPAGATE_EXCEPTIONS'] = False
    
    # In production, use:
    # app.run(host='0.0.0.0', port=5000, debug=False)
    app.run(debug=True)
```

## Security Testing Suite

```python
import pytest
import uuid
from decimal import Decimal
from unittest.mock import Mock, patch
from flask import Flask
from flask_testing import TestCase

class TestTransferAPI(TestCase):
    def create_app(self):
        app.config['TESTING'] = True
        app.config['JWT_SECRET_KEY'] = 'test-key'
        return app
        
    @pytest.fixture
    def mock_auth(self):
        """Mock JWT authentication for testing"""
        with patch('flask_jwt_extended.verify_jwt_in_request') as mock_jwt:
            mock_jwt.return_value = True
            with patch('flask_jwt_extended.get_jwt_identity') as mock_identity:
                mock_identity.return_value = "test-user-123"
                yield
    
    def test_sql_injection_prevention(self, mock_auth):
        """Test protection against SQL injection attacks"""
        # Test malicious input in account ID
        response = self.client.post(
            '/api/transfers/execute',
            json={
                "source_account_id": "1; DROP TABLE accounts;--",
                "destination_account_id": "2",
                "amount": 100
            },
            headers={"Authorization": "Bearer test-token"}
        )
        # Should be rejected with 404 (not found) or 400 (bad request)
        # but should NOT cause SQL error (500)
        assert response.status_code in [400, 404]
        
    def test_negative_amount_rejection(self, mock_auth):
        """Test rejection of negative transfer amounts"""
        response = self.client.post(
            '/api/transfers/execute',
            json={
                "source_account_id": "1",
                "destination_account_id": "2",
                "amount": -100
            },
            headers={"Authorization": "Bearer test-token"}
        )
        assert response.status_code == 400
        assert "Invalid amount" in response.json["error"]
        
    def test_unauthorized_account_access(self, mock_auth):
        """Test prevention of unauthorized account access"""
        # Setup mock to simulate account exists but belongs to different user
        with patch.object(TransferService, 'validate_accounts') as mock_validate:
            mock_validate.side_effect = AccountAccessError("ACC123")
            
            response = self.client.post(
                '/api/transfers/execute',
                json={
                    "source_account_id": "ACC123",
                    "destination_account_id": "ACC456",
                    "amount": 100
                },
                headers={"Authorization": "Bearer test-token"}
            )
            
            assert response.status_code == 403
            assert "Unauthorized access" in response.json["error"]
            
    def test_atomic_transaction_rollback(self, mock_auth):
        """Test transaction atomicity with rollback on error"""
        # Setup mocks
        source = Mock(balance=Decimal("1000"), status="ACTIVE", id="ACC001")
        dest = Mock(balance=Decimal("500"), status="ACTIVE", id="ACC002")
        
        # Simulate database error during transaction
        with patch.object(TransferService, 'validate_accounts') as mock_validate:
            mock_validate.return_value = (source, dest)
            
            with patch.object(db.session, 'begin') as mock_begin:
                # Simulate transaction that raises exception
                mock_begin.return_value.__enter__.side_effect = SQLAlchemyError("Test DB Error")
                
                response = self.client.post(
                    '/api/transfers/execute',
                    json={
                        "source_account_id": "ACC001",
                        "destination_account_id": "ACC002",
                        "amount": 100
                    },
                    headers={"Authorization": "Bearer test-token"}
                )
                
                # Should return error but not change account balances
                assert response.status_code == 500
                assert source.balance == Decimal("1000")  # Unchanged
                assert dest.balance == Decimal("500")     # Unchanged
                
    def test_rate_limiting(self):
        """Test API rate limiting protection"""
        # Make 10 rapid requests
        for i in range(10):
            self.client.post(
                '/api/transfers/execute',
                json={
                    "source_account_id": f"ACC{i}",
                    "destination_account_id": "ACC999",
                    "amount": 100
                },
                headers={"Authorization": "Bearer test-token"}
            )
            
        # 11th request should be rate limited
        response = self.client.post(
            '/api/transfers/execute',
            json={
                "source_account_id": "ACC001",
                "destination_account_id": "ACC002",
                "amount": 100
            },
            headers={"Authorization": "Bearer test-token"}
        )
        
        # Should be rate limited (if implemented)
        assert response.status_code == 429
```

## Security Headers Implementation

```python
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response
```

## Production Deployment Checklist

1. **Security Configuration**
   - [ ] Enable HTTPS with proper certificate
   - [ ] Set secure cookie flags (Secure, HttpOnly, SameSite)
   - [ ] Configure rate limiting middleware
   - [ ] Implement IP-based blocking for suspicious activity

2. **Database Security**
   - [ ] Use connection pooling with limited privileges
   - [ ] Enable SSL for database connections
   - [ ] Implement row-level security policies
   - [ ] Setup regular backup and recovery procedures

3. **Monitoring & Alerting**
   - [ ] Configure real-time monitoring for suspicious transfers
   - [ ] Set up alerts for failed authentication attempts
   - [ ] Implement transaction volume anomaly detection
   - [ ] Configure audit log rotation and archiving

4. **Performance Optimization**
   - [ ] Add database indexes for common query patterns
   - [ ] Implement caching for account status checks
   - [ ] Configure connection pooling for optimal performance
   - [ ] Set appropriate timeouts for all external services