# Query Optimization for Transaction Pagination

## Current Problem

```sql
SELECT * FROM transactions
WHERE account_number = ?
ORDER BY entry_date DESC
LIMIT 20 OFFSET ?;
```

**Issues:**
- `SELECT *` fetches unnecessary columns
- `OFFSET` becomes slow with large page numbers
- Missing proper index

## Simple Solutions

### 1. Select only needed columns

```sql
-- Instead of SELECT *
SELECT transaction_id, entry_date, amount, status
FROM transactions
WHERE account_number = ?
ORDER BY entry_date DESC
LIMIT 20 OFFSET ?;
```

### 2. Replace OFFSET with WHERE condition

```sql
-- First page
SELECT transaction_id, entry_date, amount, status
FROM transactions
WHERE account_number = ?
ORDER BY entry_date DESC
LIMIT 20;

-- Next pages
SELECT transaction_id, entry_date, amount, status
FROM transactions
WHERE account_number = ?
  AND entry_date < '2024-01-15 10:30:00' -- last timestamp from previous page
ORDER BY entry_date DESC
LIMIT 20;
```

### 3. Create proper index

```sql
CREATE INDEX idx_account_date ON transactions(account_number, entry_date DESC);
```

## Performance Comparison

**Benefits:**
- faster for deep pagination
- Less data transfer
- Easy to implement