# Idempotent Payment API

## Idempotency Key Design Choice

In this test, I chose to use an **in-memory store** for handling idempotency keys instead of a database or Redis. The main reason is that the purpose of the exercise is to **demonstrate the mechanism itself** — how to accept an idempotency key, store the request/response, and ensure consistent results on retries or concurrent requests. Using an in-memory store keeps the code simple, easy to read, and avoids introducing external dependencies that would make the test setup heavier than necessary.

---

### Real-world options

For real systems, two common options are:

1. **Database (e.g., PostgreSQL, MySQL)**  
   Ensures strong durability, persistence, and consistency of idempotency records. This is often required in **banking or financial systems** where correctness is critical.

2. **Redis cache**  
   Provides very fast access with **TTL (time-to-live)** support, making it useful for short-lived idempotency keys (e.g., 24 hours). Redis is typically used **in combination with a database** for both speed and reliability.

---

## Setup

```bash
python3.12 -m venv venv
source env/bin/activate
pip3 install -r requirements.txt
```

## Run API

```bash
uvicorn idempotent_payment_api:app --reload
```

## Test

```bash
python idempotent_payment_api.py
```
