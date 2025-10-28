# Notification Service

## 📌 Code

```python
from abc import ABC, abstractmethod
import threading
import concurrent.futures
from typing import Dict, List, Any

# Abstraction
class NotificationChannel(ABC):
    @abstractmethod
    def send(self, user, message) -> bool: ...


class EmailChannel(NotificationChannel):
    def send(self, user, message) -> bool:
        try:
            email = user.get('email')
            if not email:
                return False
            print(f"[EMAIL] to {email}: {message}")
            return True
        except Exception:
            return False


class SmsChannel(NotificationChannel):
    def send(self, user: dict[str, str], message: str) -> bool:
        try:
            phone = user.get('phone')
            if not phone:
                return False
            print(f"[SMS] to {phone}: {message}")
            return True
        except Exception:
            return False


class NotificationService:
    def __init__(self, channels: dict[str, NotificationChannel]):
        self.channels = channels

    def notify(self, user: dict[str, str], message: str) -> Dict[str, bool]:
        results = {}
        preferences = user.get("preferences", [])
        
        if not preferences:
            return results
            
        # Use ThreadPoolExecutor to send notifications in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(preferences)) as executor:
            # Create a dictionary to track futures
            future_to_channel = {}
            
            # Submit tasks to thread pool
            for preference in preferences:
                channel = self.channels.get(preference)
                if channel:
                    # Submit the task to the executor and store the future
                    future = executor.submit(channel.send, user, message)
                    future_to_channel[future] = preference
                else:
                    results[preference] = False
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_channel):
                channel_name = future_to_channel[future]
                try:
                    success = future.result()
                    results[channel_name] = success
                except Exception:
                    results[channel_name] = False
                    
        return results


# Example usage
test_channels = {"EMAIL": EmailChannel(), "SMS": SmsChannel()}
service = NotificationService(test_channels)

user1 = {"email": "a@test.com", "phone": "123", "preferences": ["EMAIL"]}
user2 = {"email": "b@test.com", "phone": "456", "preferences": ["SMS", "EMAIL"]}

results1 = service.notify(user1, "Order shipped!")
print(f"Results for user1: {results1}")

results2 = service.notify(user2, "Payment received!")
print(f"Results for user2: {results2}")
```