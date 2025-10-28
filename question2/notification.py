from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
import logging
import threading
import concurrent.futures

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Abstraction - Base class for all notification channels
class NotificationChannel(ABC):
    """Abstract base class for notification channels"""
    
    @abstractmethod
    def send(self, user: Dict[str, str], message: str) -> bool:
        """
        Send notification to user
        
        Args:
            user: User information dictionary
            message: Message to send
            
        Returns:
            bool: True if sent successfully, False otherwise
        """
        pass


class EmailChannel(NotificationChannel):
    """Email notification channel implementation"""
    
    def send(self, user: Dict[str, str], message: str) -> bool:
        """
        Send email notification
        
        Args:
            user: User information with 'email' key
            message: Message to send
            
        Returns:
            bool: True if sent successfully
        """
        try:
            # Simulate email sending via 3rd party provider
            email = user.get('email')
            if not email:
                logger.error("No email address provided")
                return False
                
            # Here you would integrate with actual email provider (SendGrid, AWS SES, etc.)
            print(f"[EMAIL] to {email}: {message}")
            logger.info(f"Email sent successfully to {email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email: {str(e)}")
            return False


class SmsChannel(NotificationChannel):
    """SMS notification channel implementation"""
    
    def send(self, user: Dict[str, str], message: str) -> bool:
        """
        Send SMS notification
        
        Args:
            user: User information with 'phone' key
            message: Message to send
            
        Returns:
            bool: True if sent successfully
        """
        try:
            # Simulate SMS sending via 3rd party provider
            phone = user.get('phone')
            if not phone:
                logger.error("No phone number provided")
                return False
                
            # Here you would integrate with actual SMS provider (Twilio, AWS SNS, etc.)
            print(f"[SMS] to {phone}: {message}")
            logger.info(f"SMS sent successfully to {phone}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send SMS: {str(e)}")
            return False


class NotificationService:
    """Main notification service that manages multiple channels"""
    
    def __init__(self, channels: Dict[str, NotificationChannel]):
        """
        Initialize notification service with available channels
        
        Args:
            channels: Dictionary mapping channel names to channel instances
        """
        self.channels = channels
        logger.info(f"NotificationService initialized with channels: {list(channels.keys())}")
    
    def notify(self, user: Dict[str, str], message: str) -> Dict[str, bool]:
        """
        Send notification to user through their preferred channels in parallel
        using multiple threads for better performance.
        
        Args:
            user: User information including preferences
            message: Message to send
            
        Returns:
            Dict[str, bool]: Results for each channel attempted
        """
        results = {}
        preferences = user.get("preferences", [])
        
        if not preferences:
            logger.warning(f"No notification preferences found for user")
            return results
        
        logger.info(f"Sending notification to user with preferences: {preferences}")
        
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
                    logger.debug(f"Submitted {preference} notification to thread pool")
                else:
                    logger.warning(f"Channel '{preference}' not available")
                    results[preference] = False
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_channel):
                channel_name = future_to_channel[future]
                try:
                    success = future.result()
                    results[channel_name] = success
                    logger.info(f"Channel {channel_name}: {'Success' if success else 'Failed'}")
                except Exception as e:
                    logger.error(f"Error sending via {channel_name}: {str(e)}")
                    results[channel_name] = False
        
        return results

# Example usage and testing
if __name__ == "__main__":
    # Initialize notification service with available channels
    test_channels = {"EMAIL": EmailChannel(), "SMS": SmsChannel()}
    service = NotificationService(test_channels)
    
    # Test users with different preferences
    user1 = {"email": "a@test.com", "phone": "123", "preferences": ["EMAIL"]}
    user2 = {"email": "b@test.com", "phone": "456", "preferences": ["SMS", "EMAIL"]}
    user3 = {"email": "c@test.com", "phone": "789", "preferences": ["PUSH"]}  # Unsupported channel
    user4 = {"email": "d@test.com", "phone": "000", "preferences": []}  # No preferences
    
    print("=== Testing Notification System ===\n")
    
    # Test 1: Single channel preference
    print("Test 1: User with EMAIL preference only")
    result1 = service.notify(user1, "Order shipped!")
    print(f"Results: {result1}\n")
    
    # Test 2: Multiple channel preferences
    print("Test 2: User with both SMS and EMAIL preferences")
    result2 = service.notify(user2, "Payment received!")
    print(f"Results: {result2}\n")
    
    # Test 3: Unsupported channel
    print("Test 3: User with unsupported channel preference")
    result3 = service.notify(user3, "New message!")
    print(f"Results: {result3}\n")
    
    # Test 4: No preferences
    print("Test 4: User with no preferences")
    result4 = service.notify(user4, "Welcome!")
    print(f"Results: {result4}\n")
    
    print("=== All tests completed ===")
