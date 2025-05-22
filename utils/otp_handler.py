import random
import time
import redis
import os
from dotenv import load_dotenv

load_dotenv()

redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

def generate_otp():
    return str(random.randint(100000, 999999))

def store_otp(email, otp):
    key = f"otp:{email}"
    if redis_client.exists(key):
        ttl = redis_client.ttl(key)
        if ttl > 240:  # if last OTP was sent less than a minute ago
            return False
    redis_client.setex(key, 300, otp)  # OTP valid for 5 minutes
    return True

def verify_otp(email, entered_otp):
    key = f"otp:{email}"
    saved_otp = redis_client.get(key)
    if saved_otp and entered_otp == saved_otp:
        redis_client.delete(key)
        return True
    return False
