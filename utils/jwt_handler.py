import jwt
import os
import datetime
from flask import request, jsonify
from functools import wraps
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")

def generate_token(payload, expiry_hours=1):
    payload["exp"] = datetime.datetime.utcnow() + datetime.timedelta(hours=expiry_hours)
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def decode_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None

def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization', None)
        if not token:
            return jsonify({'error': 'Token missing'}), 401
        try:
            token = token.replace("Bearer ", "")
            data = decode_token(token)
            if not data:
                return jsonify({'error': 'Invalid or expired token'}), 401
            return f(data, *args, **kwargs)
        except Exception as e:
            return jsonify({'error': str(e)}), 401
    return wrapper
