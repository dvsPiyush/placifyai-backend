from flask import Blueprint, request, jsonify
import logging
import random
from werkzeug.security import generate_password_hash, check_password_hash

from extensions import db
from models import User
from interview_questions import questions
from utils.email_sender import send_email
from utils.jwt_handler import generate_token, token_required
from utils.otp_handler import generate_otp, store_otp, verify_otp

# Blueprints
auth_routes = Blueprint('auth_routes', __name__)
question_routes = Blueprint('question_routes', __name__)

logging.basicConfig(level=logging.INFO)

# ✅ Send OTP
@auth_routes.route('/send-otp', methods=['POST'])
def send_otp():
    data = request.json
    email = data.get('email')

    if not email:
        return jsonify({"error": "Email is required"}), 400

    otp = generate_otp()
    stored = store_otp(email, otp)
    if not stored:
        return jsonify({"error": "OTP already sent recently. Please wait."}), 429

    logging.info(f"Sending OTP {otp} to {email}")
    send_email(email, otp)

    return jsonify({"message": f"OTP sent to {email}"}), 200

# ✅ Verify OTP
@auth_routes.route('/verify-otp', methods=['POST'])
def verify_user_otp():
    data = request.json
    email = data.get('email')
    entered_otp = data.get('otp')

    if not verify_otp(email, entered_otp):
        return jsonify({"error": "Incorrect or expired OTP"}), 401

    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(email=email, verified=True)
        db.session.add(user)
    else:
        user.verified = True
    db.session.commit()

    token = generate_token({"email": email})
    return jsonify({
        "message": "OTP verified. Login successful.",
        "token": token,
        "email": email
    }), 200

# ✅ Signup
@auth_routes.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already registered'}), 400

    hashed_password = generate_password_hash(password)
    new_user = User(email=email, password=hashed_password, verified=True)  # assume OTP already verified if signing up directly
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Signup successful'}), 200

# ✅ Login
@auth_routes.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        token = generate_token({"email": email})
        return jsonify({'token': token}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

# ✅ Get Random Interview Question (JWT Protected)
@question_routes.route('/get-random-question', methods=['GET'])
@token_required
def get_random_question(user_data):
    question = random.choice(questions)
    return jsonify(question), 200
