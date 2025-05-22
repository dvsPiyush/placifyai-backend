from flask import Flask, request, jsonify
from flask_cors import CORS
import os,io, sys
import requests
import time
from pymongo import MongoClient
import bcrypt
from dotenv import load_dotenv
import jwt
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
import random
import google.generativeai as genai
import PyPDF2
from flask_mail import Mail, Message

# App setup
app = Flask(__name__)
CORS(app, origins= ["http://localhost:3000","https://placifyai-frontend.vercel.app"], supports_credentials=True)
# Load environment variables
load_dotenv()
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'fallback_secret')
MONGO_URI = os.getenv('MONGO_URI')
EMAIL_SENDER = os.getenv('EMAIL_SENDER')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
HF_API_TOKEN = os.getenv('HF_API_TOKEN')
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
genai.configure(api_key=GEMINI_API_KEY)
# MongoDB connection
client = MongoClient(MONGO_URI)
db = client['PlacifyAI']
users_collection = db['users']
chats = db['chats']
resume_scores_collection = db['resume_scores']  # <-- Add this line

# Configure Flask-Mail (add this after your app setup)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = EMAIL_SENDER
app.config['MAIL_PASSWORD'] = EMAIL_PASSWORD
mail = Mail(app)


@app.route("/")
def home():
    try:
        users_collection.find_one()
        return "MongoDB Connected Successfully"
    except Exception as e:
        return f"MongoDB Error: {str(e)}"


@app.before_request
def check_content_type():
    # Skip content-type check for file upload
    if request.path == '/upload-resume':
        return
    if request.method in ['POST', 'PUT', 'PATCH']:
        if request.content_type != 'application/json':
            return jsonify({'message': 'Content-Type must be application/json'}), 415
def send_otp_email(email, otp):
    subject = "PlacifyAI Email Verification OTP"
    body = f"<h2>Welcome to PlacifyAI!</h2><p>Your OTP is: <strong>{otp}</strong></p><p>It will expire in 10 minutes.</p>"
    msg = MIMEText(body, "html")
    msg['Subject'] = subject
    msg['From'] = EMAIL_SENDER
    msg['To'] = email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, email, msg.as_string())
        return True
    except Exception as e:
        print("Error sending email:", e)
        return False

# ✅ Signup Route
@app.route('/api/signup', methods=['POST', 'OPTIONS'])
def signup():
    if request.method == 'OPTIONS':
        return jsonify({'message': 'CORS preflight successful'}), 200
    
    data = request.get_json()
    name = data.get('name')
    username = data.get('username')  # email
    password = data.get('password')

    if not name or not username or not password:
        return jsonify({'message': 'All fields are required'}), 400

    if users_collection.find_one({'username': username}):
        return jsonify({'message': 'User already exists'}), 409

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    otp = str(random.randint(100000, 999999))
    otp_created_at = datetime.utcnow()

    user_data = {
        'name': name,
        'username': username,
        'password': hashed_password,
        'is_active': False,
        'otp': otp,
        'otp_created_at': otp_created_at
    }

    users_collection.insert_one(user_data)

    if send_otp_email(username, otp):
        return jsonify({'message': 'OTP sent to email. Please verify to activate your PlacifyAI account.',
                        'otp_required': True}), 200
    else:
        return jsonify({'message': 'Error sending OTP email.'}), 500
# ✅ OTP Verification Route
@app.route('/api/verify-otp', methods=['POST', 'OPTIONS'])
def verify_otp():
    if request.method == 'OPTIONS':
        return jsonify({'message': 'CORS preflight successful'}), 200

    try:
        data = request.get_json()
        print("Received data:", data)  # Debugging log
        email = data.get('email')
        user_otp = data.get('otp')

        if not email or not user_otp:
            return jsonify({'message': 'Email and OTP are required'}), 400

        user = users_collection.find_one({'username': email})

        if not user:
            return jsonify({'message': 'User not found'}), 404

        stored_otp = user.get('otp')
        if str(user_otp) != str(stored_otp):
            return jsonify({'message': 'Invalid OTP'}), 401

        # Activate the account
        users_collection.update_one({'username': email}, {
            '$set': {'is_active': True},
            '$unset': {'otp': ""}
        })

        return jsonify({'message': 'OTP verified successfully'}), 200
    except Exception as e:
        print("Error in /api/verify-otp:", str(e))  # Debugging log
        return jsonify({'message': 'Internal server error'}), 500


@app.route('/api/resend-otp', methods=['POST', 'OPTIONS'])
def resend_otp():
    if request.method == 'OPTIONS':
        return jsonify({'message': 'CORS preflight successful'}), 200

    try:
        data = request.get_json()
        email = data.get('email')

        if not email:
            return jsonify({'message': 'Email is required'}), 400

        user = users_collection.find_one({'username': email})

        if not user:
            return jsonify({'message': 'User not found'}), 404

        if user.get('is_active', False):
            return jsonify({'message': 'Account is already verified'}), 400

        # Generate a new OTP
        otp = str(random.randint(100000, 999999))
        users_collection.update_one({'username': email}, {
            '$set': {'otp': otp, 'otp_created_at': datetime.utcnow()}
        })

        if send_otp_email(email, otp):
            return jsonify({'message': 'OTP resent successfully. Please check your email.'}), 200
        else:
            return jsonify({'message': 'Failed to send OTP email.'}), 500
    except Exception as e:
        print("Error in /api/resend-otp:", str(e))
        return jsonify({'message': 'Internal server error'}), 500
   
   
    # ✅ Login Route
@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        return jsonify({'message': 'CORS preflight successful'}), 200

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    user = users_collection.find_one({'username': username})

    if not user:
        return jsonify({'message': 'User not found, Please Sign Up'}), 404

    if not bcrypt.checkpw(password.encode('utf-8'), user['password']):
        return jsonify({'message': 'Invalid credentials'}), 401

    if not user.get('is_active', False):
        return jsonify({
            'message': 'Please verify your email via OTP first',
            'otp_required': True
        }), 403

    # Generate JWT token
    token_payload = {
        'username': username,
        'name': user.get('name', ''),
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    token = jwt.encode(token_payload, JWT_SECRET_KEY, algorithm='HS256')

    return jsonify({
        'message': 'Login successful',
        'token': token,
        'name': user.get('name', '')
    }), 200
   
# ✅ Protected Route
@app.route('/api/protected', methods=['GET'])
def protected():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'message': 'Missing or invalid token'}), 401

    token = auth_header.split(' ')[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
        return jsonify({'message': 'Access granted', 'user': decoded['username'], 'name': decoded['name']}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401


#@app.after_request
#def after_request(response):
 #   response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3000')
 #   response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
  #  response.headers.add('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
  #  return response

#code evalutator
@app.route('/api/evaluate', methods=['POST'])
def evaluate_code():
    data = request.get_json()
    code = data.get('code', '')
    language = data.get('language', 'python')
    if language != 'python':
        return jsonify({'output': 'Only Python is supported right now.'})
    # ...rest of your code...
    try:
        exec_globals = {}
        old_stdout = sys.stdout
        sys.stdout = mystdout = io.StringIO()
        start_time = time.time()  # <-- Start timer
        exec(code, exec_globals)
        end_time = time.time()
        sys.stdout = old_stdout
        output = mystdout.getvalue()
        # If user set a result variable, append it
        if 'result' in exec_globals:
            output += str(exec_globals['result'])
        if not output.strip():
            output = "No output"

        time_taken = f"{(end_time - start_time):.6f} sec"
        return jsonify({'output': output, 'time_complexity': time_taken})
    except Exception as e:
        sys.stdout = old_stdout
        return jsonify({'output': str(e)}), 400

@app.route('/api/get-random-question', methods=['GET'])
def get_random_question():
    questions = [
        {"type": "Beginner", "question": "Write a Python program to add two numbers."},
        {"type": "Intermediate", "question": "Write a function to check if a number is prime."},
        {"type": "Expert", "question": "Implement a binary search algorithm in Python."}
    ]
    import random
    level = request.args.get('level')
    if level:
        filtered = [q for q in questions if q['type'].lower() == level.lower()]
        if filtered:
            return jsonify(random.choice(filtered))
        else:
            return jsonify({"error": "No questions found for this level."}), 404
    return jsonify(random.choice(questions))
@app.route('/chatbot', methods=['POST'])
def chatbot():
    data = request.get_json()
    username = data.get('username')
    message = data.get('message', '')

    bot_reply = None

    # 1. Try Hugging Face API
    try:
        HF_API_TOKEN = os.getenv('HF_API_TOKEN')
        api_url = "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.3"
        headers = {"Authorization": f"Bearer {HF_API_TOKEN}"}
        payload = {"inputs": f"You are a helpful coding assistant. {message}"}
        response = requests.post(api_url, headers=headers, json=payload, timeout=30)
        result = response.json()
        if isinstance(result, list) and 'generated_text' in result[0]:
            bot_reply = result[0]['generated_text']
        elif 'error' in result and "Invalid credentials" not in result['error']:
            bot_reply = f"Error: {result['error']}"
        else:
            raise Exception(result.get('error', 'Unknown error'))
    except Exception as e:
        print(f"Hugging Face failed: {e}")
        # 2. Fallback: Try Gemini (or another API)
        try:
            model = genai.GenerativeModel('models/gemini-1.5-flash-latest')  # or any model from your list
            prompt = f"You are a helpful coding assistant. {message}"
            response = model.generate_content(prompt)
            bot_reply = response.text.strip()
        except Exception as e2:
            print(f"Gemini failed: {e2}")
            # 3. Fallback: Use a simple rule-based reply
            bot_reply = "Sorry, all AI assistants are busy right now. Please try again later."

    chats.insert_one({'username': username, 'user': message, 'bot': bot_reply})
    return jsonify({'response': bot_reply})

@app.route('/chat-history', methods=['POST'])
def chat_history():
    data = request.get_json()
    username = data.get('username')
    history = list(chats.find({'username': username}, {'_id': 0, 'user': 1, 'bot': 1}))
    return jsonify({'history': history})

@app.route('/chat-history/delete', methods=['POST', 'OPTIONS'])
def delete_chat_history():
    if request.method == 'OPTIONS':
        return jsonify({'message': 'CORS preflight successful'}), 200
    data = request.get_json()
    username = data.get('username')
    if not username:
        return jsonify({'message': 'Username required'}), 400
    result = chats.delete_many({'username': username})
    return jsonify({'message': f'Deleted {result.deleted_count} chats.'}), 200
import re

@app.route('/upload-resume', methods=['POST', 'OPTIONS'])
def upload_resume():
    if request.method == 'OPTIONS':
        return jsonify({'message': 'CORS preflight successful'}), 200

    file = request.files['resume']
    username = request.form.get('username')  # <-- Add this line

    reader = PyPDF2.PdfReader(file)
    text = ""
    for page in reader.pages:
        text += page.extract_text() or ""

    prompt = (
        "You are a professional resume evaluator. "
        "Rate this resume out of 5 and give specific suggestions for improvement. "
        "Format your answer as: 'Score: X/5\\nSuggestions: ...'"
        f"\n\n{text}"
    )

    try:
        model = genai.GenerativeModel('models/gemini-1.5-flash-latest')
        response = model.generate_content(prompt)
        ai_reply = response.text.strip()

        # Extract score using regex
        score_match = re.search(r'Score:\s*([0-5](?:\.\d+)?)/5', ai_reply)
        score = float(score_match.group(1)) if score_match else None

        # Extract suggestions
        suggestions_match = re.search(r'Suggestions:(.*)', ai_reply, re.DOTALL)
        suggestions = suggestions_match.group(1).strip() if suggestions_match else ai_reply
        resume_scores_collection.insert_one({
            'username': username,
            'score': score,
             'timestamp': datetime.utcnow()
             })
        return jsonify({'score': score, 'suggestions': suggestions})
    except Exception as e:
            print("Upload error:", e)  # Add this line
            return jsonify({'error': f'AI evaluation failed: {str(e)}'}), 500

@app.route('/resume-scores', methods=['POST'])
def resume_scores():
    data = request.get_json()
    username = data.get('username')
    scores = list(resume_scores_collection.find({'username': username}, {'_id': 0}))
    return jsonify({'scores': scores})

def check_and_award_badges(username):
    count = resume_scores_collection.count_documents({'username': username})
    badges = []
    if count >= 5:
        badges.append("Resume Novice")
    if count >= 10:
        badges.append("Resume Master")
    # Save badges to user profile or return them
    users_collection.update_one({'username': username}, {'$set': {'badges': badges}})

@app.route('/api/get-user', methods=['POST'])
def get_user():
    data = request.get_json()
    username = data.get('username')
    user = users_collection.find_one({'username': username}, {'_id': 0, 'badges': 1})
    badges = user.get('badges', []) if user else []
    return jsonify({'badges': badges})

@app.route('/delete-account', methods=['POST'])
def delete_account():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    if not username or not email:
        return jsonify({'error': 'Username and email required'}), 400

    # Delete user from database
    users_collection.delete_one({'username': username})
    chats.delete_many({'username': username})
    resume_scores_collection.delete_many({'username': username})

    # Send thank you email
    try:
        msg = Message(
            subject="Thank You from PlacifyAI!",
            sender=EMAIL_SENDER,
            recipients=[email],
            body=(
                f"Dear {username},\n\n"
                "Thank you for choosing PlacifyAI😊. We wish you the best for your future!😎\n"
                "We hope to see you again on our platform to practice and improve your skills.\n"
                "We are constantly improving the website for a better experience🥵.\n\n"
                "Best regards,\nPlacifyAI Team of one MAN😤 "
            )
        )
        mail.send(msg)
    except Exception as e:
        print("Email send error:", e)

    return jsonify({'message': 'Account deleted and email sent.'}), 200

# ✅ Start Server
if __name__ == '__main__':
    app.run(debug=True)
