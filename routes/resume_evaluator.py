import pdfplumber
import os
from flask import Blueprint, request, jsonify, current_app
from werkzeug.utils import secure_filename

resume_app = Blueprint('resume_app', __name__)
UPLOAD_FOLDER = 'uploads'

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def evaluate_resume(text):
    score = 0
    keywords = ['project', 'internship', 'skills', 'education', 'certificate']
    for word in keywords:
        if word in text.lower():
            score += 1
    return min(score, 5)

@resume_app.route('/evaluate-resume', methods=['POST'])
def evaluate_resume_api():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    with pdfplumber.open(filepath) as pdf:
        full_text = ''
        for page in pdf.pages:
            full_text += page.extract_text() or ''

    score = evaluate_resume(full_text)
    os.remove(filepath)
    return jsonify({'score': score})
