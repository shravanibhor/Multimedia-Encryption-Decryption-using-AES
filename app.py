from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, send_file
import os
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import base64

app = Flask(__name__)
app.secret_key = 'your_secret_key'

UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted'
DECRYPTED_FOLDER = 'decrypted'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ENCRYPTED_FOLDER'] = ENCRYPTED_FOLDER
app.config['DECRYPTED_FOLDER'] = DECRYPTED_FOLDER

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)

# Function to send email
def send_email(to_email, file_path):
    from_email = 'shravanibhor20@gmail.com'
    from_password = 'Shanu.30'
    subject = 'Encrypted File'
    body = 'Please find the encrypted file attached.'

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with open(file_path, 'rb') as attachment:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename={os.path.basename(file_path)}')
            msg.attach(part)

        server = smtplib.SMTP('smtp.gmail.com', 587)  # Replace with your SMTP server
        server.starttls()
        server.login(from_email, from_password)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

@app.route('/send-email', methods=['POST'])
def send_email_route():
    if 'file' not in request.files or 'email' not in request.form:
        return jsonify(success=False, message="File or email not provided")

    email = request.form['email']
    file = request.files['file']
    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    if send_email(email, file_path):
        return jsonify(success=True)
    else:
        return jsonify(success=False)

@app.route('/encrypt', methods=['POST'])
def encrypt_file():
    if 'file' not in request.files or not request.form['password']:
        flash('No file or password provided')
        return redirect(url_for('index'))

    file = request.files['file']
    password = request.form['password']
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    # Encryption logic
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(filepath, 'rb') as f:
        data = f.read()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    encrypted_filename = f"enc_{filename}"
    encrypted_path = os.path.join(app.config['ENCRYPTED_FOLDER'], encrypted_filename)
    with open(encrypted_path, 'wb') as ef:
        ef.write(salt + iv + encrypted_data)
    
    flash('File encrypted successfully')
    return send_file(encrypted_path, as_attachment=True)

@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    if 'file' not in request.files or not request.form['password']:
        flash('No file or password provided')
        return redirect(url_for('index'))
    
    file = request.files['file']
    password = request.form['password']
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    # Decryption logic
    with open(filepath, 'rb') as f:
        data = f.read()

    salt = data[:16]
    iv = data[16:32]
    encrypted_data = data[32:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()
    except ValueError as e:
        print(f"Error during unpadding: {e}")
        return jsonify(success=False, message='Decryption failed due to invalid password.')

    decrypted_filename = f"dec_{filename}"
    decrypted_path = os.path.join(app.config['DECRYPTED_FOLDER'], decrypted_filename)
    with open(decrypted_path, 'wb') as df:
        df.write(decrypted_data)
    
    return jsonify(success=True, message='File decrypted successfully.', file_url=url_for('download_file', filename=decrypted_filename))

@app.route('/download/<filename>')
def download_file(filename):
    return send_file(os.path.join(app.config['DECRYPTED_FOLDER'], filename), as_attachment=True)

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
