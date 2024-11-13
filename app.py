from flask import Flask, render_template, request, send_file, redirect, url_for, flash
import os
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend

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

# Generate AES key and IV
def generate_key_iv(password: bytes, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    iv = os.urandom(16)
    return key, iv

def aes_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def aes_decrypt(encrypted_data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt_file():
    if 'file' not in request.files or not request.form['password']:
        flash('No file or password provided')
        return redirect(url_for('index'))
    
    file = request.files['file']
    password = request.form['password']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('index'))
    
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    with open(filepath, 'rb') as f:
        file_data = f.read()
    
    salt = os.urandom(16)
    key, iv = generate_key_iv(password.encode(), salt)
    encrypted_data = aes_encrypt(file_data, key, iv)
    
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
    
    with open(filepath, 'rb') as ef:
        salt = ef.read(16)
        iv = ef.read(16)
        encrypted_data = ef.read()
    
    key, _ = generate_key_iv(password.encode(), salt)
    try:
        decrypted_data = aes_decrypt(encrypted_data, key, iv)
    except Exception as e:
        flash('Decryption failed')
        return redirect(url_for('index'))
    
    decrypted_filename = f"dec_{filename}"
    decrypted_path = os.path.join(app.config['DECRYPTED_FOLDER'], decrypted_filename)
    with open(decrypted_path, 'wb') as df:
        df.write(decrypted_data)
    
    flash('File decrypted successfully')
    return send_file(decrypted_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
