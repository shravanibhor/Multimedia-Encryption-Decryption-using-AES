import secrets
import string

def generate_password(length=16):
    # Define the character set: uppercase, lowercase, digits, and punctuation
    charset = string.ascii_letters + string.digits + string.punctuation
    
    # Generate a random password using the charset
    password = ''.join(secrets.choice(charset) for _ in range(length))
    return password

# Generate a secure 16-character password
secure_password = generate_password()
print(f"Your secure password: {secure_password}")

