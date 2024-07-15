import bcrypt
from cryptography.fernet import Fernet
import os

# Generate or load encryption key securely
# In a real application, store this key securely (e.g., environment variables, secret management services)
encryption_key = Fernet.generate_key()
cipher_suite = Fernet(encryption_key)

# File to store encrypted passwords
PASSWORDS_FILE = 'passwords.dat'

# Function to encrypt data
def encrypt_data(data):
    encrypted_data = cipher_suite.encrypt(data)
    return encrypted_data

# Function to decrypt data
def decrypt_data(encrypted_data):
    decrypted_data = cipher_suite.decrypt(encrypted_data).decode('utf-8')
    return decrypted_data

# Function to hash a password
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

# Function to store a new user's password securely
def store_password(username, password):
    # Hash the password
    hashed_password = hash_password(password)
    
    # Encrypt the hashed password
    encrypted_password = encrypt_data(hashed_password)
    
    # Store the encrypted password in the file
    with open(PASSWORDS_FILE, 'ab') as f:
        f.write(username.encode('utf-8') + b':' + encrypted_password + b'\n')
    
    print(f"Password for user '{username}' stored securely.")

# Function to verify login credentials
def verify_password(username, password):
    # Read and decrypt stored passwords
    if not os.path.exists(PASSWORDS_FILE):
        print("No users registered yet.")
        return False
    
    with open(PASSWORDS_FILE, 'rb') as f:
        for line in f:
            parts = line.strip().split(b':')
            stored_username = parts[0].decode('utf-8')
            encrypted_password = parts[1]
            
            if stored_username == username:
                # Decrypt the encrypted password
                decrypted_password = decrypt_data(encrypted_password)
                
                # Check if the password matches
                if bcrypt.checkpw(password.encode('utf-8'), decrypted_password):
                    print(f"Login successful. Welcome, '{username}'!")
                    return True
                else:
                    print("Incorrect password.")
                    return False
        
        print(f"User '{username}' not found.")
        return False

# Example usage
if __name__ == "__main__":
    # Register a new user
    store_password('alice', 'password123')
    
    # Login with correct password
    verify_password('alice', 'password123')
    
    # Login with incorrect password
    verify_password('alice', 'wrongpassword')
