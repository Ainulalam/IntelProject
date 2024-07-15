import bcrypt
from cryptography.fernet import Fernet

# Generate a key for encryption (store this securely in a real application)
encryption_key = Fernet.generate_key()
cipher_suite = Fernet(encryption_key)

# Function to hash a password
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

# Function to encrypt data
def encrypt_data(data):
    encrypted_data = cipher_suite.encrypt(data.encode('utf-8'))
    return encrypted_data

# Function to decrypt data
def decrypt_data(encrypted_data):
    decrypted_data = cipher_suite.decrypt(encrypted_data).decode('utf-8')
    return decrypted_data

# Example usage
if __name__ == "__main__":
    # Simulate storing hashed passwords securely
    
    # Example passwords
    passwords = ["password1", "strongPassword123", "letmein"]
    
    # Hash and encrypt passwords
    hashed_and_encrypted_passwords = []
    for password in passwords:
        hashed_password = hash_password(password)
        encrypted_password = encrypt_data(hashed_password)
        hashed_and_encrypted_passwords.append(encrypted_password)
    
    # Store encrypted passwords in a file
    with open('encrypted_passwords.dat', 'wb') as f:
        for encrypted_password in hashed_and_encrypted_passwords:
            f.write(encrypted_password + b'\n')
    
    # Read and decrypt passwords from file
    decrypted_passwords = []
    with open('encrypted_passwords.dat', 'rb') as f:
        for line in f:
            decrypted_password = decrypt_data(line.strip())
            decrypted_passwords.append(decrypted_password)
    
    # Print decrypted passwords
    print("Decrypted Passwords:")
    for password in decrypted_passwords:
        print(password)
