import json
import hashlib
import getpass
import os
from cryptography.fernet import Fernet


class PasswordManager:
    def __init__(self):
        self.key_file = 'data/secret.key'
        self.password_file = 'data/passwords.json'
        self.master_hash_file = 'data/master.hash'
        self.cipher = None

    def generate_key(self):
        """Generate a new encryption key"""
        key = Fernet.generate_key()
        with open(self.key_file, 'wb') as key_file:
            key_file.write(key)
        return key

    def load_key(self):
        """Load the encryption key from file"""
        if not os.path.exists(self.key_file):
            return self.generate_key()
        with open(self.key_file, 'rb') as key_file:
            return key_file.read()

    def hash_password(self, password):
        """Create SHA-256 hash of password"""
        return hashlib.sha256(password.encode()).hexdigest()

    def setup_master_password(self):
        """Set up the master password for first time use"""
        print("\n[*] Setting up master password")
        master = getpass.getpass("Create master password: ")
        confirm = getpass.getpass("Confirm master password: ")

        if master != confirm:
            print("[-] Passwords don't match!")
            return False

        hashed = self.hash_password(master)
        with open(self.master_hash_file, 'w') as f:
            f.write(hashed)

        print("[+] Master password created successfully!")
        return True

    def verify_master_password(self):
        """Verify the master password"""
        if not os.path.exists(self.master_hash_file):
            return self.setup_master_password()

        with open(self.master_hash_file, 'r') as f:
            stored_hash = f.read().strip()

        master = getpass.getpass("Enter master password: ")
        if self.hash_password(master) == stored_hash:
            print("[+] Access granted!")
            return True
        else:
            print("[-] Access denied!")
            return False

    def initialize(self):
        """Initialize the password manager"""
        if not self.verify_master_password():
            return False

        key = self.load_key()
        self.cipher = Fernet(key)

        # Create password file if doesn't exist
        if not os.path.exists(self.password_file):
            with open(self.password_file, 'w') as f:
                json.dump([], f)

        return True

    def encrypt_password(self, password):
        """Encrypt a password"""
        return self.cipher.encrypt(password.encode()).decode()

    def decrypt_password(self, encrypted_password):
        """Decrypt a password"""
        return self.cipher.decrypt(encrypted_password.encode()).decode()

    def add_password(self, website, username, password):
        """Add a new password entry"""
        encrypted = self.encrypt_password(password)

        # Load existing passwords
        with open(self.password_file, 'r') as f:
            passwords = json.load(f)

        # Add new entry
        passwords.append({
            'website': website,
            'username': username,
            'password': encrypted
        })

        # Save updated passwords
        with open(self.password_file, 'w') as f:
            json.dump(passwords, f, indent=4)

        print(f"[+] Password for {website} saved successfully!")

    def get_password(self, website):
        """Retrieve password for a website"""
        with open(self.password_file, 'r') as f:
            passwords = json.load(f)

        for entry in passwords:
            if entry['website'].lower() == website.lower():
                decrypted = self.decrypt_password(entry['password'])
                return {
                    'website': entry['website'],
                    'username': entry['username'],
                    'password': decrypted
                }

        return None

    def list_passwords(self):
        """List all stored websites and usernames"""
        with open(self.password_file, 'r') as f:
            passwords = json.load(f)

        if not passwords:
            print("[-] No passwords stored yet!")
            return

        print("\n=== Stored Passwords ===")
        for i, entry in enumerate(passwords, 1):
            print(f"{i}. {entry['website']} - {entry['username']}")

    def generate_strong_password(self, length=16):
        """Generate a strong random password"""
        import secrets
        import string

        alphabet = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        return password


# Usage example
if __name__ == "__main__":
    pm = PasswordManager()

    if pm.initialize():
        # Add a password
        website = "github.com"
        username = "myusername"
        password = pm.generate_strong_password()
        pm.add_password(website, username, password)

        # Retrieve password
        result = pm.get_password(website)
        if result:
            print(f"\nWebsite: {result['website']}")
            print(f"Username: {result['username']}")
            print(f"Password: {result['password']}")
