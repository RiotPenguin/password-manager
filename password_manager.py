from cryptography.fernet import Fernet
import json
import os
import getpass
import argparse
import secrets
import string
from hashlib import pbkdf2_hmac
import base64

class PasswordManager:
    def __init__(self, master_password, key_file='~/.password_manager/key.key', password_file='~/.password_manager/passwords.json'):
        self.master_password = master_password
        self.key_file = os.path.expanduser(key_file)
        self.password_file = os.path.expanduser(password_file)
        self.key = self.load_key()
        self.cipher = Fernet(self.key)
        self.passwords = self.load_passwords()

    def derive_key(self, password):
        salt = b'\x00' * 16  # Replace with a randomly generated salt for more security
        kdf = pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return base64.urlsafe_b64encode(kdf)

    def load_key(self):
        if not os.path.exists(self.key_file):
            os.makedirs(os.path.dirname(self.key_file), exist_ok=True)
            key = Fernet.generate_key()
            derived_key = self.derive_key(self.master_password)
            cipher = Fernet(derived_key)
            encrypted_key = cipher.encrypt(key)
            with open(self.key_file, 'wb') as key_file:
                key_file.write(encrypted_key)
        else:
            with open(self.key_file, 'rb') as key_file:
                encrypted_key = key_file.read()
            derived_key = self.derive_key(self.master_password)
            cipher = Fernet(derived_key)
            key = cipher.decrypt(encrypted_key)
        return key

    def load_passwords(self):
        if os.path.exists(self.password_file):
            with open(self.password_file, 'r') as password_file:
                passwords = json.load(password_file)
                for account, enc_password in passwords.items():
                    passwords[account] = self.cipher.decrypt(enc_password.encode()).decode()
        else:
            passwords = {}
        return passwords

    def save_passwords(self):
        encrypted_passwords = {account: self.cipher.encrypt(password.encode()).decode()
                               for account, password in self.passwords.items()}
        os.makedirs(os.path.dirname(self.password_file), exist_ok=True)
        with open(self.password_file, 'w') as password_file:
            json.dump(encrypted_passwords, password_file)

    def add_password(self, account, password):
        self.passwords[account] = password
        self.save_passwords()

    def get_password(self, account):
        return self.passwords.get(account)

    def delete_password(self, account):
        if account in self.passwords:
            del self.passwords[account]
            self.save_passwords()

    def generate_password(self, length=12):
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(characters) for i in range(length))

def main():
    parser = argparse.ArgumentParser(description='Password Manager')
    parser.add_argument('action', choices=['add', 'get', 'delete', 'generate'], help='Action to perform')
    parser.add_argument('account', nargs='?', help='Account name')
    parser.add_argument('--password', help='Password for the account (only needed for add action)')
    parser.add_argument('--length', type=int, default=12, help='Length of the generated password (only needed for generate action)')

    args = parser.parse_args()

    master_password = getpass.getpass('Enter your master password: ')
    pm = PasswordManager(master_password)

    if args.action == 'add':
        if args.password is None:
            print('Password is required for adding an account.')
        else:
            pm.add_password(args.account, args.password)
            print(f'Password for {args.account} added.')
    elif args.action == 'get':
        password = pm.get_password(args.account)
        if password:
            print(f'Password for {args.account}: {password}')
        else:
            print(f'No password found for {args.account}.')
    elif args.action == 'delete':
        pm.delete_password(args.account)
        print(f'Password for {args.account} deleted.')
    elif args.action == 'generate':
        generated_password = pm.generate_password(args.length)
        print(f'Generated password: {generated_password}')

if __name__ == "__main__":
    main()
