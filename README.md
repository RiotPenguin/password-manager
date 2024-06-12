# Password Manager

A simple and secure password manager written in Python. This password manager uses a master password to encrypt and decrypt stored passwords, ensuring your sensitive information is protected.

## Features

- **Master Password Protection**: Encrypt all stored passwords with a master password.
- **Secure Encryption**: Uses Fernet (symmetric encryption) for strong encryption.
- **Password Generation**: Generate strong, random passwords.
- **Command-Line Interface (CLI)**: Manage your passwords easily from the terminal.

## Prerequisites

- Python 3.6 or higher
- `cryptography` library

# Add a password
password-manager add example.com --password my_secure_password

# Retrieve a password
password-manager get example.com

# Delete a password
password-manager delete example.com

# Generate a strong, random password
password-manager generate --length 16
