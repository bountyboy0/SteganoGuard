# SteganoGuard

Secure image steganography with hybrid RSA and Fernet encryption.

## Overview

SteganoGuard is a secure image steganography tool that uses robust RSA (4096-bit) and Fernet encryption to hide sensitive messages within images. Designed for high-security applications, it features an intuitive command-line interface with colorful prompts.

## Features

- **Hybrid Encryption:** Uses RSA for secure key exchange and Fernet for message encryption.
- **Cross-Platform:** Works on both Windows and Linux.
- **User-Friendly:** Colorful terminal output and automatic file extension handling.
- **Secure Data Hiding:** Embed encrypted messages into images with ease.

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/bountyboy0/SteganoGuard.git
   cd SteganoGuard

Install dependencies:
pip install -r requirements.txt

Run the tool:
python3 steganography.py 


Usage
After running the tool, you will be prompted with three options:

Generate RSA Key Pair: Create a secure 4096-bit RSA key pair.
Encode Message: Encrypt and embed a message into an image.
Decode Message: Extract and decrypt the hidden message from an image.
Follow the on-screen instructions to use the desired feature.

Requirements
Python 3.x
Pillow
stepic
cryptography
colorama
License

This project is licensed under the MIT License.

Author
AJ

