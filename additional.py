import re
import os
import base64
from uuid import uuid4
from functools import wraps
from flask import redirect, session
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# generates unique random url
def gen_id():
    genid = base64.urlsafe_b64encode(bytes.fromhex(uuid4().hex)).decode('utf-8').strip('=')[:7]
    return genid

# login decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function

#custom filter JINJA
def stat(s):
    if s == 0:
        return "No"
    elif s == 1:
        return "Yes"

# Check for file extension - LIST TO BE EXPANDED
def file_check(name):
    exts = {'txt', 'md', 'csv', 'json', 'xml', 'html', 'css', 'js', 'py', 'java', 'c', 'cpp', 'cs', 'h', 'php', 'rb', 'go', 'sh', 'bat', 'pl', 'r', 'kt', 'swift', 'ts'}
    return '.' in name and \
           name.rsplit('.', 1)[1].lower() in exts

# Gen key from password
def keygen(passwd: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(passwd.encode())
    return key

# Encrypt Function
def encrypt(data: bytes, passwd: str):
    salt = os.urandom(16)
    key = keygen(passwd, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)

    cipher = aesgcm.encrypt(nonce, data, None)
    return salt + nonce + cipher

# Decrypt Function
def decrypt(encrypted_data: bytes, passwd: str):
    salt = encrypted_data[:16]
    nonce = encrypted_data[16:28]
    cipher = encrypted_data[28:]
    
    key = keygen(passwd, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, cipher, None)
    
    return plaintext