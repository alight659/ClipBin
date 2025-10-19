import re
import os
import csv
import json
import base64
import pyotp
from uuid import uuid4
from functools import wraps
from io import StringIO, BytesIO
from flask import redirect, session
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# generates unique random url
def gen_id():
    genid = base64.urlsafe_b64encode(bytes.fromhex(uuid4().hex)).decode("utf-8").strip("=")[:7]
    return genid


# login decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function


# custom filter JINJA
def stat(s):
    if s == 0:
        return "No"
    elif s == 1:
        return "Yes"


# Check for file extension #LIST TO BE EXPANDED
def file_check(name):
    exts = {
        "txt",
        "md",
        "csv",
        "json",
        "xml",
        "html",
        "css",
        "js",
        "py",
        "java",
        "c",
        "cpp",
        "cs",
        "h",
        "php",
        "rb",
        "go",
        "sh",
        "bat",
        "pl",
        "r",
        "kt",
        "swift",
        "ts",
    }
    return "." in name and name.rsplit(".", 1)[1].lower() in exts


# Gen key from password
def keygen(passwd: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
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
    if isinstance(encrypted_data, str):
        encrypted_data = encrypted_data.encode("latin-1")
    salt = encrypted_data[:16]
    nonce = encrypted_data[16:28]
    cipher = encrypted_data[28:]

    key = keygen(passwd, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, cipher, None)

    return plaintext


# Validate custom alias
def validate_alias(alias):
    # Check if alias length is between 4 and 12 characters
    if len(alias) < 4 or len(alias) > 12:
        return False
    # Check if alias contains only alphanumeric, hyphen and underscore
    pattern = r"^[a-zA-Z0-9_-]+$"
    return bool(re.match(pattern, alias))


# CSVfy data Function
def csvfy(data):
    if not data:
        return ""

    output = StringIO()
    fields = data[0].keys()
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    writer.writerows(data)

    csv_string = output.getvalue()
    output.close()
    return csv_string


# Textify data Function
def textify(data):
    buffer = StringIO()
    for i, element in enumerate(data):
        if i > 0:
            buffer.write("\n\n")
        buffer.write(
            f"ID: {element['id']}\n"
            f"Name: {element['name']}\n"
            f"Text: {element['text']}\n"
            f"Time: {element['time']}"
        )
    return buffer.getvalue()


# Jsonify Export Data Function
def jsonfy(data):
    json_data = StringIO()
    json.dump(data, json_data, indent=4, ensure_ascii=False)

    json_bytes = BytesIO(json_data.getvalue().encode("utf-8"))
    json_bytes.seek(0)

    return json_bytes


# Generate TOTP secret and provisioning URI
def totp_generator(user_id: str, username: str):
    totp_secret = pyotp.random_base32()
    encrypted_bytes = encrypt(totp_secret.encode("utf-8"), str(user_id) + username)
    encrypted_b64 = base64.b64encode(encrypted_bytes).decode("utf-8")
    provisioning_uri = pyotp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="Clipbin")
    return encrypted_b64, provisioning_uri


# Decrypt TOTP secret
def totpCode(encrypted_secret: str, user_id: str, username: str):
    try:
        encrypted_bytes = base64.b64decode(encrypted_secret)
        decrypted_bytes = decrypt(encrypted_bytes, str(user_id) + username)
        return decrypted_bytes.decode("utf-8")
    except Exception as e:
        raise ValueError(f"Failed to decrypt TOTP secret: {str(e)}")


# Verify TOTP code
def totp_verify(encrypted_secret_b64: str, user_id: str, username: str, otp_code: str, last_used: str = None) -> bool:
    try:
        totp_secret = totpCode(encrypted_secret_b64, user_id, username)
        totp = pyotp.TOTP(totp_secret)
        # Check if the provided code matches the last used code
        if last_used and otp_code == last_used:
            return False  # Prevent reuse of the same TOTP code
        return totp.verify(otp_code, valid_window=1)
    except Exception:
        return False
