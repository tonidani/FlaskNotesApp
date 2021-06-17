from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import bcrypt



def get_hashed_password(password):
   
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def get_key(username, password):

    return bcrypt.hashpw(str(username + password).encode('utf-8'), bcrypt.gensalt())


def check_password(password, hashed_password):
 
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

def generate_key_derivation(master_password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bcrypt.gensalt(),
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password))
    return key


def encrypt(key, value_to_encrypt):
    f = Fernet(key)
    encrypted_txt = f.encrypt(value_to_encrypt.encode())
    return encrypted_txt

def decrypt(key, encrypted_txt):
    f = Fernet(key)
    return f.decrypt(encrypted_txt)

