import rsa
from tkinter import messagebox

import Common
# Tạo chữ ký
def sign_message(hash_msg, path_privkey, hash_method):
    with open(path_privkey , "rb") as f:
        privkey = rsa.PrivateKey.load_pkcs1(f.read())
    signature = rsa.sign_hash(hash_msg, privkey, hash_method)
    return signature



