import rsa
from tkinter import messagebox

import Common
# Tạo chữ ký
def sign_message(hash_msg, path_privkey, hash_method):
    with open(path_privkey , "rb") as f:
        privkey = rsa.PrivateKey.load_pkcs1(f.read())
    signature = rsa.sign_hash(hash_msg, privkey, hash_method)
    return signature

# Lưu chữ ký
def save_signature(signature):
    file = Common.saveFile()
    if file is None:
        return
    text_file = open(file.name, "wb")
    text_file.write(signature)
    text_file.close()
    if text_file.closed:
        messagebox.showinfo("Lưu chữ ký", "Lưu chữ ký thành công")

