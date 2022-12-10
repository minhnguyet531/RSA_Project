import rsa
from tkinter import messagebox
import os
from os import path

list_hash_objects = ["SHA-1", "SHA-256", "SHA-512"]

# Hash message
def hash_message(path_mess, hashType):
    if path.isfile(path_mess) == False:
        messagebox.showinfo("Hash", "File không tồn tại")
        return
    input_mess = open(path_mess, 'rb').read()
    
    hash_msg = rsa.compute_hash(input_mess, hashType)

    return hash_msg

