import rsa
from tkinter import messagebox
import Common

# import Design
# Generate a public/private key pair
# 128/ 256/ 384/ 512/ 1024/ 2048/ 3072/ 4096 / 8192 / 16384

def create_keys(size):
    (pubkey, privkey) = rsa.newkeys(int(size))
    return pubkey, privkey

def save_key(value_key):
    # Save the public key
    Common.saveFile(value_key.save_pkcs1("PEM"),"wb", "*.pem")
    
def load_public_key(path):
    # Load the public key
    with open(path + "public.pem" , "rb") as f:
        pubkey = rsa.PublicKey.load_pkcs1(f.read())
    return pubkey

def load_private_key(path):
    # Load the private key
    with open(path + "private.pem" , "rb") as f:
        privkey = rsa.PrivateKey.load_pkcs1(f.read())
    return privkey