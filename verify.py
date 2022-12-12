import rsa

# Xac thuc chữ ký
def verify_signature( path_message, path_signature, path_pubkey):
    with open(path_message, "rb") as f:
        message = f.read()
    
    with open(path_signature , "rb") as f:
        signature = f.read()

    with open(path_pubkey , "rb") as f:
        pubkey = rsa.PublicKey.load_pkcs1(f.read())

    # print(rsa.verify(message, signature, pubkey))
    try:
        rsa.verify(message, signature, pubkey)
        return True
    except rsa.pkcs1.VerificationError:
        return False





    