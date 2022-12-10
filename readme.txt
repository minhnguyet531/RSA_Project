1. Mô tả các file
Common.py => Lưu các hàm dùng chung cho chương trình
Design.py => Lưu các thiết kế form chương trình
GenerateKeys.py => Lưu hàm tạo public_key, private_key và các hàm liên quan đến khóa
hashMess.py => Lưu hàm dùng để băm thông điệp đầu vào
paths.py => Lưu các đường dẫn chính của thư mục
sign.py => Lưu hàm tạo chữ ký số
verify.py => Lưu hàm xác minh chữ ký số

2. Thư viện sử dụng chính là RSA của python để tạo chữ ký và xác minh chữ ký
pip install rsa

3. Thư viện tkinter của python để code form chương trình
pip install tk

4. Hàm chính trong bài
(pubkey, privkey) = rsa.newkeys(size) => Tạo khóa
rsa.PublicKey.load_pkcs1() => Load khóa công khai
rsa.PrivateKey.load_pkcs1() => Load khóa bí mật
rsa.compute_hash(input_mess, hashType) => Hàm băm
rsa.sign_hash(hash_msg, privkey, hash_method) => Tạo chữ ký
rsa.verify(message, signature, pubkey) => Xác minh chữ ký