from tkinter import *
from tkinter import ttk
from tkinter import messagebox

import GenerateKeys
import paths
import Common
import hashMess
import sign
import verify

root = Tk()
root.title('Chữ ký số')
root.geometry("600x500")

tab_control = ttk.Notebook(root)
tab_control.pack(expand=1, fill='both')
tab1 = ttk.Frame(tab_control)
tab2 = ttk.Frame(tab_control)
tab3 = ttk.Frame(tab_control)

tab_control.add(tab1, text='Tạo khóa')
tab_control.add(tab2, text='Chữ ký số')
tab_control.add(tab3, text='Xác thực chữ ký số')

# =====> Functions 
def openFile(input_txt):
    input_txt.delete(0, 'end')
    filename = Common.openFile(root)
    input_txt.insert(0, filename)


def combobox_size_changed(event):
    retryTab1()
    current_size = combobox_size.get() # Lấy giá trị hiện tại của combobox
    # print(f'Current size: {current_size}')
    return current_size

def create_keys():
    size = selected_size.get()
    global pubkey, privkey 
    pubkey, privkey = GenerateKeys.create_keys(size)
    txtPublicKey.insert(INSERT, pubkey)
    txtPrivateKey.insert(INSERT, privkey)

# =====> Group Khóa (Tab1)
def retryTab1():
    txtPrivateKey.delete('1.0', END)
    txtPublicKey.delete('1.0', END)
LabelFrameKhoa = LabelFrame(tab1, text="Khóa", padx=5, pady=5)
LabelFrameKhoa.pack( padx= 5, pady = 5)

Label(LabelFrameKhoa, text="Chọn kích thước:").grid(row=0, column=0, padx=10)
# Tạo combobox
selected_size = StringVar()
combobox_size = ttk.Combobox(LabelFrameKhoa, textvariable=selected_size, state='readonly', width=9) # state='readonly' để không cho nhập trực tiếp
combobox_size['values'] = ('256', '512', '1024')
combobox_size.set('256')
combobox_size.grid(row=0, column=1, padx=10, pady=10)
combobox_size.bind("<<ComboboxSelected>>",combobox_size_changed) # Lấy giá trị khi combobox được chọn

# === Khóa bí mật
Label(LabelFrameKhoa, text="Khóa bí mật").grid(row=2, column=0, padx=10)
Button(LabelFrameKhoa, text="Lưu", command=lambda: GenerateKeys.save_key(privkey)).grid(row=2, column=1, padx=5, pady=5)
txtPrivateKey = Text(LabelFrameKhoa, height = 5, width = 20)
txtPrivateKey.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

# === Khóa công khai
Label(LabelFrameKhoa, text="Khóa công khai").grid(row=4, column=0, padx=10)
Button(LabelFrameKhoa, text="Lưu", command=lambda: GenerateKeys.save_key(pubkey)).grid(row=4, column=1, padx=5, pady=5)
txtPublicKey = Text(LabelFrameKhoa, height = 5, width = 20)
txtPublicKey.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

Button(LabelFrameKhoa, text="Tạo khóa", command=create_keys).grid(row=6, column=0, padx=10, pady=10)

Button(LabelFrameKhoa, text="Thử lại", command=retryTab1).grid(row=6, column=1, padx=10, pady=10)


# =========> Tạo chữ ký (Người gửi) (tab2)

# =====> Functions for tab 2
def retryTab2():
    entryMessage.delete(0, 'end')
    entryKhoaBiMat.delete(0, 'end'  )
    txtMessageHashed.delete('1.0', END)
    txtSignature.delete('1.0', END   )

def create_signature():
    global hash_message, signature
    message = entryMessage.get() # Lấy path thông điệp
    khoaBiMat = entryKhoaBiMat.get() # Lấy khóa bí mật
    hashType = Common.ShowChoiceHash(selected_hash) # Lấy giá trị hash
    hash_message = hashMess.hash_message(message, hashType) # mã hóa thông điệp
    txtMessageHashed.insert(INSERT, hash_message)
    signature = sign.sign_message( hash_message, khoaBiMat, hashType) # Tạo chữ ký
    txtSignature.insert(INSERT, signature)

LabelFrameTaoChuKy = LabelFrame(tab2, text="Chữ ký số", padx=5, pady=5)
LabelFrameTaoChuKy.pack( padx= 5, pady = 5)

Label(LabelFrameTaoChuKy, text="Thông điệp đầu vào").grid(row=0, column=0, padx=10)
entryMessage = Entry(LabelFrameTaoChuKy, width = 40)
entryMessage.grid(row=0, column=1, padx=10, pady=10)
Button(LabelFrameTaoChuKy, text="Open File", command=lambda: openFile(entryMessage)).grid(row=0, column=2, padx=10, pady=10)


# Tạo radio chọn hàm băm
HASHS  = [
    ("SHA-1", "SHA-1"),
    ("SHA-256", "SHA-256"),
    ("SHA-512", "SHA-512"),
]

selected_hash = StringVar()
selected_hash.set("SHA-256")

for text, mode in HASHS:
    i = HASHS.index((text, mode))
    Radiobutton(LabelFrameTaoChuKy, text= text, variable=selected_hash, value=mode, command=lambda: Common.ShowChoiceHash(selected_hash)).grid(row=1, column=i, padx=5, pady=5)

# === Băm dữ liệu
Label(LabelFrameTaoChuKy, text="Chọn khóa bí mật").grid(row=2, column=0, padx=10)
entryKhoaBiMat = Entry(LabelFrameTaoChuKy, width = 40)
entryKhoaBiMat.grid(row=2, column=1, padx=10, pady=5)
Button(LabelFrameTaoChuKy, text="Open File", command=lambda: openFile(entryKhoaBiMat)).grid(row=2, column=2, padx=10, pady=10)

Label(LabelFrameTaoChuKy, text="Thông điệp sau khi băm").grid(row=3, column=0, padx=10)
Button(LabelFrameTaoChuKy, text="Lưu thông điệp đã băm", command=lambda: Common.saveFile(hash_message, "wb")).grid(row=3, column=2, padx=10, pady=10)
txtMessageHashed = Text(LabelFrameTaoChuKy, height = 5, width = 50)
txtMessageHashed.grid(row=4, column=0, columnspan=3, padx=10, pady=10)
Label(LabelFrameTaoChuKy, text="Chữ ký số").grid(row=5, column=0, padx=10)
txtSignature = Text(LabelFrameTaoChuKy, height = 5, width = 50)
txtSignature.grid(row=6, column=0, columnspan=3, padx=10, pady=10)
Button(LabelFrameTaoChuKy, text="Tạo chữ ký", command=create_signature).grid(row=7, column=0, padx=10, pady=10)

Button(LabelFrameTaoChuKy, text="Lưu chữ ký", command=lambda: Common.saveFile(signature, "wb")).grid(row=7, column=1, padx=10, pady=10)
Button(LabelFrameTaoChuKy, text="Thử lại", command=retryTab2).grid(row=7, column=2, padx=10, pady=10)

# Xác thực chữ ký số (Người nhận) (tab3)
def retryTab3():
    entryMessageTab3.delete(0, 'end')
    entrySignatureTab3.delete(0, 'end')
    entryPublicKeyTab3.delete(0, 'end')

def verify_signature():
    message = entryMessageTab3.get() # Lấy path thông điệp
    signature_path = entrySignatureTab3.get() # Lấy path chữ ký
    public_key = entryPublicKeyTab3.get() # Lấy path khóa công khai
    result = verify.verify_signature( message, signature_path, public_key) # xác thực chữ ký
    if result:
        messagebox.showinfo("Xác thực chữ ký", "Chữ ký hợp lệ")
    else:
        messagebox.showerror("Xác thực chữ ký", "Chữ ký không hợp lệ")

LabelFrameXacNhanChuKyGroup1 = LabelFrame(tab3, text="Xác nhận chữ ký số", padx=5, pady=5)
LabelFrameXacNhanChuKyGroup1.pack(padx=5, pady=5,fill="both", expand="yes")

Label(LabelFrameXacNhanChuKyGroup1, text="Thông điệp dữ liệu").grid(row=0, column=0, padx=10)
entryMessageTab3 = Entry(LabelFrameXacNhanChuKyGroup1, width = 40)
entryMessageTab3.grid(row=0, column=1, padx=10, pady=10)
Button(LabelFrameXacNhanChuKyGroup1, text="Open File", command=lambda: openFile(entryMessageTab3)).grid(row=0, column=2, padx=10, pady=10)

# Tạo radio chọn hàm băm
HASHS  = [
    ("SHA-1", "SHA-1"),
    ("SHA-256", "SHA-256"),
    ("SHA-512", "SHA-512"),
]

selected_hash_verify = StringVar()
selected_hash_verify.set("SHA-256")

for text, mode in HASHS:
    i = HASHS.index((text, mode))
    Radiobutton(LabelFrameXacNhanChuKyGroup1, text= text, variable=selected_hash_verify, value=mode, command=lambda: Common.ShowChoiceHash(selected_hash_verify)).grid(row=1, column=i, padx=5, pady=5)

Label(LabelFrameXacNhanChuKyGroup1, text="Chữ ký số").grid(row=2, column=0, padx=10)
entrySignatureTab3 = Entry(LabelFrameXacNhanChuKyGroup1, width = 40)
entrySignatureTab3.grid(row=2, column=1, padx=10, pady=5)
Button(LabelFrameXacNhanChuKyGroup1, text="Open File", command=lambda: openFile(entrySignatureTab3)).grid(row=2, column=2, padx=10, pady=10)

Label(LabelFrameXacNhanChuKyGroup1, text="Chọn khóa công khai").grid(row=3, column=0, padx=10)
entryPublicKeyTab3 = Entry(LabelFrameXacNhanChuKyGroup1, width = 40)
entryPublicKeyTab3.grid(row=3, column=1, padx=10, pady=5)
Button(LabelFrameXacNhanChuKyGroup1, text="Open File", command=lambda: openFile(entryPublicKeyTab3)).grid(row=3, column=2, padx=10, pady=10)

Button(LabelFrameXacNhanChuKyGroup1, text="Xác minh chữ ký", command=verify_signature).grid(row=4, column=1, padx=10, pady=10)
Button(LabelFrameXacNhanChuKyGroup1, text="Thử lại", command=retryTab3).grid(row=5, column=1, padx=5, pady=5)

root.mainloop()