from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from tkinter.filedialog import asksaveasfile
import paths
from tkinter import messagebox

files = [('All Files', '*.*'),  
             ('Python Files', '*.py'), 
             ('Text Document', '*.txt'),
             ('Image Files', '*.png'),
             ('KEY Files', '*.pem'),]

def openFile(root):
    root.filename = filedialog.askopenfilename(initialdir = paths.path, title = "Select a File", filetypes = files)
    return root.filename

def saveFile(value, type_file = "w"):
    file = asksaveasfile(initialdir = paths.path, filetypes = files, defaultextension = files)
    if file is None:
        return
    with open(file.name, type_file) as text_file:
        text_file.write(value)
        text_file.close()
        if text_file.closed:
            messagebox.showinfo("Lưu file", "Lưu file thành công")
    
def ShowChoiceHash(element):
    value_hash = element.get()
    return value_hash

