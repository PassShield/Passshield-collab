
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import threading
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import json
import os
import hashlib
import random
import string
import re
from datetime import datetime
import pyperclip
import secrets
import binascii
import time
from PIL import Image, ImageTk
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

# Constants
DB_FILE = "passshield_db.json"
USERS_FILE = "users_db.json"
SECURITY_QUESTIONS = [
    "What was the name of your first pet?",
    "What was your childhood nickname?",
    "What is the name of your favorite book?",
    "What was the name of your first school?",
    "What is your mother's maiden name?",
    "What was your first car's model?",
    "What city were you born in?",
    "What is your favorite movie?",
    "What was the name of your first teacher?",
    "What is your favorite sports team?"
]

CAPTCHA_QUESTIONS = [
    {"question": "What is 3 + 5?", "answer": "8"},
    {"question": "What is the capital of France?", "answer": "paris"},
    {"question": "What color is the sky on a clear day?", "answer": "blue"},
    {"question": "How many sides does a triangle have?", "answer": "3"},
    {"question": "What is the opposite of 'day'?", "answer": "night"}
]

# Utility functions
def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def hash_password(password):
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), 
                                salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')

def verify_password(stored_password, provided_password):
    salt = stored_password[:64]
    stored_password = stored_password[64:]
    pwdhash = hashlib.pbkdf2_hmac('sha512', 
                                  provided_password.encode('utf-8'), 
                                  salt.encode('ascii'), 
                                  100000)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    return pwdhash == stored_password

def load_db():
    if not os.path.exists(DB_FILE):
        return {}
    try:
        with open(DB_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_db(data):
    with open(DB_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_users(data):
    with open(USERS_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def get_user_by_email_or_username(identifier, users_db):
    for username, user in users_db.items():
        if user['email'].lower() == identifier.lower() or username.lower() == identifier.lower():
            return user
    return None

def check_password_strength(password):
    if len(password) < 15:
        return "Weak (must be at least 15 characters)"
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    missing = []
    if not has_upper:
        missing.append("uppercase letter")
    if not has_lower:
        missing.append("lowercase letter")
    if not has_digit:
        missing.append("digit")
    if not has_special:
        missing.append("special character")
    
    if missing:
        return f"Weak (missing: {', '.join(missing)})"
    
    if password.lower() in ['password', '12345678', 'qwerty']:
        return "Very Weak (common password)"
    
    return "Excellent"

def generate_strong_password(length=20):
    chars = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(chars) for _ in range(length))
        if any(c.islower() for c in password) and \
           any(c.isupper() for c in password) and \
           any(c.isdigit() for c in password) and \
           any(c in string.punctuation for c in password):
            return password

def generate_pin(length=6):
    return ''.join(secrets.choice(string.digits) for _ in range(length))

def validate_pin(pin):
    return len(pin) >= 4 and pin.isdigit()

def encrypt_data(data, password):
    """Encrypt data with password"""
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    f = Fernet(key)
    encrypted = f.encrypt(data.encode())
    
    return salt + encrypted

def decrypt_data(encrypted_data, password):
    """Decrypt data with password"""
    salt = encrypted_data[:16]
    encrypted = encrypted_data[16:]
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    f = Fernet(key)
    try:
        decrypted = f.decrypt(encrypted)
        return decrypted.decode()
    except:
        raise ValueError("Incorrect password or corrupted data")

# Main Application
class PassShieldApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PassShield - Secure Password Manager")
        self.geometry("1000x700")
        self.configure(bg='#e0f0ff')
        
        self.users_db = load_users()
        self.password_db = load_db()
        self.current_user = None
        self.current_username = None
        
        # Create container frame
        self.container = tk.Frame(self, bg='#e0f0ff')
        self.container.pack(side="top", fill="both", expand=True)
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)
        
        # Initialize all frames
        self.frames = {}
        for F in (SignInPage, SignUpPage, ForgotPasswordPage, 
                  StoragePage, SettingsPage, ChangePasswordPage):
            frame = F(self.container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        
        self.show_frame(SignInPage)
    
    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()
        if hasattr(frame, 'on_show'):
            frame.on_show()

# Pages
class SignInPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(bg='#e0f0ff')
        self.show_password = False
        self.font_conf = ('Arial', 14)
        
        # Center container
        center_frame = tk.Frame(self, bg='#e0f0ff')
        center_frame.place(relx=0.5, rely=0.5, anchor='center')
        
        # Logo
        try:
            self.logo_img = Image.open("images/logo.png")
            self.logo_img = self.logo_img.resize((150, 150), Image.LANCZOS)
            self.logo_photo = ImageTk.PhotoImage(self.logo_img)
            logo_label = tk.Label(center_frame, image=self.logo_photo, bg='#e0f0ff')
            logo_label.pack(pady=10)
        except:
            tk.Label(center_frame, text="PassShield", font=('Arial', 24, 'bold'), 
                    bg='#e0f0ff', fg='black').pack(pady=10)
        
        tk.Label(center_frame, text="Sign In", font=('Arial', 20, 'bold'), 
                bg='#e0f0ff', fg='black').pack(pady=5)
        
        # Entry Frame
        entry_frame = tk.Frame(center_frame, bg='#f0f0f0', padx=20, pady=20, bd=1, relief='solid')
        entry_frame.pack(pady=10, padx=20, fill='x')
        
        # Username/Email
        tk.Label(entry_frame, text="Username or Email:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w', pady=(0, 5))
        self.identifier_entry = tk.Entry(entry_frame, font=self.font_conf, 
                                       relief='solid', highlightthickness=0,
                                       bd=1, bg='white', fg='black', 
                                       insertbackground='black', insertwidth=2)
        self.identifier_entry.pack(fill='x', pady=5, ipady=5)
        
        # Password
        tk.Label(entry_frame, text="Password:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w', pady=(10, 5))
        
        password_frame = tk.Frame(entry_frame, bg='#f0f0f0')
        password_frame.pack(fill='x', pady=5)
        
        self.password_entry = tk.Entry(password_frame, font=self.font_conf, show="•", 
                                     relief='solid', highlightthickness=0, bd=1, 
                                     bg='white', fg='black', insertbackground='black', 
                                     insertwidth=2)
        self.password_entry.pack(side='left', fill='x', expand=True, ipady=5)
        
        self.toggle_pass_btn = tk.Button(password_frame, text="Show", command=self.toggle_password, 
                                       bg='#e0f0ff', fg='black', relief='solid', bd=1,
                                       font=self.font_conf, padx=10, cursor='hand2')
        self.toggle_pass_btn.pack(side='left', padx=5)
        
        # Button Frame
        button_frame = tk.Frame(center_frame, bg='#e0f0ff')
        button_frame.pack(pady=15, fill='x', padx=20)
        
        tk.Button(button_frame, text="Login", command=self.login, font=self.font_conf,
                 bg='#4CAF50', fg='black', relief='solid', bd=1, padx=20, pady=5,
                 cursor='hand2').pack(pady=5, fill='x')
        
        tk.Button(button_frame, text="Forgot Password?", 
                 command=lambda: controller.show_frame(ForgotPasswordPage), 
                 font=self.font_conf, fg="blue", bg='#e0f0ff', relief='flat',
                 cursor='hand2').pack(pady=5)
        
        tk.Button(button_frame, text="Change Password", 
                 command=lambda: controller.show_frame(ChangePasswordPage), 
                 font=self.font_conf, fg="blue", bg='#e0f0ff', relief='flat',
                 cursor='hand2').pack(pady=5)
        
        tk.Button(button_frame, text="Don't have an account? Sign Up", 
                 command=lambda: controller.show_frame(SignUpPage), 
                 font=self.font_conf, fg="blue", bg='#e0f0ff', relief='flat',
                 cursor='hand2').pack(pady=5)
        
        # Status label
        self.status_label = tk.Label(center_frame, text="", font=self.font_conf, 
                                    bg='#e0f0ff', fg='red')
        self.status_label.pack(pady=5)
    
    def toggle_password(self):
        self.show_password = not self.show_password
        show_char = "" if self.show_password else "•"
        self.password_entry.config(show=show_char)
        self.toggle_pass_btn.config(text="Hide" if self.show_password else "Show")
    
    def login(self):
        identifier = self.identifier_entry.get().strip()
        password = self.password_entry.get()
        
        if not identifier or not password:
            self.status_label.config(text="Username/email and password are required", fg='red')
            return
        
        user = get_user_by_email_or_username(identifier, self.controller.users_db)
        if not user:
            self.status_label.config(text="User not found", fg='red')
            return
        
        if not verify_password(user['password'], password):
            self.status_label.config(text="Invalid password", fg='red')
            return
        
        # Login successful
        self.controller.current_user = user
        self.controller.current_username = user['username']
        
        # Show welcome message
        messagebox.showinfo("Welcome", f"Welcome back, {user['username']}!", parent=self)
        
        self.controller.show_frame(StoragePage)
        
        # Clear fields
        self.identifier_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.status_label.config(text="")

class ChangePasswordPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(bg='#e0f0ff')
        self.show_password = False
        self.show_new_password = False
        self.show_confirm_password = False
        self.font_conf = ('Arial', 14)
        
        # Center container
        center_frame = tk.Frame(self, bg='#e0f0ff')
        center_frame.place(relx=0.5, rely=0.5, anchor='center')
        
        # Logo
        try:
            self.logo_img = Image.open("images/logo.png")
            self.logo_img = self.logo_img.resize((150, 150), Image.LANCZOS)
            self.logo_photo = ImageTk.PhotoImage(self.logo_img)
            logo_label = tk.Label(center_frame, image=self.logo_photo, bg='#e0f0ff')
            logo_label.pack(pady=10)
        except:
            tk.Label(center_frame, text="PassShield", font=('Arial', 24, 'bold'), 
                    bg='#e0f0ff', fg='black').pack(pady=10)
        
        tk.Label(center_frame, text="Change Password", font=('Arial', 20, 'bold'), 
                bg='#e0f0ff', fg='black').pack(pady=5)
        
        # Entry Frame
        entry_frame = tk.Frame(center_frame, bg='#f0f0f0', padx=20, pady=20, bd=1, relief='solid')
        entry_frame.pack(pady=10, padx=20, fill='x')
        
        # Username/Email
        tk.Label(entry_frame, text="Username or Email:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w', pady=(0, 5))
        self.identifier_entry = tk.Entry(entry_frame, font=self.font_conf, 
                                       relief='solid', highlightthickness=0,
                                       bd=1, bg='white', fg='black', 
                                       insertbackground='black', insertwidth=2)
        self.identifier_entry.pack(fill='x', pady=5, ipady=5)
        
        # Current Password
        tk.Label(entry_frame, text="Current Password:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w', pady=(10, 5))
        
        current_pass_frame = tk.Frame(entry_frame, bg='#f0f0f0')
        current_pass_frame.pack(fill='x', pady=5)
        
        self.current_password_entry = tk.Entry(current_pass_frame, font=self.font_conf, show="•", 
                                             relief='solid', highlightthickness=0, bd=1, 
                                             bg='white', fg='black', insertbackground='black', 
                                             insertwidth=2)
        self.current_password_entry.pack(side='left', fill='x', expand=True, ipady=5)
        
        self.toggle_current_pass_btn = tk.Button(current_pass_frame, text="Show", command=self.toggle_current_password, 
                                               bg='#e0f0ff', fg='black', relief='solid', bd=1,
                                               font=self.font_conf, padx=10, cursor='hand2')
        self.toggle_current_pass_btn.pack(side='left', padx=5)
        
        # New Password
        tk.Label(entry_frame, text="New Password:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w', pady=(10, 5))
        
        new_pass_frame = tk.Frame(entry_frame, bg='#f0f0f0')
        new_pass_frame.pack(fill='x', pady=5)
        
        self.new_password_entry = tk.Entry(new_pass_frame, font=self.font_conf, show="•", 
                                         relief='solid', highlightthickness=0, bd=1, 
                                         bg='white', fg='black', insertbackground='black', 
                                         insertwidth=2)
        self.new_password_entry.pack(side='left', fill='x', expand=True, ipady=5)
        
        self.toggle_new_pass_btn = tk.Button(new_pass_frame, text="Show", command=self.toggle_new_password, 
                                           bg='#e0f0ff', fg='black', relief='solid', bd=1,
                                           font=self.font_conf, padx=10, cursor='hand2')
        self.toggle_new_pass_btn.pack(side='left', padx=5)
        
        # Password strength
        self.password_strength = tk.Label(entry_frame, text="", font=('Arial', 12), 
                                        bg='#f0f0f0', fg='red')
        self.password_strength.pack(anchor='w', pady=(5, 0))
        self.new_password_entry.bind('<KeyRelease>', self.check_password_strength)
        
        # Confirm Password
        tk.Label(entry_frame, text="Confirm New Password:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w', pady=(10, 5))
        
        confirm_frame = tk.Frame(entry_frame, bg='#f0f0f0')
        confirm_frame.pack(fill='x', pady=5)
        
        self.confirm_password_entry = tk.Entry(confirm_frame, font=self.font_conf, show="•", 
                                             relief='solid', highlightthickness=0, bd=1, 
                                             bg='white', fg='black', insertbackground='black', 
                                             insertwidth=2)
        self.confirm_password_entry.pack(side='left', fill='x', expand=True, ipady=5)
        
        self.toggle_confirm_btn = tk.Button(confirm_frame, text="Show", command=self.toggle_confirm_password, 
                                          bg='#e0f0ff', fg='black', relief='solid', bd=1,
                                          font=self.font_conf, padx=10, cursor='hand2')
        self.toggle_confirm_btn.pack(side='left', padx=5)
        
        # Status label
        self.status_label = tk.Label(entry_frame, text="", font=self.font_conf, 
                                    bg='#f0f0f0', fg='red')
        self.status_label.pack(pady=10)
        
        # Button Frame
        button_frame = tk.Frame(center_frame, bg='#e0f0ff')
        button_frame.pack(pady=15, fill='x', padx=20)
        
        tk.Button(button_frame, text="Change Password", command=self.change_password, font=self.font_conf,
                 bg='#4CAF50', fg='white', relief='solid', bd=1, padx=20, pady=5,
                 cursor='hand2').pack(pady=5, fill='x')
        
        tk.Button(button_frame, text="Back to Sign In", 
                 command=lambda: controller.show_frame(SignInPage), 
                 font=self.font_conf, fg="blue", bg='#e0f0ff', relief='flat',
                 cursor='hand2').pack(pady=5)
    
    def toggle_current_password(self):
        self.show_password = not self.show_password
        show_char = "" if self.show_password else "•"
        self.current_password_entry.config(show=show_char)
        self.toggle_current_pass_btn.config(text="Hide" if self.show_password else "Show")
    
    def toggle_new_password(self):
        self.show_new_password = not self.show_new_password
        show_char = "" if self.show_new_password else "•"
        self.new_password_entry.config(show=show_char)
        self.toggle_new_pass_btn.config(text="Hide" if self.show_new_password else "Show")
    
    def toggle_confirm_password(self):
        self.show_confirm_password = not self.show_confirm_password
        show_char = "" if self.show_confirm_password else "•"
        self.confirm_password_entry.config(show=show_char)
        self.toggle_confirm_btn.config(text="Hide" if self.show_confirm_password else "Show")
    
    def check_password_strength(self, event=None):
        password = self.new_password_entry.get()
        strength = check_password_strength(password)
        if "Weak" in strength:
            self.password_strength.config(text=strength, fg='red')
        else:
            self.password_strength.config(text=strength, fg='green')
    
    def change_password(self):
        identifier = self.identifier_entry.get().strip()
        current_password = self.current_password_entry.get()
        new_password = self.new_password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        
        # Validate fields
        if not all([identifier, current_password, new_password, confirm_password]):
            self.status_label.config(text="All fields are required", fg='red')
            return
        
        user = get_user_by_email_or_username(identifier, self.controller.users_db)
        if not user:
            self.status_label.config(text="User not found", fg='red')
            return
        
        if not verify_password(user['password'], current_password):
            self.status_label.config(text="Current password is incorrect", fg='red')
            return
        
        if len(new_password) < 15:
            self.status_label.config(text="Password must be at least 15 characters", fg='red')
            return
        
        if new_password != confirm_password:
            self.status_label.config(text="New passwords don't match", fg='red')
            return
        
        # Check password strength
        strength = check_password_strength(new_password)
        if "Weak" in strength:
            self.status_label.config(text=f"Password too weak: {strength}", fg='red')
            return
        
        # Update password
        self.controller.users_db[user['username']]['password'] = hash_password(new_password)
        save_users(self.controller.users_db)
        
        self.status_label.config(text="Password changed successfully!", fg='green')
        
        # Clear fields
        self.identifier_entry.delete(0, tk.END)
        self.current_password_entry.delete(0, tk.END)
        self.new_password_entry.delete(0, tk.END)
        self.confirm_password_entry.delete(0, tk.END)
        self.password_strength.config(text="")
        
        # Auto switch to login after 2 seconds
        self.after(2000, lambda: self.controller.show_frame(SignInPage))

class SignUpPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(bg='#e0f0ff')
        self.show_password = False
        self.show_confirm_password = False
        self.show_pin = False
        self.show_confirm_pin = False
        self.font_conf = ('Arial', 14)
        self.captcha_attempts = 0
        self.captcha_locked = False
        self.captcha_lock_time = 0
        self.current_captcha = None

        # Main container using grid
        main_container = tk.Frame(self, bg='#e0f0ff')
        main_container.pack(fill='both', expand=True)
        main_container.grid_columnconfigure(1, weight=1)
        main_container.grid_rowconfigure(0, weight=1)

        # Left Logo Frame
        left_logo_frame = tk.Frame(main_container, bg='#e0f0ff', width=300)
        left_logo_frame.grid(row=0, column=0, sticky='ns')
        left_logo_frame.pack_propagate(False)

        # Logo and Header
        logo_container = tk.Frame(left_logo_frame, bg='#e0f0ff')
        logo_container.place(relx=0.5, rely=0.5, anchor='center')
        
        try:
            self.logo_img = Image.open("images/logo.png")
            self.logo_img = self.logo_img.resize((150, 150), Image.LANCZOS)
            self.logo_photo = ImageTk.PhotoImage(self.logo_img)
            logo_label = tk.Label(logo_container, image=self.logo_photo, bg='#e0f0ff')
            logo_label.pack(pady=10)
        except:
            tk.Label(logo_container, text="PassShield", font=('Arial', 24, 'bold'), 
                    bg='#e0f0ff', fg='black').pack(pady=10)
        
        tk.Label(logo_container, text="Create Account", font=('Arial', 22, 'bold'), 
                bg='#e0f0ff', fg='black').pack()

        # Right Form Frame with Scrollbar
        right_form_frame = tk.Frame(main_container, bg='#e0f0ff')
        right_form_frame.grid(row=0, column=1, sticky='nsew')

        # Scrollable Canvas
        canvas = tk.Canvas(right_form_frame, bg='#e0f0ff', highlightthickness=0)
        scrollbar = ttk.Scrollbar(right_form_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg='#e0f0ff')

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Content frame
        content_frame = tk.Frame(scrollable_frame, bg='#e0f0ff')
        content_frame.pack(fill='both', expand=True, padx=40, pady=40)

        # Entry Frame
        entry_frame = tk.Frame(content_frame, bg='#f0f0f0', padx=40, pady=40, bd=1, relief='solid')
        entry_frame.pack(fill='x', pady=20)
        
        # Configure grid layout for form elements
        entry_frame.grid_columnconfigure(1, weight=1)
        row = 0

        # Username
        tk.Label(entry_frame, text="Username (min 7 chars):", font=self.font_conf, 
                bg='#f0f0f0', fg='black').grid(row=row, column=0, sticky='w', pady=10)
        self.username_entry = tk.Entry(entry_frame, font=self.font_conf, 
                                     relief='solid', highlightthickness=0,
                                     bd=1, bg='white', fg='black', 
                                     insertbackground='black', insertwidth=2)
        self.username_entry.grid(row=row, column=1, sticky='ew', pady=10, padx=10, ipady=5)
        row += 1

        # Email
        tk.Label(entry_frame, text="Email:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').grid(row=row, column=0, sticky='w', pady=10)
        self.email_entry = tk.Entry(entry_frame, font=self.font_conf, 
                                  relief='solid', highlightthickness=0,
                                  bd=1, bg='white', fg='black', 
                                  insertbackground='black', insertwidth=2)
        self.email_entry.grid(row=row, column=1, sticky='ew', pady=10, padx=10, ipady=5)
        row += 1

        # Password
        tk.Label(entry_frame, text="Password (min 15 chars):", font=self.font_conf, 
                bg='#f0f0f0', fg='black').grid(row=row, column=0, sticky='w', pady=10)
        
        password_frame = tk.Frame(entry_frame, bg='#f0f0f0')
        password_frame.grid(row=row, column=1, sticky='ew', pady=10, padx=10)
        
        self.password_entry = tk.Entry(password_frame, font=self.font_conf, show="•", 
                                     relief='solid', highlightthickness=0, bd=1, 
                                     bg='white', fg='black', insertbackground='black', 
                                     insertwidth=2)
        self.password_entry.pack(side='left', fill='x', expand=True, ipady=5)
        
        self.toggle_pass_btn = tk.Button(password_frame, text="Show", command=self.toggle_password, 
                                       bg='#e0f0ff', fg='black', relief='solid', bd=1,
                                       font=self.font_conf, padx=15, cursor='hand2')
        self.toggle_pass_btn.pack(side='left', padx=5)
        row += 1

        # Password strength
        self.password_strength = tk.Label(entry_frame, text="", font=('Arial', 12), 
                                        bg='#f0f0f0', fg='red')
        self.password_strength.grid(row=row, column=1, sticky='w', pady=(0, 10))
        self.password_entry.bind('<KeyRelease>', self.check_password_strength)
        row += 1

        # Confirm Password
        tk.Label(entry_frame, text="Confirm Password:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').grid(row=row, column=0, sticky='w', pady=10)
        
        confirm_frame = tk.Frame(entry_frame, bg='#f0f0f0')
        confirm_frame.grid(row=row, column=1, sticky='ew', pady=10, padx=10)
        
        self.confirm_password = tk.Entry(confirm_frame, font=self.font_conf, show="•", 
                                       relief='solid', highlightthickness=0, bd=1, 
                                       bg='white', fg='black', insertbackground='black', 
                                       insertwidth=2)
        self.confirm_password.pack(side='left', fill='x', expand=True, ipady=5)
        
        self.toggle_confirm_btn = tk.Button(confirm_frame, text="Show", command=self.toggle_confirm_password, 
                                          bg='#e0f0ff', fg='black', relief='solid', bd=1,
                                          font=self.font_conf, padx=15, cursor='hand2')
        self.toggle_confirm_btn.pack(side='left', padx=5)
        row += 1

        # PIN
        tk.Label(entry_frame, text="6-digit PIN:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').grid(row=row, column=0, sticky='w', pady=10)
        
        pin_frame = tk.Frame(entry_frame, bg='#f0f0f0')
        pin_frame.grid(row=row, column=1, sticky='ew', pady=10, padx=10)
        
        self.pin_entry = tk.Entry(pin_frame, font=self.font_conf, show="•", 
                                relief='solid', highlightthickness=0, bd=1, 
                                bg='white', fg='black', insertbackground='black', 
                                insertwidth=2)
        self.pin_entry.pack(side='left', fill='x', expand=True, ipady=5)
        
        self.toggle_pin_btn = tk.Button(pin_frame, text="Show", command=self.toggle_pin, 
                                      bg='#e0f0ff', fg='black', relief='solid', bd=1,
                                      font=self.font_conf, padx=15, cursor='hand2')
        self.toggle_pin_btn.pack(side='left', padx=5)
        row += 1

        # Confirm PIN
        tk.Label(entry_frame, text="Confirm 6-digit PIN:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').grid(row=row, column=0, sticky='w', pady=10)
        
        confirm_pin_frame = tk.Frame(entry_frame, bg='#f0f0f0')
        confirm_pin_frame.grid(row=row, column=1, sticky='ew', pady=10, padx=10)
        
        self.confirm_pin_entry = tk.Entry(confirm_pin_frame, font=self.font_conf, show="•", 
                                        relief='solid', highlightthickness=0, bd=1, 
                                        bg='white', fg='black', insertbackground='black', 
                                        insertwidth=2)
        self.confirm_pin_entry.pack(side='left', fill='x', expand=True, ipady=5)
        
        self.toggle_confirm_pin_btn = tk.Button(confirm_pin_frame, text="Show", command=self.toggle_confirm_pin, 
                                              bg='#e0f0ff', fg='black', relief='solid', bd=1,
                                              font=self.font_conf, padx=15, cursor='hand2')
        self.toggle_confirm_pin_btn.pack(side='left', padx=5)
        row += 1

        # Security Question
        tk.Label(entry_frame, text="Security Question:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').grid(row=row, column=0, sticky='w', pady=10)
        
        self.security_question = ttk.Combobox(entry_frame, values=SECURITY_QUESTIONS, 
                                            font=self.font_conf, state="readonly")
        self.security_question.grid(row=row, column=1, sticky='ew', pady=10, padx=10, ipady=5)
        row += 1

        # Security Answer
        tk.Label(entry_frame, text="Security Answer:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').grid(row=row, column=0, sticky='w', pady=10)
        self.security_answer = tk.Entry(entry_frame, font=self.font_conf,
                                      relief='solid', highlightthickness=0,
                                      bd=1, bg='white', fg='black',
                                      insertbackground='black', insertwidth=2)
        self.security_answer.grid(row=row, column=1, sticky='ew', pady=10, padx=10, ipady=5)
        row += 1

        # CAPTCHA
        self.captcha_label = tk.Label(entry_frame, text="", font=self.font_conf,
                                    bg='#f0f0f0', fg='black')
        self.captcha_label.grid(row=row, column=0, sticky='w', pady=10)
        
        self.captcha_entry = tk.Entry(entry_frame, font=self.font_conf,
                                    relief='solid', highlightthickness=0,
                                    bd=1, bg='white', fg='black',
                                    insertbackground='black', insertwidth=2)
        self.captcha_entry.grid(row=row, column=1, sticky='ew', pady=10, padx=10, ipady=5)
        row += 1

        # Generate initial CAPTCHA
        self.generate_captcha()

        # Status label
        self.status_label = tk.Label(entry_frame, text="", font=self.font_conf,
                                   bg='#f0f0f0', fg='red')
        self.status_label.grid(row=row, column=0, columnspan=2, pady=10)
        row += 1

        # Button Frame
        button_frame = tk.Frame(content_frame, bg='#e0f0ff')
        button_frame.pack(fill='x', pady=20)

        tk.Button(button_frame, text="Create Account", command=self.signup, font=self.font_conf,
                 bg='#4CAF50', fg='white', relief='solid', bd=1, padx=20, pady=5,
                 cursor='hand2').pack(pady=5, fill='x')

        tk.Button(button_frame, text="Already have an account? Sign In",
                 command=lambda: controller.show_frame(SignInPage),
                 font=self.font_conf, fg="blue", bg='#e0f0ff', relief='flat',
                 cursor='hand2').pack(pady=5)

    def toggle_password(self):
        self.show_password = not self.show_password
        show_char = "" if self.show_password else "•"
        self.password_entry.config(show=show_char)
        self.toggle_pass_btn.config(text="Hide" if self.show_password else "Show")

    def toggle_confirm_password(self):
        self.show_confirm_password = not self.show_confirm_password
        show_char = "" if self.show_confirm_password else "•"
        self.confirm_password.config(show=show_char)
        self.toggle_confirm_btn.config(text="Hide" if self.show_confirm_password else "Show")

    def toggle_pin(self):
        self.show_pin = not self.show_pin
        show_char = "" if self.show_pin else "•"
        self.pin_entry.config(show=show_char)
        self.toggle_pin_btn.config(text="Hide" if self.show_pin else "Show")

    def toggle_confirm_pin(self):
        self.show_confirm_pin = not self.show_confirm_pin
        show_char = "" if self.show_confirm_pin else "•"
        self.confirm_pin_entry.config(show=show_char)
        self.toggle_confirm_pin_btn.config(text="Hide" if self.show_confirm_pin else "Show")

    def check_password_strength(self, event=None):
        password = self.password_entry.get()
        strength = check_password_strength(password)
        if "Weak" in strength:
            self.password_strength.config(text=strength, fg='red')
        else:
            self.password_strength.config(text=strength, fg='green')

    def generate_captcha(self):
        if self.captcha_locked:
            remaining_time = max(0, 30 - (time.time() - self.captcha_lock_time))
            if remaining_time > 0:
                self.captcha_label.config(text=f"CAPTCHA locked for {int(remaining_time)} seconds")
                self.after(1000, self.generate_captcha)
                return
            else:
                self.captcha_locked = False
                self.captcha_attempts = 0

        self.current_captcha = random.choice(CAPTCHA_QUESTIONS)
        self.captcha_label.config(text=self.current_captcha["question"])
        self.captcha_entry.delete(0, tk.END)

    def validate_captcha(self):
        if self.captcha_locked:
            return False

        user_answer = self.captcha_entry.get().strip().lower()
        correct_answer = self.current_captcha["answer"].lower()

        if user_answer != correct_answer:
            self.captcha_attempts += 1
            if self.captcha_attempts >= 3:
                self.captcha_locked = True
                self.captcha_lock_time = time.time()
                self.status_label.config(text="Too many wrong CAPTCHA attempts. Please wait 30 seconds.", fg='red')
                self.generate_captcha()
                return False
            else:
                self.status_label.config(text="Wrong CAPTCHA answer. Try again.", fg='red')
                self.generate_captcha()
                return False
        return True

    def signup(self):
        # Check if CAPTCHA is locked
        if self.captcha_locked:
            self.status_label.config(text="CAPTCHA is still locked. Please wait.", fg='red')
            return

        # Validate CAPTCHA first
        if not self.validate_captcha():
            return

        # Get all form values
        username = self.username_entry.get().strip()
        email = self.email_entry.get().strip()
        password = self.password_entry.get()
        confirm_password = self.confirm_password.get()
        pin = self.pin_entry.get()
        confirm_pin = self.confirm_pin_entry.get()
        security_question = self.security_question.get()
        security_answer = self.security_answer.get().strip()

        # Validate all fields
        if not all([username, email, password, confirm_password, pin, confirm_pin, security_question, security_answer]):
            self.status_label.config(text="All fields are required", fg='red')
            return

        # Validate username
        if len(username) < 7:
            self.status_label.config(text="Username must be at least 7 characters", fg='red')
            return

        if username in self.controller.users_db:
            self.status_label.config(text="Username already exists", fg='red')
            return

        # Validate email
        if not validate_email(email):
            self.status_label.config(text="Invalid email address", fg='red')
            return

        # Check if email is already registered
        for user in self.controller.users_db.values():
            if user['email'].lower() == email.lower():
                self.status_label.config(text="Email already registered", fg='red')
                return

        # Validate password
        if len(password) < 15:
            self.status_label.config(text="Password must be at least 15 characters", fg='red')
            return

        if password != confirm_password:
            self.status_label.config(text="Passwords don't match", fg='red')
            return

        # Check password strength
        strength = check_password_strength(password)
        if "Weak" in strength:
            self.status_label.config(text=f"Password too weak: {strength}", fg='red')
            return

        # Validate PIN
        if not validate_pin(pin):
            self.status_label.config(text="PIN must be at least 4 digits", fg='red')
            return

        if pin != confirm_pin:
            self.status_label.config(text="PINs don't match", fg='red')
            return

        # Validate security answer
        if not security_answer:
            self.status_label.config(text="Security answer is required", fg='red')
            return

        # Create new user
        hashed_password = hash_password(password)
        hashed_pin = hash_password(pin)

        self.controller.users_db[username] = {
            'username': username,
            'email': email,
            'password': hashed_password,
            'pin': hashed_pin,
            'security_question': security_question,
            'security_answer': hash_password(security_answer.lower()),
            'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'last_login': None,
            'password_history': [hashed_password],
            'failed_attempts': 0,
            'locked': False
        }

        # Save user data
        save_users(self.controller.users_db)

        # Create empty password storage for this user
        if username not in self.controller.password_db:
            self.controller.password_db[username] = {}
            save_db(self.controller.password_db)

        self.status_label.config(text="Account created successfully! Redirecting to login...", fg='green')

        # Clear form
        self.username_entry.delete(0, tk.END)
        self.email_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.confirm_password.delete(0, tk.END)
        self.pin_entry.delete(0, tk.END)
        self.confirm_pin_entry.delete(0, tk.END)
        self.security_question.set('')
        self.security_answer.delete(0, tk.END)
        self.password_strength.config(text="")

        # Redirect to login after 2 seconds
        self.after(2000, lambda: self.controller.show_frame(SignInPage))

class ForgotPasswordPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(bg='#e0f0ff')
        self.font_conf = ('Arial', 14)
        self.step = 1  # 1: identifier, 2: security question, 3: reset password
        self.current_user = None

        # Center container
        center_frame = tk.Frame(self, bg='#e0f0ff')
        center_frame.place(relx=0.5, rely=0.5, anchor='center')

        # Logo
        try:
            self.logo_img = Image.open("images/logo.png")
            self.logo_img = self.logo_img.resize((150, 150), Image.LANCZOS)
            self.logo_photo = ImageTk.PhotoImage(self.logo_img)
            logo_label = tk.Label(center_frame, image=self.logo_photo, bg='#e0f0ff')
            logo_label.pack(pady=10)
        except:
            tk.Label(center_frame, text="PassShield", font=('Arial', 24, 'bold'), 
                    bg='#e0f0ff', fg='black').pack(pady=10)

        self.title_label = tk.Label(center_frame, text="Password Recovery", 
                                  font=('Arial', 20, 'bold'), 
                                  bg='#e0f0ff', fg='black')
        self.title_label.pack(pady=5)

        # Main content frame
        self.content_frame = tk.Frame(center_frame, bg='#f0f0f0', padx=20, pady=20, bd=1, relief='solid')
        self.content_frame.pack(pady=10, padx=20, fill='x')

        # Step 1: Enter username/email
        self.step1_frame = tk.Frame(self.content_frame, bg='#f0f0f0')
        self.step1_frame.pack(fill='x')

        tk.Label(self.step1_frame, text="Enter your username or email:", 
                font=self.font_conf, bg='#f0f0f0', fg='black').pack(anchor='w', pady=(0, 5))
        
        self.identifier_entry = tk.Entry(self.step1_frame, font=self.font_conf, 
                                       relief='solid', highlightthickness=0,
                                       bd=1, bg='white', fg='black', 
                                       insertbackground='black', insertwidth=2)
        self.identifier_entry.pack(fill='x', pady=5, ipady=5)

        self.next_btn = tk.Button(self.step1_frame, text="Next", command=self.verify_identifier,
                                font=self.font_conf, bg='#4CAF50', fg='white',
                                relief='solid', bd=1, padx=20, pady=5,
                                cursor='hand2')
        self.next_btn.pack(pady=10, fill='x')

        # Step 2: Security question
        self.step2_frame = tk.Frame(self.content_frame, bg='#f0f0f0')
        
        self.security_question_label = tk.Label(self.step2_frame, text="", 
                                             font=self.font_conf, bg='#f0f0f0', fg='black')
        self.security_question_label.pack(anchor='w', pady=(0, 5))
        
        self.security_answer_entry = tk.Entry(self.step2_frame, font=self.font_conf, 
                                           relief='solid', highlightthickness=0,
                                           bd=1, bg='white', fg='black', 
                                           insertbackground='black', insertwidth=2)
        self.security_answer_entry.pack(fill='x', pady=5, ipady=5)

        self.verify_btn = tk.Button(self.step2_frame, text="Verify", command=self.verify_security_answer,
                                  font=self.font_conf, bg='#4CAF50', fg='white',
                                  relief='solid', bd=1, padx=20, pady=5,
                                  cursor='hand2')
        self.verify_btn.pack(pady=10, fill='x')

        # Step 3: Reset password
        self.step3_frame = tk.Frame(self.content_frame, bg='#f0f0f0')
        
        tk.Label(self.step3_frame, text="New Password:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w', pady=(0, 5))
        
        self.new_password_entry = tk.Entry(self.step3_frame, font=self.font_conf, show="•", 
                                        relief='solid', highlightthickness=0, bd=1, 
                                        bg='white', fg='black', insertbackground='black', 
                                        insertwidth=2)
        self.new_password_entry.pack(fill='x', pady=5, ipady=5)

        # Password strength
        self.password_strength = tk.Label(self.step3_frame, text="", font=('Arial', 12), 
                                        bg='#f0f0f0', fg='red')
        self.password_strength.pack(anchor='w', pady=(5, 0))
        self.new_password_entry.bind('<KeyRelease>', self.check_password_strength)

        tk.Label(self.step3_frame, text="Confirm New Password:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w', pady=(10, 5))
        
        self.confirm_password_entry = tk.Entry(self.step3_frame, font=self.font_conf, show="•", 
                                            relief='solid', highlightthickness=0, bd=1, 
                                            bg='white', fg='black', insertbackground='black', 
                                            insertwidth=2)
        self.confirm_password_entry.pack(fill='x', pady=5, ipady=5)

        self.reset_btn = tk.Button(self.step3_frame, text="Reset Password", command=self.reset_password,
                                 font=self.font_conf, bg='#4CAF50', fg='white',
                                 relief='solid', bd=1, padx=20, pady=5,
                                 cursor='hand2')
        self.reset_btn.pack(pady=10, fill='x')

        # Status label
        self.status_label = tk.Label(center_frame, text="", font=self.font_conf, 
                                   bg='#e0f0ff', fg='red')
        self.status_label.pack(pady=5)

        # Back to login button
        tk.Button(center_frame, text="Back to Sign In", 
                 command=lambda: controller.show_frame(SignInPage), 
                 font=self.font_conf, fg="blue", bg='#e0f0ff', relief='flat',
                 cursor='hand2').pack(pady=5)

    def verify_identifier(self):
        identifier = self.identifier_entry.get().strip()
        if not identifier:
            self.status_label.config(text="Please enter your username or email", fg='red')
            return

        user = get_user_by_email_or_username(identifier, self.controller.users_db)
        if not user:
            self.status_label.config(text="User not found", fg='red')
            return

        self.current_user = user
        self.security_question_label.config(text=f"Security Question: {user['security_question']}")
        
        # Hide step 1, show step 2
        self.step1_frame.pack_forget()
        self.step2_frame.pack(fill='x')
        self.step = 2
        self.status_label.config(text="")

    def verify_security_answer(self):
        answer = self.security_answer_entry.get().strip().lower()
        if not answer:
            self.status_label.config(text="Please enter your security answer", fg='red')
            return

        hashed_answer = hash_password(answer)
        if hashed_answer != self.current_user['security_answer']:
            self.status_label.config(text="Incorrect security answer", fg='red')
            return

        # Hide step 2, show step 3
        self.step2_frame.pack_forget()
        self.step3_frame.pack(fill='x')
        self.step = 3
        self.status_label.config(text="")

    def check_password_strength(self, event=None):
        password = self.new_password_entry.get()
        strength = check_password_strength(password)
        if "Weak" in strength:
            self.password_strength.config(text=strength, fg='red')
        else:
            self.password_strength.config(text=strength, fg='green')

    def reset_password(self):
        new_password = self.new_password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        if not new_password or not confirm_password:
            self.status_label.config(text="Both password fields are required", fg='red')
            return

        if len(new_password) < 15:
            self.status_label.config(text="Password must be at least 15 characters", fg='red')
            return

        if new_password != confirm_password:
            self.status_label.config(text="Passwords don't match", fg='red')
            return

        # Check password strength
        strength = check_password_strength(new_password)
        if "Weak" in strength:
            self.status_label.config(text=f"Password too weak: {strength}", fg='red')
            return

        # Update password
        hashed_password = hash_password(new_password)
        username = self.current_user['username']
        self.controller.users_db[username]['password'] = hashed_password
        self.controller.users_db[username]['password_history'].append(hashed_password)
        
        # Save changes
        save_users(self.controller.users_db)

        self.status_label.config(text="Password reset successfully! Redirecting to login...", fg='green')

        # Clear all fields
        self.identifier_entry.delete(0, tk.END)
        self.security_answer_entry.delete(0, tk.END)
        self.new_password_entry.delete(0, tk.END)
        self.confirm_password_entry.delete(0, tk.END)
        self.password_strength.config(text="")

        # Reset steps
        self.step3_frame.pack_forget()
        self.step1_frame.pack(fill='x')
        self.step = 1

        # Redirect to login after 2 seconds
        self.after(2000, lambda: self.controller.show_frame(SignInPage))

class StoragePage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(bg='#e0f0ff')
        self.font_conf = ('Arial', 12)
        self.selected_item = None
        self.search_var = tk.StringVar()
        self.search_var.trace("w", self.filter_passwords)

        # Header Frame
        header_frame = tk.Frame(self, bg='#4CAF50', height=60)
        header_frame.pack(fill='x', side='top')

        # Welcome label
        self.welcome_label = tk.Label(header_frame, text="", font=('Arial', 16, 'bold'), 
                                     bg='#4CAF50', fg='white')
        self.welcome_label.pack(side='left', padx=20)

        # Search Frame
        search_frame = tk.Frame(header_frame, bg='#4CAF50')
        search_frame.pack(side='right', padx=20)

        tk.Label(search_frame, text="Search:", font=self.font_conf, 
                bg='#4CAF50', fg='white').pack(side='left', padx=5)

        self.search_entry = tk.Entry(search_frame, textvariable=self.search_var, 
                                    font=self.font_conf, relief='solid', 
                                    highlightthickness=0, bd=1, width=30)
        self.search_entry.pack(side='left', padx=5, ipady=3)

        # Main Content Frame
        main_frame = tk.Frame(self, bg='#e0f0ff')
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)

        # Left Frame - Password List
        left_frame = tk.Frame(main_frame, bg='#e0f0ff', width=300)
        left_frame.pack(side='left', fill='y')
        left_frame.pack_propagate(False)

        # Password List Header
        list_header = tk.Frame(left_frame, bg='#4CAF50', height=40)
        list_header.pack(fill='x')

        tk.Label(list_header, text="Saved Passwords", font=('Arial', 14, 'bold'), 
                bg='#4CAF50', fg='white').pack(side='left', padx=10)

        # Add New Button
        self.add_btn = tk.Button(list_header, text="+", command=self.show_add_dialog,
                                font=('Arial', 14, 'bold'), bg='#4CAF50', fg='white',
                                relief='flat', bd=0, cursor='hand2')
        self.add_btn.pack(side='right', padx=10)

        # Password List
        self.password_list = ttk.Treeview(left_frame, columns=('name'), show='tree', 
                                        selectmode='browse')
        self.password_list.heading('#0', text='', anchor='w')
        self.password_list.column('#0', width=0, stretch=tk.NO)
        self.password_list.heading('name', text='Name')
        self.password_list.column('name', width=280, anchor='w')

        self.password_list.pack(fill='both', expand=True, pady=(0, 10))

        # Bind selection event
        self.password_list.bind('<<TreeviewSelect>>', self.on_password_select)

        # Right Frame - Password Details
        right_frame = tk.Frame(main_frame, bg='#f0f0f0', bd=1, relief='solid')
        right_frame.pack(side='right', fill='both', expand=True)

        # Password Details Header
        detail_header = tk.Frame(right_frame, bg='#4CAF50', height=40)
        detail_header.pack(fill='x')

        tk.Label(detail_header, text="Password Details", font=('Arial', 14, 'bold'), 
                bg='#4CAF50', fg='white').pack(side='left', padx=10)

        # Details Content
        detail_content = tk.Frame(right_frame, bg='#f0f0f0', padx=20, pady=20)
        detail_content.pack(fill='both', expand=True)

        # Name
        tk.Label(detail_content, text="Name:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').grid(row=0, column=0, sticky='w', pady=5)
        self.name_var = tk.StringVar()
        self.name_entry = tk.Entry(detail_content, textvariable=self.name_var, 
                                 font=self.font_conf, relief='solid', 
                                 highlightthickness=0, bd=1, bg='white', fg='black',
                                 insertbackground='black', insertwidth=2)
        self.name_entry.grid(row=0, column=1, sticky='ew', pady=5, padx=10, ipady=3)

        # Username/Email
        tk.Label(detail_content, text="Username/Email:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').grid(row=1, column=0, sticky='w', pady=5)
        self.username_var = tk.StringVar()
        self.username_entry = tk.Entry(detail_content, textvariable=self.username_var, 
                                      font=self.font_conf, relief='solid', 
                                      highlightthickness=0, bd=1, bg='white', fg='black',
                                      insertbackground='black', insertwidth=2)
        self.username_entry.grid(row=1, column=1, sticky='ew', pady=5, padx=10, ipady=3)

        # Password
        tk.Label(detail_content, text="Password:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').grid(row=2, column=0, sticky='w', pady=5)
        
        password_frame = tk.Frame(detail_content, bg='#f0f0f0')
        password_frame.grid(row=2, column=1, sticky='ew', pady=5, padx=10)
        
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(password_frame, textvariable=self.password_var, 
                                      font=self.font_conf, show="•", relief='solid', 
                                      highlightthickness=0, bd=1, bg='white', fg='black',
                                      insertbackground='black', insertwidth=2)
        self.password_entry.pack(side='left', fill='x', expand=True, ipady=3)
        
        self.show_pass_btn = tk.Button(password_frame, text="Show", command=self.toggle_password,
                                     font=self.font_conf, bg='#e0f0ff', fg='black',
                                     relief='solid', bd=1, padx=10, cursor='hand2')
        self.show_pass_btn.pack(side='left', padx=5)

        # URL
        tk.Label(detail_content, text="URL:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').grid(row=3, column=0, sticky='w', pady=5)
        self.url_var = tk.StringVar()
        self.url_entry = tk.Entry(detail_content, textvariable=self.url_var, 
                                font=self.font_conf, relief='solid', 
                                highlightthickness=0, bd=1, bg='white', fg='black',
                                insertbackground='black', insertwidth=2)
        self.url_entry.grid(row=3, column=1, sticky='ew', pady=5, padx=10, ipady=3)

        # Notes
        tk.Label(detail_content, text="Notes:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').grid(row=4, column=0, sticky='nw', pady=5)
        self.notes_text = tk.Text(detail_content, font=self.font_conf, wrap='word', 
                                relief='solid', highlightthickness=0, bd=1, 
                                height=5, bg='white', fg='black',
                                insertbackground='black', insertwidth=2)
        self.notes_text.grid(row=4, column=1, sticky='nsew', pady=5, padx=10)

        # Button Frame
        button_frame = tk.Frame(detail_content, bg='#f0f0f0')
        button_frame.grid(row=5, column=0, columnspan=2, pady=10, sticky='ew')

        # Configure grid weights
        detail_content.grid_columnconfigure(1, weight=1)
        detail_content.grid_rowconfigure(4, weight=1)

        # Buttons
        self.save_btn = tk.Button(button_frame, text="Save", command=self.save_password,
                                font=self.font_conf, bg='#4CAF50', fg='white',
                                relief='solid', bd=1, padx=20, pady=5,
                                cursor='hand2')
        self.save_btn.pack(side='left', padx=5)

        self.copy_btn = tk.Button(button_frame, text="Copy Password", command=self.copy_password,
                                font=self.font_conf, bg='#2196F3', fg='white',
                                relief='solid', bd=1, padx=20, pady=5,
                                cursor='hand2')
        self.copy_btn.pack(side='left', padx=5)

        self.generate_btn = tk.Button(button_frame, text="Generate", command=self.generate_password,
                                   font=self.font_conf, bg='#FF9800', fg='white',
                                   relief='solid', bd=1, padx=20, pady=5,
                                   cursor='hand2')
        self.generate_btn.pack(side='left', padx=5)

        self.delete_btn = tk.Button(button_frame, text="Delete", command=self.delete_password,
                                  font=self.font_conf, bg='#F44336', fg='white',
                                  relief='solid', bd=1, padx=20, pady=5,
                                  cursor='hand2')
        self.delete_btn.pack(side='right', padx=5)

        # Bottom Frame - Navigation
        bottom_frame = tk.Frame(self, bg='#e0f0ff', height=50)
        bottom_frame.pack(fill='x', side='bottom')

        tk.Button(bottom_frame, text="Settings", command=lambda: controller.show_frame(SettingsPage),
                 font=self.font_conf, bg='#607D8B', fg='white',
                 relief='solid', bd=1, padx=20, pady=5,
                 cursor='hand2').pack(side='right', padx=10)

        tk.Button(bottom_frame, text="Sign Out", command=self.sign_out,
                 font=self.font_conf, bg='#F44336', fg='white',
                 relief='solid', bd=1, padx=20, pady=5,
                 cursor='hand2').pack(side='right', padx=10)

        # Initialize password list
        self.load_passwords()

    def on_show(self):
        self.welcome_label.config(text=f"Welcome, {self.controller.current_username}!")
        self.load_passwords()

    def load_passwords(self):
        # Clear current list
        for item in self.password_list.get_children():
            self.password_list.delete(item)

        # Load passwords for current user
        username = self.controller.current_username
        if username in self.controller.password_db:
            passwords = self.controller.password_db[username]
            for name in sorted(passwords.keys()):
                self.password_list.insert('', 'end', values=(name,))

    def filter_passwords(self, *args):
        search_term = self.search_var.get().lower()
        for item in self.password_list.get_children():
            name = self.password_list.item(item, 'values')[0].lower()
            if search_term in name:
                self.password_list.item(item, open=True)
                self.password_list.selection_set(item)
            else:
                self.password_list.item(item, open=False)

    def on_password_select(self, event):
        selected = self.password_list.selection()
        if not selected:
            return

        self.selected_item = selected[0]
        name = self.password_list.item(self.selected_item, 'values')[0]
        
        # Load password details
        username = self.controller.current_username
        password_data = self.controller.password_db[username][name]

        self.name_var.set(name)
        self.username_var.set(password_data.get('username', ''))
        self.password_var.set(password_data.get('password', ''))
        self.url_var.set(password_data.get('url', ''))
        
        # Clear notes and insert new content
        self.notes_text.delete('1.0', tk.END)
        self.notes_text.insert('1.0', password_data.get('notes', ''))

    def toggle_password(self):
        current_show = self.password_entry.cget('show')
        if current_show == '':
            self.password_entry.config(show='•')
            self.show_pass_btn.config(text='Show')
        else:
            self.password_entry.config(show='')
            self.show_pass_btn.config(text='Hide')

    def clear_fields(self):
        self.name_var.set('')
        self.username_var.set('')
        self.password_var.set('')
        self.url_var.set('')
        self.notes_text.delete('1.0', tk.END)
        self.password_list.selection_remove(self.password_list.selection())

    def show_add_dialog(self):
        self.clear_fields()
        self.name_entry.focus_set()

    def save_password(self):
        name = self.name_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get()
        url = self.url_var.get().strip()
        notes = self.notes_text.get('1.0', tk.END).strip()

        if not name:
            messagebox.showerror("Error", "Name is required", parent=self)
            return

        # Get current user's password storage
        current_user = self.controller.current_username
        if current_user not in self.controller.password_db:
            self.controller.password_db[current_user] = {}

        # Save password data
        self.controller.password_db[current_user][name] = {
            'username': username,
            'password': password,
            'url': url,
            'notes': notes,
            'updated_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        # Save to file
        save_db(self.controller.password_db)

        # Reload password list
        self.load_passwords()

        # Select the newly added/updated item
        for item in self.password_list.get_children():
            if self.password_list.item(item, 'values')[0] == name:
                self.password_list.selection_set(item)
                self.password_list.focus(item)
                break

        messagebox.showinfo("Success", "Password saved successfully", parent=self)

    def copy_password(self):
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("Warning", "No password to copy", parent=self)
            return

        pyperclip.copy(password)
        messagebox.showinfo("Copied", "Password copied to clipboard", parent=self)

    def generate_password(self):
        password = generate_strong_password()
        self.password_var.set(password)
        messagebox.showinfo("Generated", "A strong password has been generated", parent=self)

    def delete_password(self):
        if not self.selected_item:
            messagebox.showwarning("Warning", "No password selected", parent=self)
            return

        name = self.password_list.item(self.selected_item, 'values')[0]
        if not messagebox.askyesno("Confirm", f"Delete password for '{name}'?", parent=self):
            return

        # Delete from database
        current_user = self.controller.current_username
        if current_user in self.controller.password_db and name in self.controller.password_db[current_user]:
            del self.controller.password_db[current_user][name]
            save_db(self.controller.password_db)

        # Reload password list
        self.load_passwords()
        self.clear_fields()

    def sign_out(self):
        self.controller.current_user = None
        self.controller.current_username = None
        self.clear_fields()
        self.controller.show_frame(SignInPage)

class SettingsPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(bg='#e0f0ff')
        self.font_conf = ('Arial', 14)
        self.show_current_password = False
        self.show_new_password = False
        self.show_confirm_password = False

        # Header Frame
        header_frame = tk.Frame(self, bg='#4CAF50', height=60)
        header_frame.pack(fill='x', side='top')

        # Back button
        back_btn = tk.Button(header_frame, text="← Back", command=lambda: controller.show_frame(StoragePage),
                            font=self.font_conf, bg='#4CAF50', fg='white',
                            relief='flat', bd=0, cursor='hand2')
        back_btn.pack(side='left', padx=20)

        # Title
        tk.Label(header_frame, text="Settings", font=('Arial', 18, 'bold'),
                bg='#4CAF50', fg='white').pack(side='left', padx=20)

        # Main Content Frame
        content_frame = tk.Frame(self, bg='#e0f0ff')
        content_frame.pack(fill='both', expand=True, padx=20, pady=20)

        # Notebook for different settings sections
        notebook = ttk.Notebook(content_frame)
        notebook.pack(fill='both', expand=True)

        # Account Tab
        account_tab = tk.Frame(notebook, bg='#e0f0ff')
        notebook.add(account_tab, text='Account')

        # Password Change Frame
        pass_frame = tk.Frame(account_tab, bg='#f0f0f0', bd=1, relief='solid', padx=20, pady=20)
        pass_frame.pack(fill='x', pady=10)

        tk.Label(pass_frame, text="Change Password", font=('Arial', 16, 'bold'),
                bg='#f0f0f0', fg='black').grid(row=0, column=0, columnspan=3, pady=10, sticky='w')

        # Current Password
        tk.Label(pass_frame, text="Current Password:", font=self.font_conf,
                bg='#f0f0f0', fg='black').grid(row=1, column=0, sticky='e', pady=5, padx=5)
        
        self.current_pass_entry = tk.Entry(pass_frame, font=self.font_conf, show="•",
                                        relief='solid', highlightthickness=0, bd=1,
                                        bg='white', fg='black', insertbackground='black',
                                        insertwidth=2)
        self.current_pass_entry.grid(row=1, column=1, sticky='ew', pady=5, padx=5, ipady=3)
        
        self.toggle_current_pass = tk.Button(pass_frame, text="Show", command=self.toggle_current_password,
                                           font=self.font_conf, bg='#e0f0ff', fg='black',
                                           relief='solid', bd=1, padx=10, cursor='hand2')
        self.toggle_current_pass.grid(row=1, column=2, sticky='w', pady=5, padx=5)

        # New Password
        tk.Label(pass_frame, text="New Password:", font=self.font_conf,
                bg='#f0f0f0', fg='black').grid(row=2, column=0, sticky='e', pady=5, padx=5)
        
        self.new_pass_entry = tk.Entry(pass_frame, font=self.font_conf, show="•",
                                     relief='solid', highlightthickness=0, bd=1,
                                     bg='white', fg='black', insertbackground='black',
                                     insertwidth=2)
        self.new_pass_entry.grid(row=2, column=1, sticky='ew', pady=5, padx=5, ipady=3)
        
        self.toggle_new_pass = tk.Button(pass_frame, text="Show", command=self.toggle_new_password,
                                       font=self.font_conf, bg='#e0f0ff', fg='black',
                                       relief='solid', bd=1, padx=10, cursor='hand2')
        self.toggle_new_pass.grid(row=2, column=2, sticky='w', pady=5, padx=5)

        # Password strength
        self.pass_strength_label = tk.Label(pass_frame, text="", font=('Arial', 12),
                                          bg='#f0f0f0', fg='red')
        self.pass_strength_label.grid(row=3, column=1, sticky='w', pady=(0, 10))
        self.new_pass_entry.bind('<KeyRelease>', self.check_password_strength)

        # Confirm New Password
        tk.Label(pass_frame, text="Confirm Password:", font=self.font_conf,
                bg='#f0f0f0', fg='black').grid(row=4, column=0, sticky='e', pady=5, padx=5)
        
        self.confirm_pass_entry = tk.Entry(pass_frame, font=self.font_conf, show="•",
                                         relief='solid', highlightthickness=0, bd=1,
                                         bg='white', fg='black', insertbackground='black',
                                         insertwidth=2)
        self.confirm_pass_entry.grid(row=4, column=1, sticky='ew', pady=5, padx=5, ipady=3)
        
        self.toggle_confirm_pass = tk.Button(pass_frame, text="Show", command=self.toggle_confirm_password,
                                           font=self.font_conf, bg='#e0f0ff', fg='black',
                                           relief='solid', bd=1, padx=10, cursor='hand2')
        self.toggle_confirm_pass.grid(row=4, column=2, sticky='w', pady=5, padx=5)

        # Change Password Button
        tk.Button(pass_frame, text="Change Password", command=self.change_password,
                 font=self.font_conf, bg='#4CAF50', fg='white',
                 relief='solid', bd=1, padx=20, pady=5,
                 cursor='hand2').grid(row=5, column=1, pady=10)

        # PIN Change Frame
        pin_frame = tk.Frame(account_tab, bg='#f0f0f0', bd=1, relief='solid', padx=20, pady=20)
        pin_frame.pack(fill='x', pady=10)

        tk.Label(pin_frame, text="Change PIN", font=('Arial', 16, 'bold'),
                bg='#f0f0f0', fg='black').grid(row=0, column=0, columnspan=3, pady=10, sticky='w')

        # Current PIN
        tk.Label(pin_frame, text="Current PIN:", font=self.font_conf,
                bg='#f0f0f0', fg='black').grid(row=1, column=0, sticky='e', pady=5, padx=5)
        
        self.current_pin_entry = tk.Entry(pin_frame, font=self.font_conf, show="•",
                                        relief='solid', highlightthickness=0, bd=1,
                                        bg='white', fg='black', insertbackground='black',
                                        insertwidth=2)
        self.current_pin_entry.grid(row=1, column=1, sticky='ew', pady=5, padx=5, ipady=3)

        # New PIN
        tk.Label(pin_frame, text="New PIN:", font=self.font_conf,
                bg='#f0f0f0', fg='black').grid(row=2, column=0, sticky='e', pady=5, padx=5)
        
        self.new_pin_entry = tk.Entry(pin_frame, font=self.font_conf, show="•",
                                    relief='solid', highlightthickness=0, bd=1,
                                    bg='white', fg='black', insertbackground='black',
                                    insertwidth=2)
        self.new_pin_entry.grid(row=2, column=1, sticky='ew', pady=5, padx=5, ipady=3)

        # Confirm New PIN
        tk.Label(pin_frame, text="Confirm PIN:", font=self.font_conf,
                bg='#f0f0f0', fg='black').grid(row=3, column=0, sticky='e', pady=5, padx=5)
        
        self.confirm_pin_entry = tk.Entry(pin_frame, font=self.font_conf, show="•",
                                        relief='solid', highlightthickness=0, bd=1,
                                        bg='white', fg='black', insertbackground='black',
                                        insertwidth=2)
        self.confirm_pin_entry.grid(row=3, column=1, sticky='ew', pady=5, padx=5, ipady=3)

        # Change PIN Button
        tk.Button(pin_frame, text="Change PIN", command=self.change_pin,
                 font=self.font_conf, bg='#4CAF50', fg='white',
                 relief='solid', bd=1, padx=20, pady=5,
                 cursor='hand2').grid(row=4, column=1, pady=10)

        # Security Questions Frame
        security_frame = tk.Frame(account_tab, bg='#f0f0f0', bd=1, relief='solid', padx=20, pady=20)
        security_frame.pack(fill='x', pady=10)

        tk.Label(security_frame, text="Security Question", font=('Arial', 16, 'bold'),
                bg='#f0f0f0', fg='black').grid(row=0, column=0, columnspan=2, pady=10, sticky='w')

        # Current Security Question
        tk.Label(security_frame, text="Current Question:", font=self.font_conf,
                bg='#f0f0f0', fg='black').grid(row=1, column=0, sticky='e', pady=5, padx=5)
        
        self.current_question_label = tk.Label(security_frame, text="", font=self.font_conf,
                                             bg='#f0f0f0', fg='black', anchor='w')
        self.current_question_label.grid(row=1, column=1, sticky='ew', pady=5, padx=5)

        # New Security Question
        tk.Label(security_frame, text="New Question:", font=self.font_conf,
                bg='#f0f0f0', fg='black').grid(row=2, column=0, sticky='e', pady=5, padx=5)
        
        self.new_question_var = tk.StringVar()
        self.new_question_menu = ttk.Combobox(security_frame, textvariable=self.new_question_var,
                                            values=SECURITY_QUESTIONS, font=self.font_conf,
                                            state='readonly')
        self.new_question_menu.grid(row=2, column=1, sticky='ew', pady=5, padx=5, ipady=3)

        # Security Answer
        tk.Label(security_frame, text="Answer:", font=self.font_conf,
                bg='#f0f0f0', fg='black').grid(row=3, column=0, sticky='e', pady=5, padx=5)
        
        self.security_answer_entry = tk.Entry(security_frame, font=self.font_conf,
                                           relief='solid', highlightthickness=0, bd=1,
                                           bg='white', fg='black', insertbackground='black',
                                           insertwidth=2)
        self.security_answer_entry.grid(row=3, column=1, sticky='ew', pady=5, padx=5, ipady=3)

        # Change Security Question Button
        tk.Button(security_frame, text="Update Security", command=self.change_security_question,
                 font=self.font_conf, bg='#4CAF50', fg='white',
                 relief='solid', bd=1, padx=20, pady=5,
                 cursor='hand2').grid(row=4, column=1, pady=10)

        # Status Label
        self.status_label = tk.Label(account_tab, text="", font=self.font_conf,
                                   bg='#e0f0ff', fg='red')
        self.status_label.pack(pady=10)

        # Application Tab
        app_tab = tk.Frame(notebook, bg='#e0f0ff')
        notebook.add(app_tab, text='Application')

        # Theme Settings
        theme_frame = tk.Frame(app_tab, bg='#f0f0f0', bd=1, relief='solid', padx=20, pady=20)
        theme_frame.pack(fill='x', pady=10)

        tk.Label(theme_frame, text="Theme Settings", font=('Arial', 16, 'bold'),
                bg='#f0f0f0', fg='black').grid(row=0, column=0, columnspan=2, pady=10, sticky='w')

        # Theme Selection
        tk.Label(theme_frame, text="Select Theme:", font=self.font_conf,
                bg='#f0f0f0', fg='black').grid(row=1, column=0, sticky='e', pady=5, padx=5)
        
        self.theme_var = tk.StringVar()
        theme_menu = ttk.Combobox(theme_frame, textvariable=self.theme_var,
                                values=['Light', 'Dark', 'System'], font=self.font_conf,
                                state='readonly')
        theme_menu.grid(row=1, column=1, sticky='ew', pady=5, padx=5, ipady=3)

        # Save Theme Button
        tk.Button(theme_frame, text="Save Theme", command=self.save_theme,
                 font=self.font_conf, bg='#4CAF50', fg='white',
                 relief='solid', bd=1, padx=20, pady=5,
                 cursor='hand2').grid(row=2, column=1, pady=10)

        # Data Management
        data_frame = tk.Frame(app_tab, bg='#f0f0f0', bd=1, relief='solid', padx=20, pady=20)
        data_frame.pack(fill='x', pady=10)

        tk.Label(data_frame, text="Data Management", font=('Arial', 16, 'bold'),
                bg='#f0f0f0', fg='black').grid(row=0, column=0, columnspan=2, pady=10, sticky='w')

        # Export Button
        tk.Button(data_frame, text="Export Data", command=self.export_data,
                 font=self.font_conf, bg='#2196F3', fg='white',
                 relief='solid', bd=1, padx=20, pady=5,
                 cursor='hand2').grid(row=1, column=0, pady=10, padx=5)

        # Import Button
        tk.Button(data_frame, text="Import Data", command=self.import_data,
                 font=self.font_conf, bg='#2196F3', fg='white',
                 relief='solid', bd=1, padx=20, pady=5,
                 cursor='hand2').grid(row=1, column=1, pady=10, padx=5)

        # Account Deletion
        delete_frame = tk.Frame(app_tab, bg='#f0f0f0', bd=1, relief='solid', padx=20, pady=20)
        delete_frame.pack(fill='x', pady=10)

        tk.Label(delete_frame, text="Account Deletion", font=('Arial', 16, 'bold'),
                bg='#f0f0f0', fg='black').grid(row=0, column=0, columnspan=2, pady=10, sticky='w')

        # Warning label
        tk.Label(delete_frame, text="Warning: This action cannot be undone!", font=('Arial', 12),
                bg='#f0f0f0', fg='red').grid(row=1, column=0, columnspan=2, pady=5, sticky='w')

        # Delete Account Button
        tk.Button(delete_frame, text="Delete Account", command=self.delete_account,
                 font=self.font_conf, bg='#F44336', fg='white',
                 relief='solid', bd=1, padx=20, pady=5,
                 cursor='hand2').grid(row=2, column=0, columnspan=2, pady=10)

        # Load current settings
        self.load_current_settings()

    def load_current_settings(self):
        """Load current user settings into the form"""
        username = self.controller.current_username
        if username in self.controller.users_db:
            user_data = self.controller.users_db[username]
            
            # Set current security question
            self.current_question_label.config(text=user_data['security_question'])

    def toggle_current_password(self):
        self.show_current_password = not self.show_current_password
        show_char = "" if self.show_current_password else "•"
        self.current_pass_entry.config(show=show_char)
        self.toggle_current_pass.config(text="Hide" if self.show_current_password else "Show")

    def toggle_new_password(self):
        self.show_new_password = not self.show_new_password
        show_char = "" if self.show_new_password else "•"
        self.new_pass_entry.config(show=show_char)
        self.toggle_new_pass.config(text="Hide" if self.show_new_password else "Show")

    def toggle_confirm_password(self):
        self.show_confirm_password = not self.show_confirm_password
        show_char = "" if self.show_confirm_password else "•"
        self.confirm_pass_entry.config(show=show_char)
        self.toggle_confirm_pass.config(text="Hide" if self.show_confirm_password else "Show")

    def check_password_strength(self, event=None):
        password = self.new_pass_entry.get()
        strength = check_password_strength(password)
        if "Weak" in strength:
            self.pass_strength_label.config(text=strength, fg='red')
        else:
            self.pass_strength_label.config(text=strength, fg='green')

    def change_password(self):
        current_pass = self.current_pass_entry.get()
        new_pass = self.new_pass_entry.get()
        confirm_pass = self.confirm_pass_entry.get()

        if not all([current_pass, new_pass, confirm_pass]):
            self.status_label.config(text="All fields are required", fg='red')
            return

        if len(new_pass) < 15:
            self.status_label.config(text="Password must be at least 15 characters", fg='red')
            return

        if new_pass != confirm_pass:
            self.status_label.config(text="New passwords don't match", fg='red')
            return

        # Check password strength
        strength = check_password_strength(new_pass)
        if "Weak" in strength:
            self.status_label.config(text=f"Password too weak: {strength}", fg='red')
            return

        username = self.controller.current_username
        user_data = self.controller.users_db.get(username, {})
        
        # Verify current password
        if not verify_password(current_pass, user_data.get('password', '')):
            self.status_label.config(text="Current password is incorrect", fg='red')
            return

        # Check if new password is same as any in history
        hashed_new_pass = hash_password(new_pass)
        if hashed_new_pass in user_data.get('password_history', []):
            self.status_label.config(text="Cannot use a previously used password", fg='red')
            return

        # Update password
        self.controller.users_db[username]['password'] = hashed_new_pass
        self.controller.users_db[username]['password_history'].append(hashed_new_pass)
        
        # Save changes
        save_users(self.controller.users_db)

        self.status_label.config(text="Password changed successfully!", fg='green')
        
        # Clear fields
        self.current_pass_entry.delete(0, tk.END)
        self.new_pass_entry.delete(0, tk.END)
        self.confirm_pass_entry.delete(0, tk.END)
        self.pass_strength_label.config(text="")

    def change_pin(self):
        current_pin = self.current_pin_entry.get()
        new_pin = self.new_pin_entry.get()
        confirm_pin = self.confirm_pin_entry.get()

        if not all([current_pin, new_pin, confirm_pin]):
            self.status_label.config(text="All fields are required", fg='red')
            return

        if not validate_pin(new_pin):
            self.status_label.config(text="PIN must be at least 4 digits", fg='red')
            return

        if new_pin != confirm_pin:
            self.status_label.config(text="New PINs don't match", fg='red')
            return

        username = self.controller.current_username
        user_data = self.controller.users_db.get(username, {})
        
        # Verify current PIN
        if not verify_password(current_pin, user_data.get('pin', '')):
            self.status_label.config(text="Current PIN is incorrect", fg='red')
            return

        # Update PIN
        self.controller.users_db[username]['pin'] = hash_password(new_pin)
        
        # Save changes
        save_users(self.controller.users_db)

        self.status_label.config(text="PIN changed successfully!", fg='green')
        
        # Clear fields
        self.current_pin_entry.delete(0, tk.END)
        self.new_pin_entry.delete(0, tk.END)
        self.confirm_pin_entry.delete(0, tk.END)

    def change_security_question(self):
        new_question = self.new_question_var.get()
        answer = self.security_answer_entry.get().strip()

        if not new_question or not answer:
            self.status_label.config(text="Both question and answer are required", fg='red')
            return

        username = self.controller.current_username
        self.controller.users_db[username]['security_question'] = new_question
        self.controller.users_db[username]['security_answer'] = hash_password(answer.lower())
        
        # Save changes
        save_users(self.controller.users_db)

        self.status_label.config(text="Security question updated successfully!", fg='green')
        
        # Update current question display
        self.current_question_label.config(text=new_question)
        
        # Clear fields
        self.new_question_var.set('')
        self.security_answer_entry.delete(0, tk.END)

    def save_theme(self):
        theme = self.theme_var.get()
        if not theme:
            return

        # TODO: Implement theme change logic
        messagebox.showinfo("Theme Changed", f"Theme will be set to {theme} on next launch", parent=self)

    def export_data(self):
        username = self.controller.current_username
        if not username:
            return

        # Get user's password data
        password_data = self.controller.password_db.get(username, {})
        if not password_data:
            messagebox.showinfo("No Data", "No passwords to export", parent=self)
            return

        # Create export dictionary
        export_data = {
            'version': 1,
            'username': username,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'passwords': password_data
        }

        # Ask for file location
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Export Passwords"
        )

        if not file_path:
            return

        try:
            with open(file_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            messagebox.showinfo("Success", "Data exported successfully", parent=self)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export data: {str(e)}", parent=self)

    def import_data(self):
        username = self.controller.current_username
        if not username:
            return

        # Ask for file location
        file_path = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Import Passwords"
        )

        if not file_path:
            return

        try:
            with open(file_path, 'r') as f:
                import_data = json.load(f)

            # Verify import data
            if not isinstance(import_data, dict) or 'passwords' not in import_data:
                raise ValueError("Invalid data format")

            # Confirm import
            if not messagebox.askyesno(
                "Confirm Import",
                f"This will import {len(import_data['passwords'])} password entries. Continue?",
                parent=self
            ):
                return

            # Merge passwords (existing ones will be overwritten)
            if username not in self.controller.password_db:
                self.controller.password_db[username] = {}

            self.controller.password_db[username].update(import_data['passwords'])
            save_db(self.controller.password_db)

            messagebox.showinfo("Success", "Data imported successfully", parent=self)
            self.controller.frames[StoragePage].load_passwords()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import data: {str(e)}", parent=self)

    def delete_account(self):
        username = self.controller.current_username
        if not username:
            return

        # Confirm deletion
        if not messagebox.askyesno(
            "Confirm Deletion",
            "This will permanently delete your account and all stored passwords. Continue?",
            parent=self
        ):
            return

        # Verify password
        password = simpledialog.askstring(
            "Confirm Password",
            "Enter your password to confirm account deletion:",
            parent=self,
            show='*'
        )

        if not password:
            return

        # Verify password
        user_data = self.controller.users_db.get(username, {})
        if not verify_password(password, user_data.get('password', '')):
            messagebox.showerror("Error", "Incorrect password", parent=self)
            return

        # Delete user account
        del self.controller.users_db[username]
        save_users(self.controller.users_db)

        # Delete user's password data
        if username in self.controller.password_db:
            del self.controller.password_db[username]
            save_db(self.controller.password_db)

        # Sign out
        self.controller.current_user = None
        self.controller.current_username = None
        self.controller.show_frame(SignInPage)

        messagebox.showinfo("Account Deleted", "Your account has been permanently deleted", parent=self)
