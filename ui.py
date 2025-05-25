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
    "What is your favorite sports team?",

    "What is the name of your favorite childhood toy?",
    "What was your dream job as a child?",
    "What is the name of the street you grew up on?",
    "What is your favorite holiday destination?",
    "What was the name of your first employer?",
    "What is the title of your favorite song?",
    "What was your favorite subject in school?",
    "What is your favorite color?",
    "What is the name of your favorite teacher?",
    "What is your favorite ice cream flavor?",
    "What is your oldest cousin’s name?",
    "What was the name of your elementary school principal?"
]


CAPTCHA_QUESTIONS = [
    {"question": "What is 3 + 5?", "answer": "8"},
    {"question": "What is the capital of France?", "answer": "paris"},
    {"question": "What color is the sky on a clear day?", "answer": "blue"},
    {"question": "How many sides does a triangle have?", "answer": "3"},
    {"question": "What is the opposite of 'day'?", "answer": "night"},
    {"question": "What is the last letter of the English alphabet?", "answer": "z"},
    {"question": "How many hours are in a day?", "answer": "24"},
    {"question": "What is 2 + 2?", "answer": "4"},
    {"question": "What planet do we live on?", "answer": "earth"},
    {"question": "How many months are in a year?", "answer": "12"},
    {"question": "What do bees make?", "answer": "honey"},
    {"question": "What color is grass?", "answer": "green"}
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
        
        # Create container frame
        self.container = tk.Frame(self, bg='#e0f0ff')
        self.container.pack(side="top", fill="both", expand=True)
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)
        
        # Initialize all frames
        self.frames = {}
        for F in (SignInPage, SignUpPage, ForgotPasswordPage, 
                  StoragePage, SettingsPage, GuidePage, ChangePasswordPage):
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
        self.controller.current_user = user['username']
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
        self.captcha_frame = tk.Frame(entry_frame, bg='#f0f0f0')
        self.captcha_frame.grid(row=row, column=0, columnspan=2, sticky='ew', pady=20)
        self.setup_captcha()
        
        # Status label
        self.status_label = tk.Label(content_frame, text="", font=self.font_conf, 
                                    bg='#e0f0ff', fg='red')
        self.status_label.pack(pady=10)

        # Button Frame
        button_frame = tk.Frame(content_frame, bg='#e0f0ff')
        button_frame.pack(fill='x', pady=20)

        btn_width = 20
        tk.Button(button_frame, text="Create Account", command=self.signup, font=self.font_conf,
                 bg='#4CAF50', fg='black', relief='solid', bd=1, padx=20, pady=10,
                 cursor='hand2', width=btn_width).pack(side='left', expand=True, padx=10)
        
        tk.Button(button_frame, text="Clear All Fields", command=self.clear_fields,
                 font=self.font_conf, bg='#e0f0ff', fg='black', relief='solid', 
                                  bd=1, padx=20, pady=10, cursor='hand2', width=btn_width).pack(side='left', expand=True, padx=10)
        
        tk.Button(button_frame, text="Back to Sign In", 
                 command=lambda: controller.show_frame(SignInPage), 
                 font=self.font_conf, bg='#e0f0ff', fg='black', relief='solid',
                 bd=1, padx=20, pady=10, cursor='hand2', width=btn_width).pack(side='left', expand=True, padx=10)
    
    def setup_captcha(self):
        for widget in self.captcha_frame.winfo_children():
            widget.destroy()
        
        if self.captcha_locked:
            remaining_time = max(0, 30 - (time.time() - self.captcha_lock_time))
            if remaining_time > 0:
                tk.Label(self.captcha_frame, text=f"Too many attempts! Please wait {int(remaining_time)} seconds", 
                        font=self.font_conf, bg='#f0f0f0', fg='red').pack()
                self.after(1000, self.setup_captcha)
                return
            else:
                self.captcha_locked = False
                self.captcha_attempts = 0
        
        self.current_captcha = random.choice(CAPTCHA_QUESTIONS)
        tk.Label(self.captcha_frame, text="Security Check:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w')
        tk.Label(self.captcha_frame, text=self.current_captcha["question"], 
                font=self.font_conf, bg='#f0f0f0', fg='black').pack(anchor='w', pady=(5, 0))
        
        self.captcha_entry = tk.Entry(self.captcha_frame, font=self.font_conf, 
                                    relief='solid', highlightthickness=0,
                                    bd=1, bg='white', fg='black', 
                                    insertbackground='black', insertwidth=2)
        self.captcha_entry.pack(fill='x', pady=5, ipady=5)
    
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
    
    def clear_fields(self):
        self.username_entry.delete(0, tk.END)
        self.email_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.confirm_password.delete(0, tk.END)
        self.pin_entry.delete(0, tk.END)
        self.confirm_pin_entry.delete(0, tk.END)
        self.security_question.set('')
        self.security_answer.delete(0, tk.END)
        self.captcha_entry.delete(0, tk.END)
        self.password_strength.config(text="")
        self.status_label.config(text="")
        self.setup_captcha()
    
    def signup(self):
        username = self.username_entry.get().strip()
        email = self.email_entry.get().strip()
        password = self.password_entry.get()
        confirm_password = self.confirm_password.get()
        pin = self.pin_entry.get()
        confirm_pin = self.confirm_pin_entry.get()
        security_question = self.security_question.get()
        security_answer = self.security_answer.get().strip()
        captcha_answer = self.captcha_entry.get().strip().lower()
        
        # Validate fields
        if not all([username, email, password, confirm_password, pin, confirm_pin, security_question, security_answer, captcha_answer]):
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
            self.status_label.config(text="Invalid email format", fg='red')
            return
        
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
        
        # Validate CAPTCHA
        if self.captcha_locked:
            self.status_label.config(text="Too many CAPTCHA attempts. Please wait.", fg='red')
            return
        
        if captcha_answer != self.current_captcha["answer"].lower():
            self.captcha_attempts += 1
            if self.captcha_attempts >= 3:
                self.captcha_locked = True
                self.captcha_lock_time = time.time()
                self.setup_captcha()
                self.status_label.config(text="Too many CAPTCHA attempts. Please wait 30 seconds.", fg='red')
            else:
                self.status_label.config(text="Incorrect CAPTCHA answer", fg='red')
                self.setup_captcha()
            return
        
        # Create user
        self.controller.users_db[username] = {
            'username': username,
            'email': email,
            'password': hash_password(password),
            'pin': pin,
            'security_question': security_question,
            'security_answer': security_answer,
            'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Initialize password storage for this user
        self.controller.password_db[username] = {}
        save_users(self.controller.users_db)
        save_db(self.controller.password_db)
        
        self.status_label.config(text="Account created successfully!", fg='green')
        self.after(2000, lambda: self.controller.show_frame(SignInPage))

class ForgotPasswordPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(bg='#e0f0ff')
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
        
        tk.Label(center_frame, text="Password Recovery", font=('Arial', 20, 'bold'), 
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
        
        # Button Frame
        button_frame = tk.Frame(center_frame, bg='#e0f0ff')
        button_frame.pack(pady=15, fill='x', padx=20)
        
        tk.Button(button_frame, text="Recover Password", command=self.recover_password, 
                font=self.font_conf, bg='#4CAF50', fg='black', relief='solid', 
                bd=1, padx=20, pady=5, cursor='hand2').pack(pady=5, fill='x')
        
        tk.Button(button_frame, text="Back to Sign In", 
                 command=lambda: controller.show_frame(SignInPage), 
                 font=self.font_conf, fg="blue", bg='#e0f0ff', relief='flat',
                 cursor='hand2').pack(pady=5)
        
        # Status label
        self.status_label = tk.Label(center_frame, text="", font=self.font_conf, 
                                    bg='#e0f0ff', fg='red')
        self.status_label.pack(pady=5)
    
    def recover_password(self):
        identifier = self.identifier_entry.get().strip()
        
        if not identifier:
            self.status_label.config(text="Username/email is required", fg='red')
            return
        
        user = get_user_by_email_or_username(identifier, self.controller.users_db)
        if not user:
            self.status_label.config(text="User not found", fg='red')
            return
        
        # Show security question
        security_question = user['security_question']
        answer = simpledialog.askstring("Security Question", 
                                       f"{security_question}\nAnswer:", 
                                       parent=self)
        
        if not answer:
            return
        
        if answer.strip().lower() != user['security_answer'].strip().lower():
            self.status_label.config(text="Incorrect security answer", fg='red')
            return
        
        # Generate temporary password
        temp_password = generate_strong_password(16)
        
        # Update user's password (in real app, you would send this via email)
        self.controller.users_db[user['username']]['password'] = hash_password(temp_password)
        save_users(self.controller.users_db)
        
        # Show temporary password (in a real app, this would be emailed)
        messagebox.showinfo("Password Reset", 
                          f"Your temporary password is:\n{temp_password}\n\n"
                          "Please change it after logging in.", parent=self)
        
        self.controller.show_frame(SignInPage)

class StoragePage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(bg='#e0f0ff')
        self.font_conf = ('Arial', 12)
        self.selected_item = None
        self.search_var = tk.StringVar()
        self.search_var.trace("w", self.on_search)
        
        # Top Navigation Bar
        nav_frame = tk.Frame(self, bg='#4e73df', height=50)
        nav_frame.pack(side='top', fill='x')
        nav_frame.pack_propagate(False)
        
        # App Title
        tk.Label(nav_frame, text="PassShield", font=('Arial', 18, 'bold'), 
                bg='#4e73df', fg='white').pack(side='left', padx=20)
        
        # Navigation Buttons
        nav_buttons = tk.Frame(nav_frame, bg='#4e73df')
        nav_buttons.pack(side='right', padx=10)
        
        tk.Button(nav_buttons, text="Guide", command=lambda: controller.show_frame(GuidePage),
                font=self.font_conf, bg='#4e73df', fg='white', relief='flat',
                cursor='hand2').pack(side='left', padx=5)
        
        tk.Button(nav_buttons, text="Settings", command=lambda: controller.show_frame(SettingsPage),
                font=self.font_conf, bg='#4e73df', fg='white', relief='flat',
                cursor='hand2').pack(side='left', padx=5)
        
        tk.Button(nav_buttons, text="Sign Out", command=self.sign_out,
                font=self.font_conf, bg='#4e73df', fg='white', relief='flat',
                cursor='hand2').pack(side='left', padx=5)
        
        # Main Content Area
        main_frame = tk.Frame(self, bg='#e0f0ff')
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Left Panel - Password List
        left_panel = tk.Frame(main_frame, bg='#f0f0f0', bd=1, relief='solid')
        left_panel.pack(side='left', fill='y', padx=(0, 10))
        left_panel.pack_propagate(False)
        left_panel.config(width=300)
        
        # Search Box
        search_frame = tk.Frame(left_panel, bg='#f0f0f0', padx=10, pady=10)
        search_frame.pack(fill='x')
        
        tk.Label(search_frame, text="Search:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w')
        
        search_entry = tk.Entry(search_frame, textvariable=self.search_var, 
                              font=self.font_conf, relief='solid', 
                              highlightthickness=0, bd=1)
        search_entry.pack(fill='x', pady=5, ipady=5)
        
        # Password List
        list_frame = tk.Frame(left_panel, bg='#f0f0f0')
        list_frame.pack(fill='both', expand=True)
        
        self.tree = ttk.Treeview(list_frame, columns=('name'), show='headings')
        self.tree.heading('name', text='Saved Passwords')
        self.tree.column('name', width=280)
        
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        self.tree.bind('<<TreeviewSelect>>', self.on_password_select)
        
        # Add Password Button
        add_btn = tk.Button(left_panel, text="+ Add New Password", 
                          command=self.add_password,
                          font=self.font_conf, bg='#4CAF50', fg='black',
                          relief='solid', bd=1, padx=10, pady=5)
        add_btn.pack(fill='x', padx=10, pady=10)
        
        # Right Panel - Password Details
        right_panel = tk.Frame(main_frame, bg='#f0f0f0', bd=1, relief='solid')
        right_panel.pack(side='right', fill='both', expand=True)
        
        # Password Details Header
        detail_header = tk.Frame(right_panel, bg='#4e73df', height=50)
        detail_header.pack(side='top', fill='x')
        detail_header.pack_propagate(False)
        
        self.detail_title = tk.Label(detail_header, text="Password Details", 
                                   font=('Arial', 16, 'bold'), bg='#4e73df', 
                                   fg='white')
        self.detail_title.pack(side='left', padx=20)
        
        # Action Buttons
        action_buttons = tk.Frame(detail_header, bg='#4e73df')
        action_buttons.pack(side='right', padx=10)
        
        self.copy_btn = tk.Button(action_buttons, text="Copy", 
                                command=self.copy_password,
                                font=self.font_conf, bg='#4e73df', fg='white', 
                                relief='flat', state='disabled', cursor='hand2')
        self.copy_btn.pack(side='left', padx=5)
        
        self.edit_btn = tk.Button(action_buttons, text="Edit", 
                                command=self.edit_password,
                                font=self.font_conf, bg='#4e73df', fg='white', 
                                relief='flat', state='disabled', cursor='hand2')
        self.edit_btn.pack(side='left', padx=5)
        
        self.delete_btn = tk.Button(action_buttons, text="Delete", 
                                  command=self.delete_password,
                                  font=self.font_conf, bg='#4e73df', fg='white', 
                                  relief='flat', state='disabled', cursor='hand2')
        self.delete_btn.pack(side='left', padx=5)
        
        # Password Details Content
        detail_content = tk.Frame(right_panel, bg='#f0f0f0', padx=20, pady=20)
        detail_content.pack(fill='both', expand=True)
        
        # Name
        tk.Label(detail_content, text="Name:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').grid(row=0, column=0, sticky='w', pady=5)
        self.name_label = tk.Label(detail_content, text="", font=self.font_conf, 
                                 bg='#f0f0f0', fg='black')
        self.name_label.grid(row=0, column=1, sticky='w', pady=5)
        
        # Username
        tk.Label(detail_content, text="Username/Email:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').grid(row=1, column=0, sticky='w', pady=5)
        self.username_label = tk.Label(detail_content, text="", font=self.font_conf, 
                                     bg='#f0f0f0', fg='black')
        self.username_label.grid(row=1, column=1, sticky='w', pady=5)
        
        # Password
        tk.Label(detail_content, text="Password:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').grid(row=2, column=0, sticky='w', pady=5)
        
        password_frame = tk.Frame(detail_content, bg='#f0f0f0')
        password_frame.grid(row=2, column=1, sticky='w', pady=5)
        
        self.password_label = tk.Label(password_frame, text="", font=self.font_conf, 
                                     bg='#f0f0f0', fg='black')
        self.password_label.pack(side='left')
        
        self.show_pass_btn = tk.Button(password_frame, text="Show", 
                                     command=self.toggle_password_display,
                                     font=self.font_conf, bg='#e0f0ff', 
                                     fg='black', relief='solid', bd=1,
                                     state='disabled', cursor='hand2')
        self.show_pass_btn.pack(side='left', padx=5)
        
        # URL
        tk.Label(detail_content, text="URL:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').grid(row=3, column=0, sticky='w', pady=5)
        self.url_label = tk.Label(detail_content, text="", font=self.font_conf, 
                                bg='#f0f0f0', fg='black')
        self.url_label.grid(row=3, column=1, sticky='w', pady=5)
        
        # Notes
        tk.Label(detail_content, text="Notes:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').grid(row=4, column=0, sticky='nw', pady=5)
        self.notes_label = tk.Label(detail_content, text="", font=self.font_conf, 
                                  bg='#f0f0f0', fg='black', wraplength=400,
                                  justify='left')
        self.notes_label.grid(row=4, column=1, sticky='w', pady=5)
        
        # Created/Modified
        tk.Label(detail_content, text="Created:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').grid(row=5, column=0, sticky='w', pady=5)
        self.created_label = tk.Label(detail_content, text="", font=self.font_conf, 
                                     bg='#f0f0f0', fg='black')
        self.created_label.grid(row=5, column=1, sticky='w', pady=5)
        
        tk.Label(detail_content, text="Modified:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').grid(row=6, column=0, sticky='w', pady=5)
        self.modified_label = tk.Label(detail_content, text="", font=self.font_conf, 
                                      bg='#f0f0f0', fg='black')
        self.modified_label.grid(row=6, column=1, sticky='w', pady=5)
        
        # Status label
        self.status_label = tk.Label(right_panel, text="", font=self.font_conf, 
                                    bg='#f0f0f0', fg='red')
        self.status_label.pack(side='bottom', fill='x', pady=10)
    
    def on_show(self):
        self.load_passwords()
        self.clear_details()
    
    def load_passwords(self):
        self.tree.delete(*self.tree.get_children())
        if self.controller.current_user in self.controller.password_db:
            passwords = self.controller.password_db[self.controller.current_user]
            for name in sorted(passwords.keys()):
                self.tree.insert('', 'end', values=(name,))
    
    def on_search(self, *args):
        query = self.search_var.get().lower()
        self.tree.delete(*self.tree.get_children())
        
        if self.controller.current_user in self.controller.password_db:
            passwords = self.controller.password_db[self.controller.current_user]
            for name in sorted(passwords.keys()):
                if query in name.lower():
                    self.tree.insert('', 'end', values=(name,))
    
    def on_password_select(self, event):
        selected = self.tree.focus()
        if not selected:
            return
        
        self.selected_item = self.tree.item(selected)['values'][0]
        password_data = self.controller.password_db[self.controller.current_user][self.selected_item]
        
        self.name_label.config(text=self.selected_item)
        self.username_label.config(text=password_data.get('username', ''))
        self.password_label.config(text="••••••••")
        self.url_label.config(text=password_data.get('url', ''))
        self.notes_label.config(text=password_data.get('notes', ''))
        self.created_label.config(text=password_data.get('created_at', ''))
        self.modified_label.config(text=password_data.get('modified_at', ''))
        
        self.copy_btn.config(state='normal')
        self.edit_btn.config(state='normal')
        self.delete_btn.config(state='normal')
        self.show_pass_btn.config(state='normal')
        self.password_shown = False
    
    def clear_details(self):
        self.selected_item = None
        self.name_label.config(text="")
        self.username_label.config(text="")
        self.password_label.config(text="")
        self.url_label.config(text="")
        self.notes_label.config(text="")
        self.created_label.config(text="")
        self.modified_label.config(text="")
        
        self.copy_btn.config(state='disabled')
        self.edit_btn.config(state='disabled')
        self.delete_btn.config(state='disabled')
        self.show_pass_btn.config(state='disabled')
    
    def toggle_password_display(self):
        if not self.selected_item:
            return
        
        password_data = self.controller.password_db[self.controller.current_user][self.selected_item]
        
        if not self.password_shown:
            self.password_label.config(text=password_data['password'])
            self.show_pass_btn.config(text="Hide")
            self.password_shown = True
        else:
            self.password_label.config(text="••••••••")
            self.show_pass_btn.config(text="Show")
            self.password_shown = False
    
    def copy_password(self):
        if not self.selected_item:
            return
        
        password_data = self.controller.password_db[self.controller.current_user][self.selected_item]
        pyperclip.copy(password_data['password'])
        self.status_label.config(text="Password copied to clipboard!", fg='green')
        self.after(3000, lambda: self.status_label.config(text=""))
    
    def add_password(self):
        dialog = PasswordDialog(self, title="Add New Password")
        self.wait_window(dialog)
        
        if dialog.result:
            name = dialog.result['name']
            username = dialog.result['username']
            password = dialog.result['password']
            url = dialog.result['url']
            notes = dialog.result['notes']
            
            if not name:
                self.status_label.config(text="Name is required", fg='red')
                return
            
            if self.controller.current_user not in self.controller.password_db:
                self.controller.password_db[self.controller.current_user] = {}
            
            if name in self.controller.password_db[self.controller.current_user]:
                self.status_label.config(text="A password with this name already exists", fg='red')
                return
            
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.controller.password_db[self.controller.current_user][name] = {
                'username': username,
                'password': password,
                'url': url,
                'notes': notes,
                'created_at': now,
                'modified_at': now
            }
            
            save_db(self.controller.password_db)
            self.load_passwords()
            self.status_label.config(text="Password added successfully!", fg='green')
    
    def edit_password(self):
        if not self.selected_item:
            return
        
        password_data = self.controller.password_db[self.controller.current_user][self.selected_item]
        
        dialog = PasswordDialog(
            self, 
            title="Edit Password",
            name=self.selected_item,
            username=password_data['username'],
            password=password_data['password'],
            url=password_data.get('url', ''),
            notes=password_data.get('notes', '')
        )
        
        self.wait_window(dialog)
        
        if dialog.result:
            name = dialog.result['name']
            username = dialog.result['username']
            password = dialog.result['password']
            url = dialog.result['url']
            notes = dialog.result['notes']
            
            if not name:
                self.status_label.config(text="Name is required", fg='red')
                return
            
            # If name changed, check if new name exists
            if name != self.selected_item and name in self.controller.password_db[self.controller.current_user]:
                self.status_label.config(text="A password with this name already exists", fg='red')
                return
            
            # Remove old entry if name changed
            if name != self.selected_item:
                del self.controller.password_db[self.controller.current_user][self.selected_item]
                self.selected_item = name
            
            # Update password data
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.controller.password_db[self.controller.current_user][name] = {
                'username': username,
                'password': password,
                'url': url,
                'notes': notes,
                'created_at': password_data['created_at'],
                'modified_at': now
            }
            
            save_db(self.controller.password_db)
            self.load_passwords()
            self.on_password_select(None)  # Refresh details
            self.status_label.config(text="Password updated successfully!", fg='green')
    
    def delete_password(self):
        if not self.selected_item:
            return
        
        confirm = messagebox.askyesno(
            "Confirm Delete",
            f"Are you sure you want to delete '{self.selected_item}'?",
            parent=self
        )
        
        if confirm:
            del self.controller.password_db[self.controller.current_user][self.selected_item]
            save_db(self.controller.password_db)
            self.load_passwords()
            self.clear_details()
            self.status_label.config(text="Password deleted successfully!", fg='green')
    
    def sign_out(self):
        self.controller.current_user = None
        self.controller.show_frame(SignInPage)

class PasswordDialog(tk.Toplevel):
    def __init__(self, parent, title, name="", username="", password="", url="", notes=""):
        super().__init__(parent)
        self.title(title)
        self.geometry("500x500")
        self.resizable(False, False)
        self.configure(bg='#e0f0ff')
        self.font_conf = ('Arial', 12)
        
        self.result = None
        
        # Main Frame
        main_frame = tk.Frame(self, bg='#e0f0ff', padx=20, pady=20)
        main_frame.pack(fill='both', expand=True)
        
        # Name
        tk.Label(main_frame, text="Name*:", font=self.font_conf, 
                bg='#e0f0ff', fg='black').pack(anchor='w', pady=(0, 5))
        self.name_entry = tk.Entry(main_frame, font=self.font_conf, 
                                 relief='solid', highlightthickness=0,
                                 bd=1, bg='white', fg='black', 
                                 insertbackground='black', insertwidth=2)
        self.name_entry.pack(fill='x', pady=5, ipady=5)
        self.name_entry.insert(0, name)
        
        # Username/Email
        tk.Label(main_frame, text="Username/Email:", font=self.font_conf, 
                bg='#e0f0ff', fg='black').pack(anchor='w', pady=(10, 5))
        self.username_entry = tk.Entry(main_frame, font=self.font_conf, 
                                    relief='solid', highlightthickness=0,
                                    bd=1, bg='white', fg='black', 
                                    insertbackground='black', insertwidth=2)
        self.username_entry.pack(fill='x', pady=5, ipady=5)
        self.username_entry.insert(0, username)
        
        # Password
        tk.Label(main_frame, text="Password*:", font=self.font_conf, 
                bg='#e0f0ff', fg='black').pack(anchor='w', pady=(10, 5))
        
        password_frame = tk.Frame(main_frame, bg='#e0f0ff')
        password_frame.pack(fill='x', pady=5)
        
        self.password_entry = tk.Entry(password_frame, font=self.font_conf, show="•", 
                                     relief='solid', highlightthickness=0, bd=1, 
                                     bg='white', fg='black', insertbackground='black', 
                                     insertwidth=2)
        self.password_entry.pack(side='left', fill='x', expand=True, ipady=5)
        self.password_entry.insert(0, password)
        
        self.generate_btn = tk.Button(password_frame, text="Generate", 
                                    command=self.generate_password,
                                    font=self.font_conf, bg='#e0f0ff', 
                                    fg='black', relief='solid', bd=1,
                                    cursor='hand2')
        self.generate_btn.pack(side='left', padx=5)
        
        # URL
        tk.Label(main_frame, text="URL:", font=self.font_conf, 
                bg='#e0f0ff', fg='black').pack(anchor='w', pady=(10, 5))
        self.url_entry = tk.Entry(main_frame, font=self.font_conf, 
                                relief='solid', highlightthickness=0,
                                bd=1, bg='white', fg='black', 
                                insertbackground='black', insertwidth=2)
        self.url_entry.pack(fill='x', pady=5, ipady=5)
        self.url_entry.insert(0, url)
        
        # Notes
        tk.Label(main_frame, text="Notes:", font=self.font_conf, 
                bg='#e0f0ff', fg='black').pack(anchor='w', pady=(10, 5))
        self.notes_text = tk.Text(main_frame, font=self.font_conf, 
                                relief='solid', highlightthickness=0,
                                bd=1, bg='white', fg='black', 
                                insertbackground='black', insertwidth=2,
                                height=5)
        self.notes_text.pack(fill='x', pady=5)
        self.notes_text.insert('1.0', notes)
        
        # Button Frame
        button_frame = tk.Frame(main_frame, bg='#e0f0ff')
        button_frame.pack(fill='x', pady=20)
        
        tk.Button(button_frame, text="Save", command=self.on_save,
                font=self.font_conf, bg='#4CAF50', fg='black', 
                relief='solid', bd=1, padx=20, pady=5,
                cursor='hand2').pack(side='left', expand=True, padx=5)
        
        tk.Button(button_frame, text="Cancel", command=self.destroy,
                font=self.font_conf, bg='#f44336', fg='black', 
                relief='solid', bd=1, padx=20, pady=5,
                cursor='hand2').pack(side='left', expand=True, padx=5)
        
        # Status label
        self.status_label = tk.Label(main_frame, text="", font=self.font_conf, 
                                    bg='#e0f0ff', fg='red')
        self.status_label.pack(pady=5)
    
    def generate_password(self):
        password = generate_strong_password()
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
    
    def on_save(self):
        name = self.name_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        url = self.url_entry.get().strip()
        notes = self.notes_text.get("1.0", tk.END).strip()
        
        if not name:
         self.status_label.config(text="Name is required", fg='red')
        return
        
        if not password:
            self.status_label.config(text="Password is required", fg='red')
            return
        
        self.result = {
            'name': name,
            'username': username,
            'password': password,
            'url': url,
            'notes': notes
        }
        self.destroy()

class SettingsPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(bg='#e0f0ff')
        self.font_conf = ('Arial', 12)
        
        # Top Navigation Bar
        nav_frame = tk.Frame(self, bg='#4e73df', height=50)
        nav_frame.pack(side='top', fill='x')
        nav_frame.pack_propagate(False)
        
        # App Title
        tk.Label(nav_frame, text="PassShield", font=('Arial', 18, 'bold'), 
                bg='#4e73df', fg='white').pack(side='left', padx=20)
        
        # Navigation Buttons
        nav_buttons = tk.Frame(nav_frame, bg='#4e73df')
        nav_buttons.pack(side='right', padx=10)
        
        tk.Button(nav_buttons, text="Storage", command=lambda: controller.show_frame(StoragePage),
                font=self.font_conf, bg='#4e73df', fg='white', relief='flat',
                cursor='hand2').pack(side='left', padx=5)
        
        tk.Button(nav_buttons, text="Guide", command=lambda: controller.show_frame(GuidePage),
                font=self.font_conf, bg='#4e73df', fg='white', relief='flat',
                cursor='hand2').pack(side='left', padx=5)
        
        tk.Button(nav_buttons, text="Sign Out", command=self.sign_out,
                font=self.font_conf, bg='#4e73df', fg='white', relief='flat',
                cursor='hand2').pack(side='left', padx=5)
        
        # Main Content Area
        main_frame = tk.Frame(self, bg='#e0f0ff', padx=20, pady=20)
        main_frame.pack(fill='both', expand=True)
        
        # Settings Title
        tk.Label(main_frame, text="Account Settings", font=('Arial', 20, 'bold'), 
                bg='#e0f0ff', fg='black').pack(pady=10)
        
        # Settings Options
        options_frame = tk.Frame(main_frame, bg='#f0f0f0', bd=1, relief='solid')
        options_frame.pack(fill='both', expand=True, pady=10)
        
        # Change Password
        pass_frame = tk.Frame(options_frame, bg='#f0f0f0', padx=10, pady=10)
        pass_frame.pack(fill='x', pady=5)
        
        tk.Label(pass_frame, text="Change Password:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w')
        
        self.change_pass_btn = tk.Button(pass_frame, text="Change Password", 
                                       command=self.change_password,
                                       font=self.font_conf, bg='#e0f0ff', 
                                       fg='black', relief='solid', bd=1,
                                       cursor='hand2')
        self.change_pass_btn.pack(pady=5, fill='x')
        
        # Change PIN
        pin_frame = tk.Frame(options_frame, bg='#f0f0f0', padx=10, pady=10)
        pin_frame.pack(fill='x', pady=5)
        
        tk.Label(pin_frame, text="Change PIN:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w')
        
        self.change_pin_btn = tk.Button(pin_frame, text="Change PIN", 
                                      command=self.change_pin,
                                      font=self.font_conf, bg='#e0f0ff', 
                                      fg='black', relief='solid', bd=1,
                                      cursor='hand2')
        self.change_pin_btn.pack(pady=5, fill='x')
        
        # Change Security Question
        sec_frame = tk.Frame(options_frame, bg='#f0f0f0', padx=10, pady=10)
        sec_frame.pack(fill='x', pady=5)
        
        tk.Label(sec_frame, text="Security Question:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w')
        
        self.change_sec_btn = tk.Button(sec_frame, text="Change Security Question", 
                                      command=self.change_security_question,
                                      font=self.font_conf, bg='#e0f0ff', 
                                      fg='black', relief='solid', bd=1,
                                      cursor='hand2')
        self.change_sec_btn.pack(pady=5, fill='x')
        
        # Status label
        self.status_label = tk.Label(main_frame, text="", font=self.font_conf, 
                                    bg='#e0f0ff', fg='red')
        self.status_label.pack(pady=5)
    
    def change_password(self):
        current_password = simpledialog.askstring("Change Password", 
                                               "Enter current password:", 
                                               parent=self, show='*')
        if not current_password:
            return
        
        # Verify current password
        user_data = self.controller.users_db[self.controller.current_user]
        if not verify_password(current_password, user_data['password']):
            self.status_label.config(text="Incorrect current password", fg='red')
            return
        
        new_password = simpledialog.askstring("Change Password", 
                                            "Enter new password:", 
                                            parent=self, show='*')
        if not new_password:
            return
        
        confirm_password = simpledialog.askstring("Change Password", 
                                                "Confirm new password:", 
                                                parent=self, show='*')
        if not confirm_password:
            return
        
        if new_password != confirm_password:
            self.status_label.config(text="Passwords don't match", fg='red')
            return
        
        if len(new_password) < 15:
            self.status_label.config(text="Password must be at least 15 characters", fg='red')
            return
        
        # Check password strength
        strength = check_password_strength(new_password)
        if "Weak" in strength:
            self.status_label.config(text=f"Password too weak: {strength}", fg='red')
            return
        
        # Update password
        self.controller.users_db[self.controller.current_user]['password'] = hash_password(new_password)
        save_users(self.controller.users_db)
        self.status_label.config(text="Password changed successfully!", fg='green')
    
    def change_pin(self):
        current_pin = simpledialog.askstring("Change PIN", 
                                           "Enter current PIN:", 
                                           parent=self, show='*')
        if not current_pin:
            return
        
        # Verify current PIN
        user_data = self.controller.users_db[self.controller.current_user]
        if current_pin != user_data['pin']:
            self.status_label.config(text="Incorrect current PIN", fg='red')
            return
        
        new_pin = simpledialog.askstring("Change PIN", 
                                       "Enter new PIN (at least 4 digits):", 
                                       parent=self, show='*')
        if not new_pin:
            return
        
        confirm_pin = simpledialog.askstring("Change PIN", 
                                           "Confirm new PIN:", 
                                           parent=self, show='*')
        if not confirm_pin:
            return
        
        if not validate_pin(new_pin):
            self.status_label.config(text="PIN must be at least 4 digits", fg='red')
            return
        
        if new_pin != confirm_pin:
            self.status_label.config(text="PINs don't match", fg='red')
            return
        
        # Update PIN
        self.controller.users_db[self.controller.current_user]['pin'] = new_pin
        save_users(self.controller.users_db)
        self.status_label.config(text="PIN changed successfully!", fg='green')
    
    def change_security_question(self):
        current_answer = simpledialog.askstring("Security Check", 
                                              "Enter current security answer:", 
                                              parent=self)
        if not current_answer:
            return
        
        # Verify current security answer
        user_data = self.controller.users_db[self.controller.current_user]
        if current_answer.strip().lower() != user_data['security_answer'].strip().lower():
            self.status_label.config(text="Incorrect security answer", fg='red')
            return
        
        # Select new question
        new_question = simpledialog.askstring("Change Security Question", 
                                            "Enter new security question:", 
                                            parent=self)
        if not new_question:
            return
        
        new_answer = simpledialog.askstring("Change Security Question", 
                                          "Enter answer to new question:", 
                                          parent=self)
        if not new_answer:
            return
        
        # Update security question
        self.controller.users_db[self.controller.current_user]['security_question'] = new_question
        self.controller.users_db[self.controller.current_user]['security_answer'] = new_answer
        save_users(self.controller.users_db)
        self.status_label.config(text="Security question updated successfully!", fg='green')
    
    def sign_out(self):
        self.controller.current_user = None
        self.controller.show_frame(SignInPage)

class GuidePage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(bg='#e0f0ff')
        self.font_conf = ('Arial', 12)
        
        # Top Navigation Bar
        nav_frame = tk.Frame(self, bg='#4e73df', height=50)
        nav_frame.pack(side='top', fill='x')
        nav_frame.pack_propagate(False)
        
        # App Title
        tk.Label(nav_frame, text="PassShield", font=('Arial', 18, 'bold'), 
                bg='#4e73df', fg='white').pack(side='left', padx=20)
        
        # Navigation Buttons
        nav_buttons = tk.Frame(nav_frame, bg='#4e73df')
        nav_buttons.pack(side='right', padx=10)
        
        tk.Button(nav_buttons, text="Storage", command=lambda: controller.show_frame(StoragePage),
                font=self.font_conf, bg='#4e73df', fg='white', relief='flat',
                cursor='hand2').pack(side='left', padx=5)
        
        tk.Button(nav_buttons, text="Settings", command=lambda: controller.show_frame(SettingsPage),
                font=self.font_conf, bg='#4e73df', fg='white', relief='flat',
                cursor='hand2').pack(side='left', padx=5)
        
        tk.Button(nav_buttons, text="Sign Out", command=self.sign_out,
                font=self.font_conf, bg='#4e73df', fg='white', relief='flat',
                cursor='hand2').pack(side='left', padx=5)
        
        # Main Content Area
        main_frame = tk.Frame(self, bg='#e0f0ff', padx=20, pady=20)
        main_frame.pack(fill='both', expand=True)
        
        # Guide Title
        tk.Label(main_frame, text="User Guide", font=('Arial', 20, 'bold'), 
                bg='#e0f0ff', fg='black').pack(pady=10)
        
        # Text Widget for Guide Content
        text_frame = tk.Frame(main_frame, bg='#f0f0f0', bd=1, relief='solid')
        text_frame.pack(fill='both', expand=True)
        
        scrollbar = tk.Scrollbar(text_frame)
        scrollbar.pack(side='right', fill='y')
        
        self.guide_text = tk.Text(text_frame, wrap='word', yscrollcommand=scrollbar.set,
                                 font=self.font_conf, bg='white', fg='black',
                                 padx=10, pady=10, relief='flat')
        self.guide_text.pack(fill='both', expand=True)
        
        scrollbar.config(command=self.guide_text.yview)
        
        # Insert guide content
        guide_content = """
        PassShield User Guide
        
        1. Getting Started
        - Sign up for an account with a strong password (at least 15 characters)
        - Remember your PIN and security question answers
        - Log in to access your password vault
        
        2. Managing Passwords
        - Add new passwords with the "+ Add New Password" button
        - Click on any saved password to view its details
        - Use the Show button to reveal passwords when needed
        - Copy passwords directly to clipboard with the Copy button
        - Edit or delete saved passwords as needed
        
        3. Security Features
        - All passwords are encrypted and stored securely
        - Use the password generator to create strong passwords
        - Change your master password regularly in Settings
        - Update your security questions periodically
        
        4. Best Practices
        - Never reuse passwords across different sites
        - Change passwords immediately if a service reports a breach
        - Enable two-factor authentication where available
        - Be cautious of phishing attempts
        
        5. Troubleshooting
        - If you forget your password, use the Forgot Password option
        - Contact support if you suspect unauthorized access
        - Regularly back up your password database
        """
        self.guide_text.insert('1.0', guide_content)
        self.guide_text.config(state='disabled')
    
    def sign_out(self):
        self.controller.current_user = None
        self.controller.show_frame(SignInPage)

# Helper functions
def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_pin(pin):
    return pin.isdigit() and len(pin) >= 4

def check_password_strength(password):
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    strength = 0
    if length >= 15: strength += 2
    elif length >= 10: strength += 1
    
    if has_upper: strength += 1
    if has_lower: strength += 1
    if has_digit: strength += 1
    if has_special: strength += 1
    
    if strength >= 6:
        return "Strong password"
    elif strength >= 4:
        return "Medium password (consider adding more complexity)"
    else:
        return "Weak password (too short or lacks complexity)"

def generate_strong_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(random.choice(chars) for _ in range(length))
        if any(c.islower() for c in password) and \
           any(c.isupper() for c in password) and \
           any(c.isdigit() for c in password) and \
           any(not c.isalnum() for c in password):
            return password

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(input_password, hashed_password):
    return hash_password(input_password) == hashed_password

def get_user_by_email_or_username(identifier, users_db):
    for username, user_data in users_db.items():
        if username.lower() == identifier.lower() or user_data['email'].lower() == identifier.lower():
            return user_data
    return None

def save_users(users_db):
    with open('users.json', 'w') as f:
        json.dump(users_db, f)

def load_users():
    try:
        with open('users.json', 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_db(password_db):
    with open('passwords.json', 'w') as f:
        json.dump(password_db, f)

def load_db():
    try:
        with open('passwords.json', 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

# CAPTCHA questions
CAPTCHA_QUESTIONS = [
    {"question": "What is 3 + 5?", "answer": "8"},
    {"question": "What is the first letter of the alphabet?", "answer": "a"},
    {"question": "How many colors are in a rainbow? (number)", "answer": "7"},
    {"question": "What is 10 minus 3?", "answer": "7"},
    {"question": "Spell 'cat' backwards", "answer": "tac"}
]

if __name__ == "__main__":
    app = PassShieldApp()
    app.mainloop()