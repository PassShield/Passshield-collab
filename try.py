# ui.py - Complete PassShield Password Manager Application
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
import csv
import bcrypt
from threading import Timer
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Constants
DB_FILE = "passshield_db.json"
USERS_FILE = "users_db.json"
SETTINGS_FILE = "settings.json"
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

DEFAULT_SETTINGS = {
    'auto_lock': 15, 
    'theme': 'light', 
    'clipboard_clear': 30, 
    'default_length': 16,
    'complexity_upper': True,
    'complexity_lower': True,
    'complexity_digits': True,
    'complexity_special': True
}

# Utility functions
def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(stored_password, provided_password):
    try:
        return bcrypt.checkpw(provided_password.encode(), stored_password.encode())
    except ValueError:
        return False

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

def load_settings():
    if not os.path.exists(SETTINGS_FILE):
        return DEFAULT_SETTINGS
    try:
        with open(SETTINGS_FILE, 'r') as f:
            settings = json.load(f)
            # Ensure all settings are present
            for key, value in DEFAULT_SETTINGS.items():
                if key not in settings:
                    settings[key] = value
            return settings
    except:
        return DEFAULT_SETTINGS

def save_settings(data):
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def get_user_by_email_or_username(identifier, users_db):
    for user in users_db.values():
        if user['email'].lower() == identifier.lower() or user['username'].lower() == identifier.lower():
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
           (any(c in string.punctuation for c in password)):
            return password

def generate_pin(length=6):
    return ''.join(secrets.choice(string.digits) for _ in range(length))

def validate_pin(pin):
    return len(pin) == 6 and pin.isdigit()

class ChangePasswordPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(bg='#e0f0ff')
        self.font_conf = ('Arial', 12)
        self.show_current_password = False
        self.show_new_password = False
        self.show_confirm_password = False
        
        # Center container
        center_frame = tk.Frame(self, bg='#e0f0ff')
        center_frame.place(relx=0.5, rely=0.5, anchor='center')
        
        # Logo (scaled to small size)
        try:
            logo_img = tk.PhotoImage(file="images/logo.png")
            logo_img = logo_img.subsample(4, 4)  # Scale down more
            logo_label = tk.Label(center_frame, image=logo_img, bg='#e0f0ff')
            logo_label.image = logo_img
            logo_label.pack(pady=10)
        except:
            tk.Label(center_frame, text="🔒 PassShield", font=('Arial', 20, 'bold'), 
                    bg='#e0f0ff', fg='black').pack(pady=10)
        
        tk.Label(center_frame, text="Change Password", font=('Arial', 16, 'bold'), 
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
        self.password_strength = tk.Label(entry_frame, text="", font=('Arial', 10), 
                                        bg='#f0f0f0', fg='red')
        self.password_strength.pack(anchor='w', pady=(3, 0))
        self.new_password_entry.bind('<KeyRelease>', self.check_password_strength)
        
        # Confirm Password
        tk.Label(entry_frame, text="Confirm New Password:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w', pady=(10, 5))
        
        confirm_pass_frame = tk.Frame(entry_frame, bg='#f0f0f0')
        confirm_pass_frame.pack(fill='x', pady=5)
        
        self.confirm_password_entry = tk.Entry(confirm_pass_frame, font=self.font_conf, show="•", 
                                             relief='solid', highlightthickness=0, bd=1, 
                                             bg='white', fg='black', insertbackground='black', 
                                             insertwidth=2)
        self.confirm_password_entry.pack(side='left', fill='x', expand=True, ipady=5)
        
        self.toggle_confirm_btn = tk.Button(confirm_pass_frame, text="Show", command=self.toggle_confirm_password, 
                                          bg='#e0f0ff', fg='black', relief='solid', bd=1,
                                          font=self.font_conf, padx=10, cursor='hand2')
        self.toggle_confirm_btn.pack(side='left', padx=5)
        
        # Button Frame
        button_frame = tk.Frame(center_frame, bg='#e0f0ff')
        button_frame.pack(pady=15, fill='x', padx=20)
        
        tk.Button(button_frame, text="Change Password", command=self.change_password, font=self.font_conf,
                 bg='#4CAF50', fg='black', relief='solid', bd=1, padx=20, pady=5,
                 cursor='hand2').pack(pady=5, fill='x')
        
        tk.Button(button_frame, text="Back to Login", 
                 command=lambda: controller.show_frame(SignInPage), 
                 font=self.font_conf, fg="blue", bg='#e0f0ff', relief='flat',
                 cursor='hand2').pack(pady=5)
        
        # Status label
        self.status_label = tk.Label(center_frame, text="", font=self.font_conf, 
                                    bg='#e0f0ff', fg='red')
        self.status_label.pack(pady=5)
    
    def toggle_current_password(self):
        self.show_current_password = not self.show_current_password
        show_char = "" if self.show_current_password else "•"
        self.current_password_entry.config(show=show_char)
        self.toggle_current_pass_btn.config(text="Hide" if self.show_current_password else "Show")
    
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
        
        if not all([identifier, current_password, new_password, confirm_password]):
            self.status_label.config(text="All fields are required", fg='red')
            return
        
        if new_password != confirm_password:
            self.status_label.config(text="New passwords don't match", fg='red')
            return
        
        if len(new_password) < 15:
            self.status_label.config(text="Password must be at least 15 characters", fg='red')
            return
        
        # Check password strength
        strength = check_password_strength(new_password)
        if "Weak" in strength:
            self.status_label.config(text=f"Password too weak: {strength}", fg='red')
            return
        
        user = get_user_by_email_or_username(identifier, self.controller.users_db)
        if not user:
            self.status_label.config(text="User not found", fg='red')
            return
        
        if not verify_password(user['password'], current_password):
            self.status_label.config(text="Current password is incorrect", fg='red')
            return
        
        # Update password
        self.controller.users_db[user['username']]['password'] = hash_password(new_password)
        save_users(self.controller.users_db)
        
        self.status_label.config(text="Password changed successfully! Redirecting to login...", fg='green')
        
        # Clear fields and switch to login after 2 seconds
        self.after(2000, lambda: [
            self.identifier_entry.delete(0, tk.END),
            self.current_password_entry.delete(0, tk.END),
            self.new_password_entry.delete(0, tk.END),
            self.confirm_password_entry.delete(0, tk.END),
            self.password_strength.config(text=""),
            self.controller.show_frame(SignInPage)
        ])

# Main Application
class PassShieldApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PassShield - Secure Password Manager")
        self.geometry("800x500")
        self.configure(bg='#e0f0ff')
        
        self.users_db = load_users()
        self.password_db = load_db()
        self.settings = load_settings()
        self.current_user = None
        self.auto_lock_timer = None  # Initialize auto_lock_timer
        
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
        self.reset_auto_lock()
    
    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()
        if hasattr(frame, 'on_show'):
            frame.on_show()
        self.reset_auto_lock()
    
    def reset_auto_lock(self, event=None):
        if hasattr(self, 'auto_lock_timer') and self.auto_lock_timer:
            self.after_cancel(self.auto_lock_timer)
        
        lock_time = self.settings.get('auto_lock', 15) * 60 * 1000
        self.auto_lock_timer = self.after(lock_time, self.auto_lock)
    
    def auto_lock(self):
        if self.current_user:
            self.current_user = None
            self.show_frame(SignInPage)
            messagebox.showinfo("Auto-Lock", "You have been automatically logged out due to inactivity")

    def apply_theme(self, theme):
        """Apply light or dark theme to the application"""
        if theme == 'dark':
            bg_color = '#333333'
            fg_color = 'white'
            entry_bg = '#555555'
            entry_fg = 'white'
            button_bg = '#444444'
            button_fg = 'white'
        else:
            bg_color = '#e0f0ff'
            fg_color = 'black'
            entry_bg = 'white'
            entry_fg = 'black'
            button_bg = '#e0f0ff'
            button_fg = 'black'
        
        # Update main window
        self.configure(bg=bg_color)
        
        # Update all frames
        for frame in self.frames.values():
            frame.configure(bg=bg_color)
            for widget in frame.winfo_children():
                if isinstance(widget, tk.Frame):
                    widget.configure(bg=bg_color)
                    for child in widget.winfo_children():
                        try:
                            if isinstance(child, (tk.Entry, tk.Text)):
                                child.configure(bg=entry_bg, fg=entry_fg, insertbackground=fg_color)
                            elif isinstance(child, tk.Label):
                                child.configure(bg=bg_color, fg=fg_color)
                            elif isinstance(child, tk.Button):
                                child.configure(bg=button_bg, fg=button_fg)
                        except:
                            continue

# Pages
class SignInPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(bg='#e0f0ff')
        self.show_password = False
        self.font_conf = ('Arial', 12)
        
        # Center container
        center_frame = tk.Frame(self, bg='#e0f0ff')
        center_frame.place(relx=0.5, rely=0.5, anchor='center')
        
        # Logo (scaled to small size)
        try:
            logo_img = tk.PhotoImage(file="images/logo.png")
            logo_img = logo_img.subsample(4, 4)  # Scale down more
            logo_label = tk.Label(center_frame, image=logo_img, bg='#e0f0ff')
            logo_label.image = logo_img
            logo_label.pack(pady=10)
        except:
            tk.Label(center_frame, text="🔒 PassShield", font=('Arial', 20, 'bold'), 
                    bg='#e0f0ff', fg='black').pack(pady=10)
        
        tk.Label(center_frame, text="Sign In", font=('Arial', 16, 'bold'), 
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
        
        tk.Button(button_frame, text="Don't have an account? Sign Up", 
                 command=lambda: controller.show_frame(SignUpPage), 
                 font=self.font_conf, fg="blue", bg='#e0f0ff', relief='flat',
                 cursor='hand2').pack(pady=5)

        # Add Change Password button
        tk.Button(button_frame, text="Change Password", 
                 command=lambda: controller.show_frame(ChangePasswordPage), 
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
        
        # Ask for PIN
        pin = simpledialog.askstring("PIN Required", "Enter your 6-digit PIN:", show='*')
        if not pin or pin != user.get('pin', ''):
            self.status_label.config(text="Invalid PIN", fg='red')
            return
        
        # Login successful
        self.controller.current_user = user['username']
        self.controller.show_frame(StoragePage)
        
        # Clear fields
        self.identifier_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.status_label.config(text="")

class SignUpPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(bg='#e0f0ff')
        self.show_password = False
        self.show_confirm_password = False
        self.show_pin = False
        self.show_confirm_pin = False
        self.font_conf = ('Arial', 12)
        self.captcha_attempts = 0
        self.captcha_locked = False
        
        # Main container with logo on top and form below
        main_frame = tk.Frame(self, bg='#e0f0ff')
        main_frame.pack(fill='both', expand=True, padx=20, pady=10)  # Reduced padding
        
        # Logo (scaled to small size)
        try:
            logo_img = tk.PhotoImage(file="images/logo.png")
            logo_img = logo_img.subsample(4, 4)  # Scale down more
            logo_label = tk.Label(main_frame, image=logo_img, bg='#e0f0ff')
            logo_label.image = logo_img
            logo_label.pack(pady=5)  # Reduced padding
        except:
            tk.Label(main_frame, text="🔒 PassShield", font=('Arial', 20, 'bold'), 
                    bg='#e0f0ff', fg='black').pack(pady=5)  # Reduced padding
        
        # Form title
        tk.Label(main_frame, text="Create New Account", font=('Arial', 16, 'bold'), 
                bg='#e0f0ff', fg='black').pack(pady=5)
        
        # Form container - made smaller by reducing padding
        form_frame = tk.Frame(main_frame, bg='#f0f0f0', padx=15, pady=15, bd=1, relief='solid')
        form_frame.pack(fill='x', pady=5, padx=20)  # Reduced padding
        
        # Username
        tk.Label(form_frame, text="Username (min 7 chars):", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w', pady=(0, 3))  # Reduced padding
        self.username_entry = tk.Entry(form_frame, font=self.font_conf, 
                                     relief='solid', highlightthickness=0,
                                     bd=1, bg='white', fg='black', 
                                     insertbackground='black', insertwidth=2)
        self.username_entry.pack(fill='x', pady=3, ipady=3)  # Reduced padding
        
        # Email
        tk.Label(form_frame, text="Email:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w', pady=(5, 3))  # Reduced padding
        self.email_entry = tk.Entry(form_frame, font=self.font_conf, 
                                  relief='solid', highlightthickness=0,
                                  bd=1, bg='white', fg='black', 
                                  insertbackground='black', insertwidth=2)
        self.email_entry.pack(fill='x', pady=3, ipady=3)  # Reduced padding
        
        # Password
        tk.Label(form_frame, text="Password (min 15 chars):", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w', pady=(5, 3))  # Reduced padding
        
        password_frame = tk.Frame(form_frame, bg='#f0f0f0')
        password_frame.pack(fill='x', pady=3)  # Reduced padding
        
        self.password_entry = tk.Entry(password_frame, font=self.font_conf, show="•", 
                                     relief='solid', highlightthickness=0, bd=1, 
                                     bg='white', fg='black', insertbackground='black', 
                                     insertwidth=2)
        self.password_entry.pack(side='left', fill='x', expand=True, ipady=3)  # Reduced padding
        
        self.toggle_pass_btn = tk.Button(password_frame, text="Show", command=self.toggle_password, 
                                       bg='#e0f0ff', fg='black', relief='solid', bd=1,
                                       font=self.font_conf, padx=5, cursor='hand2')  # Reduced padding
        self.toggle_pass_btn.pack(side='left', padx=3)  # Reduced padding
        
        # Password strength
        self.password_strength = tk.Label(form_frame, text="", font=('Arial', 10), 
                                        bg='#f0f0f0', fg='red')
        self.password_strength.pack(anchor='w', pady=(3, 0))  # Reduced padding
        self.password_entry.bind('<KeyRelease>', self.check_password_strength)
        
        # Confirm Password
        tk.Label(form_frame, text="Confirm Password:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w', pady=(5, 3))  # Reduced padding
        
        confirm_frame = tk.Frame(form_frame, bg='#f0f0f0')
        confirm_frame.pack(fill='x', pady=3)  # Reduced padding
        
        self.confirm_password_entry = tk.Entry(confirm_frame, font=self.font_conf, show="•", 
                                             relief='solid', highlightthickness=0, bd=1, 
                                             bg='white', fg='black', insertbackground='black', 
                                             insertwidth=2)
        self.confirm_password_entry.pack(side='left', fill='x', expand=True, ipady=3)  # Reduced padding
        
        self.toggle_confirm_btn = tk.Button(confirm_frame, text="Show", command=self.toggle_confirm_password, 
                                          bg='#e0f0ff', fg='black', relief='solid', bd=1,
                                          font=self.font_conf, padx=5, cursor='hand2')  # Reduced padding
        self.toggle_confirm_btn.pack(side='left', padx=3)  # Reduced padding
        
        # Security Question
        tk.Label(form_frame, text="Security Question:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w', pady=(5, 3))  # Reduced padding
        
        self.security_question = ttk.Combobox(form_frame, values=SECURITY_QUESTIONS,
                                            font=self.font_conf, state='readonly')
        self.security_question.pack(fill='x', pady=3, ipady=3)  # Reduced padding
        
        # Security Answer
        tk.Label(form_frame, text="Security Answer:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w', pady=(5, 3))  # Reduced padding
        self.security_answer_entry = tk.Entry(form_frame, font=self.font_conf, 
                                            relief='solid', highlightthickness=0,
                                            bd=1, bg='white', fg='black', 
                                            insertbackground='black', insertwidth=2)
        self.security_answer_entry.pack(fill='x', pady=3, ipady=3)  # Reduced padding
        
        # PIN
        tk.Label(form_frame, text="6-digit PIN:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w', pady=(5, 3))  # Reduced padding
        
        pin_frame = tk.Frame(form_frame, bg='#f0f0f0')
        pin_frame.pack(fill='x', pady=3)  # Reduced padding
        
        self.pin_entry = tk.Entry(pin_frame, font=self.font_conf, show="•", 
                                relief='solid', highlightthickness=0, bd=1, 
                                bg='white', fg='black', insertbackground='black', 
                                insertwidth=2)
        self.pin_entry.pack(side='left', fill='x', expand=True, ipady=3)  # Reduced padding
        
        self.toggle_pin_btn = tk.Button(pin_frame, text="Show", command=self.toggle_pin, 
                                      bg='#e0f0ff', fg='black', relief='solid', bd=1,
                                      font=self.font_conf, padx=5, cursor='hand2')  # Reduced padding
        self.toggle_pin_btn.pack(side='left', padx=3)  # Reduced padding
        
        # Confirm PIN
        tk.Label(form_frame, text="Confirm 6-digit PIN:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w', pady=(5, 3))  # Reduced padding
        
        confirm_pin_frame = tk.Frame(form_frame, bg='#f0f0f0')
        confirm_pin_frame.pack(fill='x', pady=3)  # Reduced padding
        
        self.confirm_pin_entry = tk.Entry(confirm_pin_frame, font=self.font_conf, show="•", 
                                        relief='solid', highlightthickness=0, bd=1, 
                                        bg='white', fg='black', insertbackground='black', 
                                        insertwidth=2)
        self.confirm_pin_entry.pack(side='left', fill='x', expand=True, ipady=3)  # Reduced padding
        
        self.toggle_confirm_pin_btn = tk.Button(confirm_pin_frame, text="Show", command=self.toggle_confirm_pin, 
                                              bg='#e0f0ff', fg='black', relief='solid', bd=1,
                                              font=self.font_conf, padx=5, cursor='hand2')  # Reduced padding
        self.toggle_confirm_pin_btn.pack(side='left', padx=3)  # Reduced padding
        
        # Human validation (CAPTCHA) - Added after PIN confirmation
        self.captcha_frame = tk.Frame(form_frame, bg='#f0f0f0')
        self.captcha_frame.pack(fill='x', pady=(5, 3))  # Reduced padding
        
        self.generate_captcha()
        
        # Status label
        self.status_label = tk.Label(form_frame, text="", font=self.font_conf, 
                                    bg='#f0f0f0', fg='red')
        self.status_label.pack(pady=5)  # Reduced padding
                # Button Frame - Updated layout with equal spacing
        button_frame = tk.Frame(main_frame, bg='#e0f0ff')
        button_frame.pack(pady=10, fill='x', padx=20)
        
        tk.Button(button_frame, text="Create Account", command=self.signup, font=self.font_conf,
                 bg='#4CAF50', fg='black', relief='solid', bd=1, padx=20, pady=5,
                 cursor='hand2').pack(pady=5, fill='x')
        
        tk.Button(button_frame, text="Already have an account? Sign In", 
                 command=lambda: controller.show_frame(SignInPage), 
                 font=self.font_conf, fg="blue", bg='#e0f0ff', relief='flat',
                 cursor='hand2').pack(pady=5)
    
    def generate_captcha(self):
        """Generate a simple CAPTCHA challenge"""
        if self.captcha_locked:
            return
            
        for widget in self.captcha_frame.winfo_children():
            widget.destroy()
            
        # Generate random math problem
        num1 = random.randint(1, 10)
        num2 = random.randint(1, 10)
        self.captcha_answer = num1 + num2
        self.captcha_text = f"What is {num1} + {num2}?"
        
        tk.Label(self.captcha_frame, text="Human Verification:", font=self.font_conf,
                bg='#f0f0f0', fg='black').pack(anchor='w', pady=(0, 3))
        
        captcha_row = tk.Frame(self.captcha_frame, bg='#f0f0f0')
        captcha_row.pack(fill='x')
        
        tk.Label(captcha_row, text=self.captcha_text, font=self.font_conf,
                bg='#f0f0f0', fg='black').pack(side='left', padx=(0, 5))
        
        self.captcha_entry = tk.Entry(captcha_row, font=self.font_conf,
                                    relief='solid', highlightthickness=0,
                                    bd=1, bg='white', fg='black', 
                                    insertbackground='black', insertwidth=2,
                                    width=5)
        self.captcha_entry.pack(side='left')
        
        refresh_btn = tk.Button(captcha_row, text="↻", command=self.generate_captcha,
                              bg='#e0f0ff', fg='black', relief='solid', bd=1,
                              font=self.font_conf, padx=5, cursor='hand2')
        refresh_btn.pack(side='left', padx=5)
    
    def toggle_password(self):
        self.show_password = not self.show_password
        show_char = "" if self.show_password else "•"
        self.password_entry.config(show=show_char)
        self.toggle_pass_btn.config(text="Hide" if self.show_password else "Show")
    
    def toggle_confirm_password(self):
        self.show_confirm_password = not self.show_confirm_password
        show_char = "" if self.show_confirm_password else "•"
        self.confirm_password_entry.config(show=show_char)
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
    
    def signup(self):
        if self.captcha_locked:
            self.status_label.config(text="Too many failed attempts. Please try again later.", fg='red')
            return
            
        # Get all form data
        username = self.username_entry.get().strip()
        email = self.email_entry.get().strip()
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        security_question = self.security_question.get()
        security_answer = self.security_answer_entry.get().strip()
        pin = self.pin_entry.get()
        confirm_pin = self.confirm_pin_entry.get()
        captcha_response = self.captcha_entry.get().strip()
        
        # Validate all fields
        if not all([username, email, password, confirm_password, security_question, 
                   security_answer, pin, confirm_pin, captcha_response]):
            self.status_label.config(text="All fields are required", fg='red')
            return
        
        # Validate username
        if len(username) < 7:
            self.status_label.config(text="Username must be at least 7 characters", fg='red')
            return
        
        # Validate email
        if not validate_email(email):
            self.status_label.config(text="Invalid email address", fg='red')
            return
        
        # Check if username or email already exists
        users_db = self.controller.users_db
        for user in users_db.values():
            if user['username'].lower() == username.lower():
                self.status_label.config(text="Username already exists", fg='red')
                return
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
        
        # Validate security answer
        if len(security_answer) < 3:
            self.status_label.config(text="Security answer must be at least 3 characters", fg='red')
            return
        
        # Validate PIN
        if not validate_pin(pin):
            self.status_label.config(text="PIN must be 6 digits", fg='red')
            return
            
        if pin != confirm_pin:
            self.status_label.config(text="PINs don't match", fg='red')
            return
        
        # Validate CAPTCHA
        try:
            if int(captcha_response) != self.captcha_answer:
                self.captcha_attempts += 1
                if self.captcha_attempts >= 3:
                    self.captcha_locked = True
                    self.status_label.config(text="Too many failed attempts. Please try again later.", fg='red')
                    self.after(30000, self.reset_captcha_lock)  # 30 second lockout
                else:
                    self.status_label.config(text="Incorrect CAPTCHA answer", fg='red')
                    self.generate_captcha()
                return
        except ValueError:
            self.status_label.config(text="Please enter a valid number for CAPTCHA", fg='red')
            return
        
        # Create new user
        new_user = {
            'username': username,
            'email': email,
            'password': hash_password(password),
            'security_question': security_question,
            'security_answer': security_answer,
            'pin': pin,
            'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'last_login': None
        }
        
        # Save user to database
        self.controller.users_db[username] = new_user
        save_users(self.controller.users_db)
        
        # Show success message and redirect to login
        self.status_label.config(text="Account created successfully! Redirecting to login...", fg='green')
        
        # Clear form and switch to login after 2 seconds
        self.after(2000, lambda: [
            self.username_entry.delete(0, tk.END),
            self.email_entry.delete(0, tk.END),
            self.password_entry.delete(0, tk.END),
            self.confirm_password_entry.delete(0, tk.END),
            self.security_question.set(''),
            self.security_answer_entry.delete(0, tk.END),
            self.pin_entry.delete(0, tk.END),
            self.confirm_pin_entry.delete(0, tk.END),
            self.captcha_entry.delete(0, tk.END),
            self.password_strength.config(text=""),
            self.controller.show_frame(SignInPage)
        ])
    
    def reset_captcha_lock(self):
        self.captcha_locked = False
        self.captcha_attempts = 0
        self.generate_captcha()
        self.status_label.config(text="You can now try again", fg='green')

class ForgotPasswordPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(bg='#e0f0ff')
        self.font_conf = ('Arial', 12)
        
        # Center container
        center_frame = tk.Frame(self, bg='#e0f0ff')
        center_frame.place(relx=0.5, rely=0.5, anchor='center')
        
        # Logo (scaled to small size)
        try:
            logo_img = tk.PhotoImage(file="images/logo.png")
            logo_img = logo_img.subsample(4, 4)  # Scale down more
            logo_label = tk.Label(center_frame, image=logo_img, bg='#e0f0ff')
            logo_label.image = logo_img
            logo_label.pack(pady=10)
        except:
            tk.Label(center_frame, text="🔒 PassShield", font=('Arial', 20, 'bold'), 
                    bg='#e0f0ff', fg='black').pack(pady=10)
        
        tk.Label(center_frame, text="Password Recovery", font=('Arial', 16, 'bold'), 
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
        
        tk.Button(button_frame, text="Back to Login", 
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
        security_answer = simpledialog.askstring("Security Question", 
                                               f"{security_question}\nAnswer:", 
                                               show='*')
        
        if not security_answer or security_answer.lower() != user['security_answer'].lower():
            self.status_label.config(text="Incorrect security answer", fg='red')
            return
        
        # Generate temporary password
        temp_password = generate_strong_password(12)
        
        # Update user's password (in memory only, not saved)
        self.status_label.config(text=f"Your temporary password is: {temp_password}\n"
                                    "Please change it immediately after login.", 
                                    fg='green')
        
        # Clear the identifier field
        self.identifier_entry.delete(0, tk.END)

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
        header_frame = tk.Frame(self, bg='#e0f0ff', padx=10, pady=10)
        header_frame.pack(fill='x')
        
        try:
            logo_img = tk.PhotoImage(file="images/logo_small.png")
            logo_label = tk.Label(header_frame, image=logo_img, bg='#e0f0ff')
            logo_label.image = logo_img
            logo_label.pack(side='left', padx=10)
        except:
            tk.Label(header_frame, text="🔒", font=('Arial', 20), 
                    bg='#e0f0ff', fg='black').pack(side='left', padx=10)
        
        tk.Label(header_frame, text="Password Storage", font=('Arial', 16, 'bold'), 
                bg='#e0f0ff', fg='black').pack(side='left', padx=10)
        
        # Search and Add Frame
        search_add_frame = tk.Frame(self, bg='#e0f0ff', padx=10, pady=5)
        search_add_frame.pack(fill='x')
        
        # Search Entry
        search_frame = tk.Frame(search_add_frame, bg='#e0f0ff')
        search_frame.pack(side='left', fill='x', expand=True)
        
        tk.Label(search_frame, text="Search:", font=self.font_conf, 
                bg='#e0f0ff', fg='black').pack(side='left', padx=5)
        
        self.search_entry = tk.Entry(search_frame, textvariable=self.search_var,
                                   font=self.font_conf, relief='solid', 
                                   highlightthickness=0, bd=1, bg='white', 
                                   fg='black', insertbackground='black', 
                                   insertwidth=2, width=30)
        self.search_entry.pack(side='left', fill='x', expand=True, padx=5, ipady=3)
        
        # Add Password Button
        tk.Button(search_add_frame, text="+ Add Password", command=self.add_password,
                 font=self.font_conf, bg='#4CAF50', fg='black', relief='solid', 
                 bd=1, padx=10, pady=5, cursor='hand2').pack(side='right', padx=5)
        
        # Main Content Frame
        content_frame = tk.Frame(self, bg='#e0f0ff')
        content_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Password List Frame
        list_frame = tk.Frame(content_frame, bg='#f0f0f0', bd=1, relief='solid')
        list_frame.pack(side='left', fill='y', padx=(0, 5))
        
        # Treeview for password list
        self.tree = ttk.Treeview(list_frame, columns=('title', 'username'), 
                               show='headings', selectmode='browse')
        self.tree.heading('title', text='Title')
        self.tree.heading('username', text='Username/Email')
        self.tree.column('title', width=150)
        self.tree.column('username', width=150)
        
        vsb = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(list_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)
        
        self.tree.bind('<<TreeviewSelect>>', self.on_item_select)
        
        # Password Detail Frame
        detail_frame = tk.Frame(content_frame, bg='#f0f0f0', bd=1, relief='solid')
        detail_frame.pack(side='left', fill='both', expand=True)
        
        # Detail fields
        tk.Label(detail_frame, text="Password Details", font=('Arial', 14, 'bold'), 
                bg='#f0f0f0', fg='black').pack(pady=10)
        
        # Title
        tk.Label(detail_frame, text="Title:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w', padx=10, pady=(5, 0))
        self.title_entry = tk.Entry(detail_frame, font=self.font_conf, 
                                  relief='solid', highlightthickness=0,
                                  bd=1, bg='white', fg='black', 
                                  insertbackground='black', insertwidth=2)
        self.title_entry.pack(fill='x', padx=10, pady=(0, 5), ipady=3)
        
        # Username/Email
        tk.Label(detail_frame, text="Username/Email:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w', padx=10, pady=(5, 0))
        self.username_entry = tk.Entry(detail_frame, font=self.font_conf, 
                                     relief='solid', highlightthickness=0,
                                     bd=1, bg='white', fg='black', 
                                     insertbackground='black', insertwidth=2)
        self.username_entry.pack(fill='x', padx=10, pady=(0, 5), ipady=3)
        
        # Password
        tk.Label(detail_frame, text="Password:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w', padx=10, pady=(5, 0))
        
        password_frame = tk.Frame(detail_frame, bg='#f0f0f0')
        password_frame.pack(fill='x', padx=10, pady=(0, 5))
        
        self.password_entry = tk.Entry(password_frame, font=self.font_conf, show="•", 
                                     relief='solid', highlightthickness=0, bd=1, 
                                     bg='white', fg='black', insertbackground='black', 
                                     insertwidth=2)
        self.password_entry.pack(side='left', fill='x', expand=True, ipady=3)
        
        self.toggle_pass_btn = tk.Button(password_frame, text="Show", command=self.toggle_password, 
                                       bg='#e0f0ff', fg='black', relief='solid', bd=1,
                                       font=self.font_conf, padx=10, cursor='hand2')
        self.toggle_pass_btn.pack(side='left', padx=5)
        
        self.copy_pass_btn = tk.Button(password_frame, text="Copy", command=self.copy_password, 
                                     bg='#e0f0ff', fg='black', relief='solid', bd=1,
                                     font=self.font_conf, padx=10, cursor='hand2')
        self.copy_pass_btn.pack(side='left', padx=5)
        
        self.generate_pass_btn = tk.Button(password_frame, text="Generate", command=self.generate_password, 
                                         bg='#e0f0ff', fg='black', relief='solid', bd=1,
                                         font=self.font_conf, padx=10, cursor='hand2')
        self.generate_pass_btn.pack(side='left', padx=5)
        
        # URL
        tk.Label(detail_frame, text="URL:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w', padx=10, pady=(5, 0))
        self.url_entry = tk.Entry(detail_frame, font=self.font_conf, 
                                 relief='solid', highlightthickness=0,
                                 bd=1, bg='white', fg='black', 
                                 insertbackground='black', insertwidth=2)
        self.url_entry.pack(fill='x', padx=10, pady=(0, 5), ipady=3)
        
        # Notes
        tk.Label(detail_frame, text="Notes:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w', padx=10, pady=(5, 0))
        self.notes_text = tk.Text(detail_frame, font=self.font_conf, 
                                 relief='solid', highlightthickness=0,
                                 bd=1, bg='white', fg='black', 
                                 insertbackground='black', insertwidth=2,
                                 height=5)
        self.notes_text.pack(fill='x', padx=10, pady=(0, 5))
        
        # Button Frame
        button_frame = tk.Frame(detail_frame, bg='#f0f0f0', pady=10)
        button_frame.pack(fill='x')
        
        tk.Button(button_frame, text="Save", command=self.save_password,
                 font=self.font_conf, bg='#4CAF50', fg='black', relief='solid', 
                 bd=1, padx=20, pady=5, cursor='hand2').pack(side='left', padx=5)
        
        tk.Button(button_frame, text="Delete", command=self.delete_password,
                 font=self.font_conf, bg='#f44336', fg='black', relief='solid', 
                 bd=1, padx=20, pady=5, cursor='hand2').pack(side='left', padx=5)
        
        tk.Button(button_frame, text="Clear", command=self.clear_fields,
                 font=self.font_conf, bg='#e0f0ff', fg='black', relief='solid', 
                 bd=1, padx=20, pady=5, cursor='hand2').pack(side='left', padx=5)
        
        # Bottom Navigation Frame
        nav_frame = tk.Frame(self, bg='#e0f0ff', padx=10, pady=10)
        nav_frame.pack(fill='x', side='bottom')
        
        tk.Button(nav_frame, text="Settings", command=lambda: controller.show_frame(SettingsPage),
                 font=self.font_conf, bg='#e0f0ff', fg='black', relief='solid', 
                 bd=1, padx=20, pady=5, cursor='hand2').pack(side='left', padx=5)
        
        tk.Button(nav_frame, text="Guide", command=lambda: controller.show_frame(GuidePage),
                 font=self.font_conf, bg='#e0f0ff', fg='black', relief='solid', 
                 bd=1, padx=20, pady=5, cursor='hand2').pack(side='left', padx=5)
        
        tk.Button(nav_frame, text="Logout", command=self.logout,
                 font=self.font_conf, bg='#e0f0ff', fg='black', relief='solid', 
                 bd=1, padx=20, pady=5, cursor='hand2').pack(side='right', padx=5)
        
        # Status label
        self.status_label = tk.Label(self, text="", font=self.font_conf, 
                                    bg='#e0f0ff', fg='red')
        self.status_label.pack(side='bottom', pady=5)
        
        # Initialize password list
        self.load_passwords()
    
    def on_show(self):
        self.load_passwords()
        self.clear_fields()
        self.controller.reset_auto_lock()
    
    def load_passwords(self):
        # Clear current items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Load passwords for current user
        if self.controller.current_user in self.controller.password_db:
            passwords = self.controller.password_db[self.controller.current_user]
            for pwd_id, pwd_data in passwords.items():
                self.tree.insert('', 'end', iid=pwd_id, 
                               values=(pwd_data['title'], pwd_data['username']))
    
    def filter_passwords(self, *args):
        search_term = self.search_var.get().lower()
        
        # Show all items if search is empty
        if not search_term:
            for item in self.tree.get_children():
                self.tree.item(item, tags=('',))
                self.tree.detach(item)
                self.tree.move(item, '', 'end')
            return
        
        # Filter items
        for item in self.tree.get_children():
            values = self.tree.item(item, 'values')
            if any(search_term in str(value).lower() for value in values):
                self.tree.item(item, tags=('',))
                self.tree.detach(item)
                self.tree.move(item, '', 'end')
            else:
                self.tree.detach(item)
    
    def on_item_select(self, event):
        selected = self.tree.selection()
        if not selected:
            return
            
        self.selected_item = selected[0]
        pwd_data = self.controller.password_db[self.controller.current_user][self.selected_item]
        
        # Update fields with selected password data
        self.title_entry.delete(0, tk.END)
        self.title_entry.insert(0, pwd_data['title'])
        
        self.username_entry.delete(0, tk.END)
        self.username_entry.insert(0, pwd_data['username'])
        
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, pwd_data['password'])
        self.password_entry.config(show="•")
        self.toggle_pass_btn.config(text="Show")
        
        self.url_entry.delete(0, tk.END)
        self.url_entry.insert(0, pwd_data.get('url', ''))
        
        self.notes_text.delete(1.0, tk.END)
        self.notes_text.insert(1.0, pwd_data.get('notes', ''))
    
    def toggle_password(self):
        current_show = self.password_entry.cget('show')
        if current_show == "•":
            self.password_entry.config(show="")
            self.toggle_pass_btn.config(text="Hide")
        else:
            self.password_entry.config(show="•")
            self.toggle_pass_btn.config(text="Show")
    
    def copy_password(self):
        password = self.password_entry.get()
        if password:
            pyperclip.copy(password)
            self.status_label.config(text="Password copied to clipboard", fg='green')
            
            # Clear clipboard after timeout
            timeout = self.controller.settings.get('clipboard_clear', 30)
            self.after(timeout * 1000, lambda: pyperclip.copy(''))
    
    def generate_password(self):
        length = self.controller.settings.get('default_length', 16)
        password = generate_strong_password(length)
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        self.password_entry.config(show="")
        self.toggle_pass_btn.config(text="Hide")
        self.status_label.config(text="Strong password generated", fg='green')
    
    def clear_fields(self):
        self.title_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.password_entry.config(show="•")
        self.toggle_pass_btn.config(text="Show")
        self.url_entry.delete(0, tk.END)
        self.notes_text.delete(1.0, tk.END)
        self.selected_item = None
        self.tree.selection_remove(self.tree.selection())
        self.status_label.config(text="")
    
    def add_password(self):
        self.clear_fields()
        self.title_entry.focus_set()
    
    def save_password(self):
        # Get all field values
        title = self.title_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        url = self.url_entry.get().strip()
        notes = self.notes_text.get(1.0, tk.END).strip()
        
        # Validate required fields
        if not title or not username or not password:
            self.status_label.config(text="Title, username and password are required", fg='red')
            return
        
        # Create password data
        pwd_data = {
            'title': title,
            'username': username,
            'password': password,
            'url': url,
            'notes': notes,
            'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'updated_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Initialize user's password storage if not exists
        if self.controller.current_user not in self.controller.password_db:
            self.controller.password_db[self.controller.current_user] = {}
        
        # Add or update password
        if self.selected_item:
            # Update existing password
            self.controller.password_db[self.controller.current_user][self.selected_item] = pwd_data
            self.status_label.config(text="Password updated successfully", fg='green')
        else:
            # Add new password
            pwd_id = str(int(time.time() * 1000))  # Unique ID based on timestamp
            self.controller.password_db[self.controller.current_user][pwd_id] = pwd_data
            self.tree.insert('', 'end', iid=pwd_id, values=(title, username))
            self.status_label.config(text="Password added successfully", fg='green')
            self.selected_item = pwd_id
        
        # Save to database
        save_db(self.controller.password_db)
        
        # Clear selection and fields after 2 seconds
        self.after(2000, self.clear_fields)
    
    def delete_password(self):
        if not self.selected_item:
            self.status_label.config(text="No password selected", fg='red')
            return
            
        # Confirm deletion
        if not messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this password?"):
            return
        
        # Delete from database
        del self.controller.password_db[self.controller.current_user][self.selected_item]
        save_db(self.controller.password_db)
        
        # Remove from treeview
        self.tree.delete(self.selected_item)
        
        self.status_label.config(text="Password deleted successfully", fg='green')
        self.clear_fields()
    
    def logout(self):
        self.controller.current_user = None
        self.controller.show_frame(SignInPage)

class SettingsPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(bg='#e0f0ff')
        self.font_conf = ('Arial', 12)
        
        # Header Frame
        header_frame = tk.Frame(self, bg='#e0f0ff', padx=10, pady=10)
        header_frame.pack(fill='x')
        
        try:
            logo_img = tk.PhotoImage(file="images/logo_small.png")
            logo_label = tk.Label(header_frame, image=logo_img, bg='#e0f0ff')
            logo_label.image = logo_img
            logo_label.pack(side='left', padx=10)
        except:
            tk.Label(header_frame, text="🔒", font=('Arial', 20), 
                    bg='#e0f0ff', fg='black').pack(side='left', padx=10)
        
        tk.Label(header_frame, text="Settings", font=('Arial', 16, 'bold'), 
                bg='#e0f0ff', fg='black').pack(side='left', padx=10)
        
        # Main Content Frame
        content_frame = tk.Frame(self, bg='#e0f0ff', padx=20, pady=20)
        content_frame.pack(fill='both', expand=True)
        
        # Settings Form
        form_frame = tk.Frame(content_frame, bg='#f0f0f0', padx=20, pady=20, bd=1, relief='solid')
        form_frame.pack(fill='both', expand=True)
        
        # Auto-lock timeout
        tk.Label(form_frame, text="Auto-lock after (minutes):", font=self.font_conf, 
                bg='#f0f0f0', fg='black').grid(row=0, column=0, sticky='w', pady=5)
        
        self.auto_lock_var = tk.StringVar(value=str(self.controller.settings.get('auto_lock', 15)))
        self.auto_lock_entry = tk.Entry(form_frame, textvariable=self.auto_lock_var,
                                      font=self.font_conf, relief='solid', 
                                      highlightthickness=0, bd=1, bg='white', 
                                      fg='black', insertbackground='black', 
                                      insertwidth=2, width=5)
        self.auto_lock_entry.grid(row=0, column=1, sticky='w', pady=5, padx=5)
        
        # Clipboard clear timeout
        tk.Label(form_frame, text="Clear clipboard after (seconds):", font=self.font_conf, 
                bg='#f0f0f0', fg='black').grid(row=1, column=0, sticky='w', pady=5)
        
        self.clipboard_var = tk.StringVar(value=str(self.controller.settings.get('clipboard_clear', 30)))
        self.clipboard_entry = tk.Entry(form_frame, textvariable=self.clipboard_var,
                                      font=self.font_conf, relief='solid', 
                                      highlightthickness=0, bd=1, bg='white', 
                                      fg='black', insertbackground='black', 
                                      insertwidth=2, width=5)
        self.clipboard_entry.grid(row=1, column=1, sticky='w', pady=5, padx=5)
        
        # Default password length
        tk.Label(form_frame, text="Default password length:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').grid(row=2, column=0, sticky='w', pady=5)
        
        self.length_var = tk.StringVar(value=str(self.controller.settings.get('default_length', 16)))
        self.length_entry = tk.Entry(form_frame, textvariable=self.length_var,
                                   font=self.font_conf, relief='solid', 
                                                                      highlightthickness=0, bd=1, bg='white', 
                                   fg='black', insertbackground='black', 
                                   insertwidth=2, width=5)
        self.length_entry.grid(row=2, column=1, sticky='w', pady=5, padx=5)
        
        # Theme selection
        tk.Label(form_frame, text="Theme:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').grid(row=3, column=0, sticky='w', pady=5)
        
        self.theme_var = tk.StringVar(value=self.controller.settings.get('theme', 'light'))
        theme_options = ['light', 'dark']
        self.theme_menu = tk.OptionMenu(form_frame, self.theme_var, *theme_options)
        self.theme_menu.config(font=self.font_conf, bg='white', fg='black', 
                             relief='solid', bd=1, highlightthickness=0)
        self.theme_menu.grid(row=3, column=1, sticky='w', pady=5, padx=5)
        
        # Button Frame
        button_frame = tk.Frame(form_frame, bg='#f0f0f0', pady=20)
        button_frame.grid(row=4, column=0, columnspan=2, sticky='ew')
        
        tk.Button(button_frame, text="Save Settings", command=self.save_settings,
                 font=self.font_conf, bg='#4CAF50', fg='black', relief='solid', 
                 bd=1, padx=20, pady=5, cursor='hand2').pack(side='left', padx=5)
        
        tk.Button(button_frame, text="Reset to Defaults", command=self.reset_settings,
                 font=self.font_conf, bg='#e0f0ff', fg='black', relief='solid', 
                 bd=1, padx=20, pady=5, cursor='hand2').pack(side='left', padx=5)
        
        # Change Password Frame
        change_pass_frame = tk.Frame(content_frame, bg='#f0f0f0', padx=20, pady=20, bd=1, relief='solid')
        change_pass_frame.pack(fill='x', pady=(10, 0))
        
        tk.Label(change_pass_frame, text="Change Master Password", font=('Arial', 14, 'bold'), 
                bg='#f0f0f0', fg='black').pack(anchor='w', pady=(0, 10))
        
        # Current Password
        tk.Label(change_pass_frame, text="Current Password:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w', pady=(0, 5))
        
        self.current_pass_entry = tk.Entry(change_pass_frame, font=self.font_conf, show="•",
                                         relief='solid', highlightthickness=0, bd=1, 
                                         bg='white', fg='black', insertbackground='black', 
                                         insertwidth=2)
        self.current_pass_entry.pack(fill='x', pady=(0, 10), ipady=3)
        
        # New Password
        tk.Label(change_pass_frame, text="New Password:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w', pady=(0, 5))
        
        self.new_pass_entry = tk.Entry(change_pass_frame, font=self.font_conf, show="•",
                                    relief='solid', highlightthickness=0, bd=1, 
                                    bg='white', fg='black', insertbackground='black', 
                                    insertwidth=2)
        self.new_pass_entry.pack(fill='x', pady=(0, 10), ipady=3)
        
        # Confirm New Password
        tk.Label(change_pass_frame, text="Confirm New Password:", font=self.font_conf, 
                bg='#f0f0f0', fg='black').pack(anchor='w', pady=(0, 5))
        
        self.confirm_new_pass_entry = tk.Entry(change_pass_frame, font=self.font_conf, show="•",
                                             relief='solid', highlightthickness=0, bd=1, 
                                             bg='white', fg='black', insertbackground='black', 
                                             insertwidth=2)
        self.confirm_new_pass_entry.pack(fill='x', pady=(0, 10), ipady=3)
        
        # Change Password Button
        tk.Button(change_pass_frame, text="Change Password", command=self.change_password,
                 font=self.font_conf, bg='#4CAF50', fg='black', relief='solid', 
                 bd=1, padx=20, pady=5, cursor='hand2').pack(pady=10)
        
        # Status label
        self.status_label = tk.Label(content_frame, text="", font=self.font_conf, 
                                    bg='#e0f0ff', fg='red')
        self.status_label.pack(pady=5)
        
        # Bottom Navigation Frame
        nav_frame = tk.Frame(self, bg='#e0f0ff', padx=10, pady=10)
        nav_frame.pack(fill='x', side='bottom')
        
        tk.Button(nav_frame, text="Back to Passwords", command=lambda: controller.show_frame(StoragePage),
                 font=self.font_conf, bg='#e0f0ff', fg='black', relief='solid', 
                 bd=1, padx=20, pady=5, cursor='hand2').pack(side='left', padx=5)
        
        tk.Button(nav_frame, text="Guide", command=lambda: controller.show_frame(GuidePage),
                 font=self.font_conf, bg='#e0f0ff', fg='black', relief='solid', 
                 bd=1, padx=20, pady=5, cursor='hand2').pack(side='left', padx=5)
        
        tk.Button(nav_frame, text="Logout", command=self.logout,
                 font=self.font_conf, bg='#e0f0ff', fg='black', relief='solid', 
                 bd=1, padx=20, pady=5, cursor='hand2').pack(side='right', padx=5)
    
    def save_settings(self):
        try:
            auto_lock = int(self.auto_lock_var.get())
            clipboard_clear = int(self.clipboard_var.get())
            default_length = int(self.length_var.get())
            theme = self.theme_var.get()
            
            if auto_lock < 1 or clipboard_clear < 1 or default_length < 8:
                raise ValueError("Values must be positive integers")
                
            self.controller.settings = {
                'auto_lock': auto_lock,
                'clipboard_clear': clipboard_clear,
                'default_length': default_length,
                'theme': theme
            }
            
            save_settings(self.controller.settings)
            self.status_label.config(text="Settings saved successfully", fg='green')
            
            # Apply theme changes
            if theme == 'dark':
                self.controller.apply_dark_theme()
            else:
                self.controller.apply_light_theme()
                
        except ValueError as e:
            self.status_label.config(text=f"Invalid settings: {str(e)}", fg='red')
    
    def reset_settings(self):
        default_settings = {
            'auto_lock': 15,
            'clipboard_clear': 30,
            'default_length': 16,
            'theme': 'light'
        }
        
        self.auto_lock_var.set(str(default_settings['auto_lock']))
        self.clipboard_var.set(str(default_settings['clipboard_clear']))
        self.length_var.set(str(default_settings['default_length']))
        self.theme_var.set(default_settings['theme'])
        
        self.status_label.config(text="Settings reset to defaults", fg='green')
    
    def change_password(self):
        current_pass = self.current_pass_entry.get()
        new_pass = self.new_pass_entry.get()
        confirm_new_pass = self.confirm_new_pass_entry.get()
        
        # Validate inputs
        if not current_pass or not new_pass or not confirm_new_pass:
            self.status_label.config(text="All fields are required", fg='red')
            return
            
        if new_pass != confirm_new_pass:
            self.status_label.config(text="New passwords don't match", fg='red')
            return
            
        if len(new_pass) < 15:
            self.status_label.config(text="New password must be at least 15 characters", fg='red')
            return
            
        # Verify current password
        user_data = self.controller.users_db[self.controller.current_user]
        if not verify_password(current_pass, user_data['password']):
            self.status_label.config(text="Current password is incorrect", fg='red')
            return
            
        # Update password
        user_data['password'] = hash_password(new_pass)
        save_users(self.controller.users_db)
        
        self.status_label.config(text="Password changed successfully", fg='green')
        
        # Clear fields
        self.current_pass_entry.delete(0, tk.END)
        self.new_pass_entry.delete(0, tk.END)
        self.confirm_new_pass_entry.delete(0, tk.END)
    
    def logout(self):
        self.controller.current_user = None
        self.controller.show_frame(SignInPage)

class GuidePage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(bg='#e0f0ff')
        self.font_conf = ('Arial', 12)
        
        # Header Frame
        header_frame = tk.Frame(self, bg='#e0f0ff', padx=10, pady=10)
        header_frame.pack(fill='x')
        
        try:
            logo_img = tk.PhotoImage(file="images/logo_small.png")
            logo_label = tk.Label(header_frame, image=logo_img, bg='#e0f0ff')
            logo_label.image = logo_img
            logo_label.pack(side='left', padx=10)
        except:
            tk.Label(header_frame, text="🔒", font=('Arial', 20), 
                    bg='#e0f0ff', fg='black').pack(side='left', padx=10)
        
        tk.Label(header_frame, text="User Guide", font=('Arial', 16, 'bold'), 
                bg='#e0f0ff', fg='black').pack(side='left', padx=10)
        
        # Main Content Frame
        content_frame = tk.Frame(self, bg='#e0f0ff', padx=20, pady=20)
        content_frame.pack(fill='both', expand=True)
        
        # Text widget for guide content
        guide_text = tk.Text(content_frame, font=self.font_conf, wrap='word',
                            relief='flat', highlightthickness=0, bd=0,
                            bg="#427ce8", fg='black', padx=10, pady=10)
        guide_text.pack(fill='both', expand=True)
        
        # Insert guide content
        guide_content = """
        PassShield - Password Manager User Guide
        
        1. Getting Started
        - Sign up for a new account with a strong master password
        - Store your passwords securely in the encrypted database
        - Access your passwords from any device with your credentials
        
        2. Password Storage
        - Add new passwords by clicking the "+ Add Password" button
        - Edit existing passwords by selecting them from the list
        - Generate strong passwords using the built-in generator
        - Copy passwords to clipboard (automatically clears after timeout)
        
        3. Security Features
        - Auto-lock after period of inactivity
        - Two-factor authentication with security questions
        - Encrypted password storage
        - Clipboard clearing after use
        
        4. Best Practices
        - Use a unique master password that you don't use elsewhere
        - Enable auto-lock for added security
        - Regularly update your stored passwords
        - Never share your master password
        
        5. Troubleshooting
        - Forgot password: Use the security question recovery
        - Locked out: Contact support for account recovery
        - Technical issues: Restart the application
        
        For additional help, please contact support@passshield.com
        """
        
        guide_text.insert('1.0', guide_content)
        guide_text.config(state='disabled')  # Make it read-only
        
        # Bottom Navigation Frame
        nav_frame = tk.Frame(self, bg='#e0f0ff', padx=10, pady=10)
        nav_frame.pack(fill='x', side='bottom')
        
        tk.Button(nav_frame, text="Back to Passwords", command=lambda: controller.show_frame(StoragePage),
                 font=self.font_conf, bg='#e0f0ff', fg='black', relief='solid', 
                 bd=1, padx=20, pady=5, cursor='hand2').pack(side='left', padx=5)
        
        tk.Button(nav_frame, text="Settings", command=lambda: controller.show_frame(SettingsPage),
                 font=self.font_conf, bg='#e0f0ff', fg='black', relief='solid', 
                 bd=1, padx=20, pady=5, cursor='hand2').pack(side='left', padx=5)
        
        tk.Button(nav_frame, text="Logout", command=self.logout,
                 font=self.font_conf, bg='#e0f0ff', fg='black', relief='solid', 
                 bd=1, padx=20, pady=5, cursor='hand2').pack(side='right', padx=5)
    
    def logout(self):
        self.controller.current_user = None
        self.controller.show_frame(SignInPage)

# Utility functions
def hash_password(password):
    """Hash a password using PBKDF2 with SHA256"""
    salt = b'salt_'  # In a real app, generate a unique salt per user
    iterations = 100000
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    return base64.b64encode(key).decode('utf-8')

def verify_password(password, hashed):
    """Verify a password against its hash"""
    new_hash = hash_password(password)
    return new_hash == hashed

def validate_email(email):
    """Simple email validation"""
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def validate_pin(pin):
    """Validate PIN is 6 digits"""
    return pin.isdigit() and len(pin) == 6

def check_password_strength(password):
    """Check password strength and return feedback"""
    if len(password) < 15:
        return "Weak: Password too short (min 15 chars)"
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    strength = 0
    if has_upper: strength += 1
    if has_lower: strength += 1
    if has_digit: strength += 1
    if has_special: strength += 1
    
    if strength == 4 and len(password) >= 20:
        return "Very Strong"
    elif strength >= 3:
        return "Strong"
    elif strength >= 2:
        return "Moderate"
    else:
        return "Weak: Add more character types"

def generate_strong_password(length=16):
    """Generate a strong random password"""
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    while True:
        password = ''.join(random.choice(chars) for _ in range(length))
        if (any(c.islower() for c in password) and 
            any(c.isupper() for c in password) and 
            any(c.isdigit() for c in password) and
            any(not c.isalnum() for c in password)):
            return password

def get_user_by_email_or_username(identifier, users_db):
    """Find user by username or email"""
    for user in users_db.values():
        if user['username'].lower() == identifier.lower():
            return user
        if user['email'].lower() == identifier.lower():
            return user
    return None

def save_users(users_db):
    """Save users database to file"""
    try:
        with open('users.json', 'w') as f:
            json.dump(users_db, f, indent=2)
    except Exception as e:
        print(f"Error saving users: {e}")

def load_users():
    """Load users database from file"""
    try:
        with open('users.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except Exception as e:
        print(f"Error loading users: {e}")
        return {}

def save_db(password_db):
    """Save password database to file"""
    try:
        with open('passwords.json', 'w') as f:
            json.dump(password_db, f, indent=2)
    except Exception as e:
        print(f"Error saving password database: {e}")

def load_db():
    """Load password database from file"""
    try:
        with open('passwords.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except Exception as e:
        print(f"Error loading password database: {e}")
        return {}

def save_settings(settings):
    """Save application settings to file"""
    try:
        with open('settings.json', 'w') as f:
            json.dump(settings, f, indent=2)
    except Exception as e:
        print(f"Error saving settings: {e}")

def load_settings():
    """Load application settings from file"""
    default_settings = {
        'auto_lock': 15,
        'clipboard_clear': 30,
        'default_length': 16,
        'theme': 'light'
    }
    
    try:
        with open('settings.json', 'r') as f:
            loaded = json.load(f)
            # Ensure all settings are present
            for key in default_settings:
                if key not in loaded:
                    loaded[key] = default_settings[key]
            return loaded
    except FileNotFoundError:
        return default_settings
    except Exception as e:
        print(f"Error loading settings: {e}")
        return default_settings

if __name__ == "__main__":
    app = PassShieldApp()
    app.mainloop()