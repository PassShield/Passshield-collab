import tkinter as tk
from tkinter import ttk, messagebox
from utils.validation import validate_email
from utils.encryption import verify_password
import json
import os
from screens.signup_screen import SignupScreen
from screens.forgot_password import ForgotPasswordScreen

class LoginScreen(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        
        self.configure(bg='#ffffff')
        self.style = ttk.Style()
        self.style.configure('TButton', background='#003366', foreground='white')
        self.style.configure('TEntry', padding=5, relief='flat', bordercolor='#cccccc')
        
        self.create_widgets()
        
    def create_widgets(self):
        # Main container with padding
        main_frame = ttk.Frame(self, padding="40 20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Form container with border
        form_frame = ttk.Frame(main_frame, borderwidth=2, relief='solid', padding="30 20")
        form_frame.pack(expand=True)
        form_frame.grid_columnconfigure(0, weight=1)
        
        # Title
        title_label = ttk.Label(form_frame, text="Sign In", font=('Arial', 18, 'bold'), foreground='#003366')
        title_label.grid(row=0, column=0, pady=(0, 20), sticky='n')
        
        # Username/Email
        ttk.Label(form_frame, text="Email/Username:", font=('Arial', 10)).grid(row=1, column=0, pady=(0, 5), sticky='w')
        self.username_entry = ttk.Entry(form_frame, width=25)
        self.username_entry.grid(row=2, column=0, sticky='ew', pady=(0, 15))
        
        # Password Frame
        password_frame = ttk.Frame(form_frame)
        password_frame.grid(row=4, column=0, sticky='ew', pady=(0, 10))
        
        # Password Label
        ttk.Label(form_frame, text="Password:", font=('Arial', 10)).grid(row=3, column=0, pady=(0, 5), sticky='w')
        
        # Password Entry
        self.password_entry = ttk.Entry(password_frame, show="•", width=25)
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Eye Toggle Button
        self.eye_button = ttk.Button(
            password_frame,
            text="👁",
            width=3,
            command=self.toggle_password_visibility
        )
        self.eye_button.pack(side=tk.RIGHT, padx=(5, 0))
        
        # Login Button
        login_btn = ttk.Button(
            form_frame,
            text="Sign In",
            style='TButton',
            command=self.authenticate
        )
        login_btn.grid(row=6, column=0, pady=(0, 15), sticky='ew')
        
        # Forgot Password Link
        forgot_link = ttk.Label(
            form_frame,
            text="Forgot Password?",
            foreground='#003366',
            cursor='hand2',
            font=('Arial', 9)
        )
        forgot_link.bind('<Button-1>', lambda e: self.show_forgot_password())
        forgot_link.grid(row=7, column=0, pady=(0, 20))
        
        # Register Link
        register_link = ttk.Label(
            form_frame,
            text="Don't have an account? Register",
            foreground='#003366',
            cursor='hand2',
            font=('Arial', 9)
        )
        register_link.bind('<Button-1>', lambda e: self.show_register())
        register_link.grid(row=8, column=0, pady=(0, 10))
        
    def toggle_password_visibility(self):
        current_show = self.password_entry.cget('show')
        if current_show == "•":
            self.password_entry.config(show="")
            self.eye_button.config(text="🔒")
        else:
            self.password_entry.config(show="•")
            self.eye_button.config(text="👁")
        
    def authenticate(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
            
        # Check if user exists and password is correct
        user_data = self.load_user_data(username)
        if not user_data:
            messagebox.showerror("Error", "User not found")
            return
            
        # Check for both possible password field names
        password_hash = user_data.get('password_hash') or user_data.get('password')
        if not password_hash:
            messagebox.showerror("Error", "Invalid user data format")
            return
            
        if not verify_password(password, password_hash):
            messagebox.showerror("Error", "Invalid password")
            return
            
        # If we get here, authentication is successful
        self.app.show_dashboard(user_data)
        
    def load_user_data(self, username):
        try:
            # Check if users.json exists
            if not os.path.exists('users.json'):
                return None
                
            with open('users.json', 'r') as f:
                data = json.load(f)
                # Handle different JSON structures
                if isinstance(data, dict) and 'users' in data:
                    # Structure: {"users": [user1, user2...]}
                    users = data['users']
                elif isinstance(data, list):
                    # Structure: [user1, user2...]
                    users = data
                else:
                    return None
                
                for user in users:
                    if user.get('username') == username or user.get('email') == username:
                        return user
        except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
            print(f"Error loading user data: {e}")
            return None
        return None
        
    def show_forgot_password(self):
        self.app.switch_to_frame(ForgotPasswordScreen)
        
    def show_register(self):
        self.app.switch_to_frame(SignupScreen)