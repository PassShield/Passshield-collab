import tkinter as tk
from tkinter import ttk, messagebox
from utils.validation import validate_email
from utils.emailer import send_password_reset_email
import json
import os
import hashlib
import secrets
import string

class ForgotPasswordScreen(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.password_visible = False
        self.confirm_visible = False

        self.configure(bg='#f5f5f5')  # Light gray outer background
        self.style = ttk.Style()
        self.style.theme_use('clam')  # Use 'clam' for better visuals and rounded corners

        # Form styling
        self.style.configure('TFrame', background='white')
        self.style.configure('Outer.TFrame', background='#f5f5f5')
        self.style.configure('TLabel', background='white', foreground='#333', font=('Arial', 10))
        self.style.configure('Header.TLabel', font=('Arial', 24, 'bold'), foreground='#003366')
        self.style.configure('Title.TLabel', font=('Arial', 16, 'bold'), foreground='#333')
        self.style.configure('TEntry', fieldbackground='white', relief='flat', padding=5, font=('Arial', 10))
        self.style.map('TEntry', 
            focuscolor=[('focus', '#0078d7')],
            bordercolor=[('focus', '#0078d7')]
        )

        self.style.configure('Primary.TButton', font=('Arial', 10, 'bold'), background='#0078d7', foreground='white', padding=6)
        self.style.map('Primary.TButton', background=[('active', '#005fa3'), ('pressed', '#004e8a')])
        self.style.configure('Link.TButton', background='white', foreground='#0066cc', relief='flat')
        self.style.map('Link.TButton', foreground=[('active', '#004499'), ('pressed', '#003366')])

        self.create_widgets()

    def create_widgets(self):
        outer_frame = ttk.Frame(self, style='Outer.TFrame')
        outer_frame.pack(fill=tk.BOTH, expand=True)

        container = ttk.Frame(outer_frame, style='TFrame')
        container.place(relx=0.5, rely=0.5, anchor='center', width=500)

        ttk.Label(container, text="PassShield", style='Header.TLabel').pack(pady=(10, 10))
        ttk.Label(container, text="Forgot Password", style='Title.TLabel').pack(pady=(0, 20))

        form_frame = ttk.Frame(container, style='TFrame')
        form_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

        # Email/Username
        ttk.Label(form_frame, text="Email or Username:").grid(row=0, column=0, sticky='w', pady=(0, 5))
        self.email_user_entry = ttk.Entry(form_frame, width=30)
        self.email_user_entry.grid(row=1, column=0, sticky='ew', pady=(0, 15))

        # New Password
        ttk.Label(form_frame, text="New Password:").grid(row=2, column=0, sticky='w', pady=(0, 5))
        pass_frame = ttk.Frame(form_frame, style='TFrame')
        pass_frame.grid(row=3, column=0, sticky='ew', pady=(0, 15))
        self.password_entry = ttk.Entry(pass_frame, width=25, show='•')
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.toggle_pass_btn = ttk.Button(pass_frame, text="👁", width=3, command=self.toggle_password)
        self.toggle_pass_btn.pack(side=tk.RIGHT, padx=(5, 0))

        # Confirm Password
        ttk.Label(form_frame, text="Confirm Password:").grid(row=4, column=0, sticky='w', pady=(0, 5))
        confirm_frame = ttk.Frame(form_frame, style='TFrame')
        confirm_frame.grid(row=5, column=0, sticky='ew', pady=(0, 15))
        self.confirm_entry = ttk.Entry(confirm_frame, width=25, show='•')
        self.confirm_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.toggle_confirm_btn = ttk.Button(confirm_frame, text="👁", width=3, command=self.toggle_confirm)
        self.toggle_confirm_btn.pack(side=tk.RIGHT, padx=(5, 0))

        # Buttons
        submit_btn = ttk.Button(form_frame, text="Reset Password", style='Primary.TButton', command=self.reset_password)
        submit_btn.grid(row=6, column=0, sticky='ew', pady=(10, 10))

        back_login_btn = ttk.Button(form_frame, text="Back to Login", style='Link.TButton', command=self.go_back)
        back_login_btn.grid(row=7, column=0, sticky='ew')

        # Expand columns for responsiveness
        form_frame.columnconfigure(0, weight=1)

    def toggle_password(self):
        self.password_visible = not self.password_visible
        self.password_entry.config(show='' if self.password_visible else '•')
        self.toggle_pass_btn.config(text="👁")

    def toggle_confirm(self):
        self.confirm_visible = not self.confirm_visible
        self.confirm_entry.config(show='' if self.confirm_visible else '•')
        self.toggle_confirm_btn.config(text="👁")

    def validate_username(self, username):
        return len(username) >= 4

    def hash_password(self, password):
        """Hash a password for storing."""
        return hashlib.sha256(password.encode()).hexdigest()

    def generate_reset_token(self, length=32):
        """Generate a secure random token for password reset."""
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def reset_password(self):
        email_or_user = self.email_user_entry.get().strip()
        new_password = self.password_entry.get()
        confirm_password = self.confirm_entry.get()

        if not email_or_user:
            messagebox.showerror("Error", "Please enter your email or username")
            return

        # First try to find user by email or username
        user = self.find_user(email_or_user)
        if not user:
            messagebox.showerror("Error", "No account found with that email/username")
            return

        # Now validate the new password
        if not new_password:
            messagebox.showerror("Error", "Please enter a new password")
            return

        if len(new_password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters")
            return

        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return

        try:
            # Generate a reset token
            reset_token = self.generate_reset_token()
            
            # Hash the new password before storing
            hashed_password = self.hash_password(new_password)
            self.update_password(user['email'], hashed_password, reset_token)
            
            # Send confirmation email with the reset token
            send_password_reset_email(user['email'], user['username'], reset_token)
            
            messagebox.showinfo("Success", "Password has been reset successfully. A confirmation email has been sent.")
            self.go_back()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to reset password: {str(e)}")

    def find_user(self, email_or_user):
        try:
            # Create storage directory if it doesn't exist
            os.makedirs('storage', exist_ok=True)
            
            # Initialize database with empty users list if file doesn't exist
            if not os.path.exists('users.json'):
                with open('users.json', 'w') as f:
                    json.dump([], f)
            
            with open('users.json', 'r') as f:
                users = json.load(f)
                if not isinstance(users, list):
                    # If the file is corrupted and doesn't contain a list
                    users = []
                
                for user in users:
                    if not isinstance(user, dict):
                        continue
                    # Check both email and username (case-insensitive)
                    if ('email' in user and user['email'].lower() == email_or_user.lower()) or \
                       ('username' in user and user['username'].lower() == email_or_user.lower()):
                        return user
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error reading database: {e}")
            return None
        except Exception as e:
            print(f"Unexpected error: {e}")
            return None
        return None

    def update_password(self, email, new_password, reset_token):
        try:
            with open('users.json', 'r') as f:
                users = json.load(f)
                if not isinstance(users, list):
                    users = []
                
                updated = False
                for i, user in enumerate(users):
                    if isinstance(user, dict) and 'email' in user and user['email'].lower() == email.lower():
                        users[i]['password'] = new_password
                        users[i]['reset_token'] = reset_token  # Store the reset token
                        updated = True
                        break
                
            if updated:
                with open('users.json', 'w') as f:
                    json.dump(users, f, indent=4)
            else:
                raise Exception("User not found in database")
        except Exception as e:
            raise Exception(f"Database error: {str(e)}")

    def go_back(self):
        from screens.login_screen import LoginScreen
        # Clear the current screen first
        for widget in self.master.winfo_children():
            widget.destroy()
        # Create and show the login screen
        login_screen = LoginScreen(self.master, self.app)
        login_screen.pack(fill=tk.BOTH, expand=True)