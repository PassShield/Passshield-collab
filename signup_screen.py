import tkinter as tk
from tkinter import messagebox, ttk
from utils.encryption import hash_password, hash_pin
from utils.emailer import send_welcome_email
import json
import os
import re
import time
import random
import string

class SignupScreen(tk.Frame):
    def __init__(self, parent, app, login_screen_class):
        super().__init__(parent)
        self.app = app
        self.login_screen_class = login_screen_class  # Store the login screen class
        self.configure(bg='white')
        self.captcha_attempts = 0
        self.last_captcha_attempt_time = 0
        self.captcha_text, self.captcha_answer = self.generate_new_captcha()
        self.create_widgets()

    def generate_new_captcha(self):
        """Generate a simple math CAPTCHA"""
        num1 = random.randint(1, 10)
        num2 = random.randint(1, 10)
        operator = random.choice(['+', '-', '*'])
        
        if operator == '+':
            answer = num1 + num2
        elif operator == '-':
            answer = num1 - num2
        else:
            answer = num1 * num2
            
        captcha_text = f"{num1} {operator} {num2} = ?"
        return captcha_text, str(answer)

    def validate_pin(self, pin):
        """Validate that PIN is 6 digits"""
        return pin.isdigit() and len(pin) == 6

    def create_widgets(self):
        # Main container using grid
        main_container = tk.Frame(self, bg='white')
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Center frame using grid
        center_frame = tk.Frame(main_container, bg='white')
        center_frame.place(relx=0.5, rely=0.5, anchor='center')

        # Form container with border
        form_container = tk.Frame(center_frame, bg='white', bd=2, relief='solid',
                                 highlightbackground='black', highlightthickness=1)
        form_container.pack(padx=20, pady=10)

        # Form frame with all elements using grid
        form_frame = tk.Frame(form_container, bg='white', padx=30, pady=30)
        form_frame.pack()

        # Title
        tk.Label(form_frame, text="Sign Up", font=("Helvetica", 16, "bold"),
                bg='white', fg="#003366").grid(row=0, column=0, columnspan=2, pady=(0, 20), sticky='w')

        # Username
        tk.Label(form_frame, text="Username (min 7 chars):", bg='white').grid(row=1, column=0, sticky='w', pady=(0, 5))
        self.username_entry = tk.Entry(form_frame, bd=1, relief='solid', width=40)
        self.username_entry.grid(row=1, column=1, sticky='ew', pady=(0, 10), padx=(10, 0))

        # Email
        tk.Label(form_frame, text="Email:", bg='white').grid(row=2, column=0, sticky='w', pady=(0, 5))
        self.email_entry = tk.Entry(form_frame, bd=1, relief='solid', width=40)
        self.email_entry.grid(row=2, column=1, sticky='ew', pady=(0, 10), padx=(10, 0))

        # Password
        self.add_entry_with_toggle(form_frame, "Password (min 15 chars):", "password_entry", row=3)
        self.password_strength = tk.Label(form_frame, text="", bg='white')
        self.password_strength.grid(row=4, column=1, sticky='w', pady=(0, 10))
        self.password_entry.bind('<KeyRelease>', self.update_password_strength)

        # Confirm Password
        self.add_entry_with_toggle(form_frame, "Confirm Password:", "confirm_password_entry", row=5)

        # Security Question
        tk.Label(form_frame, text="Security Question:", bg='white').grid(row=6, column=0, sticky='w', pady=(0, 5))
        self.security_question = ttk.Combobox(form_frame, state="readonly", width=37, values=[
            "What is your mother's maiden name?",
            "What was your first pet's name?",
            "What city were you born in?",
            "What was your first school's name?"
        ])
        self.security_question.grid(row=6, column=1, sticky='ew', pady=(0, 10), padx=(10, 0))

        # Security Answer with eye toggle
        tk.Label(form_frame, text="Security Answer:", bg='white').grid(row=7, column=0, sticky='w', pady=(0, 5))
        security_answer_frame = tk.Frame(form_frame, bg='white')
        security_answer_frame.grid(row=7, column=1, sticky='ew', pady=(0, 10), padx=(10, 0))
        self.security_answer_entry = tk.Entry(security_answer_frame, show="•", bd=1, relief='solid', width=35)
        self.security_answer_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(security_answer_frame, text="👁", width=3, 
                 command=lambda: self.toggle_password_visibility(self.security_answer_entry)).pack(side=tk.RIGHT)

        # PIN
        self.add_entry_with_toggle(form_frame, "6-digit PIN:", "pin_entry", row=8)
        
        # Confirm PIN
        self.add_entry_with_toggle(form_frame, "Confirm PIN:", "confirm_pin_entry", row=9)

        # CAPTCHA
        self.captcha_label = tk.Label(form_frame, text=f"CAPTCHA: {self.captcha_text}", bg='white')
        self.captcha_label.grid(row=10, column=0, sticky='w', pady=(0, 5))
        self.captcha_entry = tk.Entry(form_frame, bd=1, relief='solid', width=40)
        self.captcha_entry.grid(row=10, column=1, sticky='ew', pady=(0, 20), padx=(10, 0))

        # Submit button
        self.submit_btn = tk.Button(
            form_frame, 
            text="Submit", 
            bg="#003366", 
            fg="white",
            font=("Helvetica", 10, "bold"),
            activebackground="#002244", 
            activeforeground="white",
            relief="flat",
            command=self.register, 
            width=38
        )
        self.submit_btn.grid(row=11, column=0, columnspan=2, pady=(10, 5), sticky='ew')

        # Login link
        login_link = tk.Label(
            form_frame, 
            text="Back to Login", 
            fg="blue", 
            bg="white", 
            cursor="hand2",
            font=("Helvetica", 10, "underline")
        )
        login_link.grid(row=12, column=0, columnspan=2, pady=(10, 0))
        login_link.bind("<Button-1>", lambda e: self.go_back_to_login())

        # Configure grid weights
        form_frame.columnconfigure(0, weight=1)
        form_frame.columnconfigure(1, weight=3)

    def add_entry_with_toggle(self, parent, label, attr, row):
        tk.Label(parent, text=label, bg='white').grid(row=row, column=0, sticky='w', pady=(0, 5))
        frame = tk.Frame(parent, bg='white')
        frame.grid(row=row, column=1, sticky='ew', pady=(0, 10), padx=(10, 0))
        
        entry = tk.Entry(frame, show="•", bd=1, relief='solid', width=35)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        btn = tk.Button(frame, text="👁", width=3, command=lambda e=entry: self.toggle_password_visibility(e))
        btn.pack(side=tk.RIGHT)
        
        setattr(self, attr, entry)

    def toggle_password_visibility(self, entry):
        if entry.cget('show') == '':
            entry.config(show='•')
        else:
            entry.config(show='')

    def update_password_strength(self, event):
        password = self.password_entry.get()
        if not password:
            self.password_strength.config(text="")
            return

        if len(password) < 15:
            self.password_strength.config(text="Password must be at least 15 characters", fg="red")
            return

        strength = "Weak"
        feedback = ""
        
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        if len(password) >= 20 and has_lower and has_upper and has_digit and has_special:
            strength = "Strong"
            feedback = "Excellent password"
        elif len(password) >= 15 and (has_lower + has_upper + has_digit + has_special) >= 3:
            strength = "Moderate"
            feedback = "Good, but could be stronger"
        else:
            strength = "Weak"
            feedback = "Too weak - include more character types"

        colors = {
            "Weak": "red",
            "Moderate": "orange",
            "Strong": "green"
        }
        self.password_strength.config(text=f"Strength: {strength} - {feedback}", fg=colors.get(strength, "black"))

    def validate_email_format(self, email):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def clear_all_fields(self):
        self.username_entry.delete(0, tk.END)
        self.email_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.confirm_password_entry.delete(0, tk.END)
        self.security_question.set('')
        self.security_answer_entry.delete(0, tk.END)
        self.pin_entry.delete(0, tk.END)
        self.confirm_pin_entry.delete(0, tk.END)
        self.captcha_entry.delete(0, tk.END)
        self.password_strength.config(text="")
        
        self.captcha_text, self.captcha_answer = self.generate_new_captcha()
        self.captcha_label.config(text=f"CAPTCHA: {self.captcha_text}")

    def go_back_to_login(self, event=None):
        self.clear_all_fields()
        self.app.switch_to_frame(self.login_screen_class)  # Use the stored login screen class

    def register(self):
        try:
            current_time = time.time()
            if self.captcha_attempts >= 3 and current_time - self.last_captcha_attempt_time < 30:
                remaining_time = int(30 - (current_time - self.last_captcha_attempt_time))
                messagebox.showerror(
                    "CAPTCHA Timeout",
                    f"Too many failed CAPTCHA attempts. Please wait {remaining_time} seconds before trying again."
                )
                self.clear_all_fields()
                return

            username = self.username_entry.get().strip()
            email = self.email_entry.get().strip()
            password = self.password_entry.get()
            confirm_password = self.confirm_password_entry.get()
            security_question = self.security_question.get()
            security_answer = self.security_answer_entry.get().strip()
            pin = self.pin_entry.get()
            confirm_pin = self.confirm_pin_entry.get()
            captcha = self.captcha_entry.get().strip()

            if not all([username, email, password, confirm_password, security_question, security_answer, pin, confirm_pin, captcha]):
                messagebox.showerror("Error", "All fields are required!")
                return

            if len(username) < 7:
                messagebox.showerror("Error", "Username must be at least 7 characters long!")
                return

            if not self.validate_email_format(email):
                messagebox.showerror("Error", "Please enter a valid email address!")
                return

            if len(password) < 15:
                messagebox.showerror("Error", "Password must be at least 15 characters long!")
                return

            if password != confirm_password:
                messagebox.showerror("Error", "Passwords do not match!")
                return

            if "Weak" in self.password_strength.cget("text"):
                messagebox.showerror("Error", "Password is too weak! Please choose a stronger password.")
                return

            if not security_question:
                messagebox.showerror("Error", "Please select a security question!")
                return

            if not security_answer:
                messagebox.showerror("Error", "Please provide an answer to the security question!")
                return

            if not self.validate_pin(pin) or not self.validate_pin(confirm_pin):
                messagebox.showerror("Error", "PIN must be 6 digits!")
                return

            if pin != confirm_pin:
                messagebox.showerror("Error", "PINs do not match!")
                return

            if captcha.lower() != str(self.captcha_answer).lower():
                self.captcha_attempts += 1
                self.last_captcha_attempt_time = time.time()
                
                if self.captcha_attempts >= 3:
                    message = f"CAPTCHA verification failed! Correct answer was: {self.captcha_answer}\n" \
                              "Too many failed attempts. Please wait 30 seconds before trying again."
                    self.clear_all_fields()
                else:
                    message = f"CAPTCHA verification failed! Correct answer was: {self.captcha_answer}\n" \
                             f"Attempts remaining: {3 - self.captcha_attempts}"
                
                messagebox.showerror("CAPTCHA Failed", message)
                
                self.captcha_text, self.captcha_answer = self.generate_new_captcha()
                self.captcha_label.config(text=f"CAPTCHA: {self.captcha_text}")
                self.captcha_entry.delete(0, tk.END)
                return

            self.captcha_attempts = 0

            users = []
            if os.path.exists("users.json"):
                try:
                    with open("users.json", "r") as f:
                        users = json.load(f)
                        if not isinstance(users, list):  # Ensure users is always a list
                            users = []
                except (json.JSONDecodeError, FileNotFoundError):
                    users = []

            if any(user.get('username', '').lower() == username.lower() for user in users):
                messagebox.showerror("Error", "Username already exists!")
                self.clear_all_fields()
                return
            if any(user.get('email', '').lower() == email.lower() for user in users):
                messagebox.showerror("Error", "Email already registered!")
                self.clear_all_fields()
                return

            hashed_password = hash_password(password)
            hashed_pin = hash_pin(pin)

            new_user = {
                "username": username,
                "email": email,
                "password": hashed_password,
                "security_question": security_question,
                "security_answer": security_answer,
                "pin": hashed_pin,
                "passwords": []  # Initialize empty passwords list
            }
            users.append(new_user)

            with open("users.json", "w") as f:
                json.dump(users, f, indent=4)

            try:
                send_welcome_email(email, username)
            except Exception as e:
                print(f"Error sending welcome email: {e}")

            messagebox.showinfo("Success", "Registration successful!")
            self.clear_all_fields()
            self.go_back_to_login()

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during registration: {str(e)}")
            print(f"Error during registration: {e}")
            self.clear_all_fields()