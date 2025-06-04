import tkinter as tk
from tkinter import ttk, messagebox
from utils.validation import validate_password_strength
from utils.encryption import hash_password
from utils.emailer import send_password_change_alert
import json

class ChangePasswordScreen(tk.Frame):
    def __init__(self, parent, app, user):
        super().__init__(parent)
        self.app = app
        self.user = user
        
        self.configure(bg='#ffffff')
        self.style = ttk.Style()
        self.style.configure('TButton', background='#003366', foreground='white')
        
        self.create_widgets()
        
    def create_widgets(self):
        # Header
        header_frame = ttk.Frame(self)
        header_frame.pack(fill=tk.X, padx=20, pady=(20, 10))
        
        logo_label = ttk.Label(header_frame, text="PassShield", font=('Arial', 24, 'bold'))
        logo_label.configure(foreground='#003366')
        logo_label.pack(side=tk.LEFT)
        
        # Back Button
        back_btn = ttk.Button(
            header_frame,
            text="Back",
            style='TButton',
            command=self.go_back
        )
        back_btn.pack(side=tk.RIGHT)
        
        # Form Frame
        form_frame = ttk.Frame(self, padding="20")
        form_frame.pack(fill=tk.BOTH, expand=True, padx=40, pady=20)
        
        # Current Password
        ttk.Label(form_frame, text="Current Password:").grid(row=0, column=0, pady=(0, 5), sticky='w')
        self.current_password_entry = ttk.Entry(form_frame, show="•")
        self.current_password_entry.grid(row=0, column=1, sticky='ew', pady=(0, 10))
        
        # New Password
        ttk.Label(form_frame, text="New Password (min 15 chars):").grid(row=1, column=0, pady=(0, 5), sticky='w')
        self.new_password_entry = ttk.Entry(form_frame, show="•")
        self.new_password_entry.grid(row=1, column=1, sticky='ew', pady=(0, 10))
        
        # Password Strength Meter
        self.password_strength = ttk.Label(form_frame, text="", foreground='red')
        self.password_strength.grid(row=2, column=1, sticky='w', pady=(0, 10))
        self.new_password_entry.bind('<KeyRelease>', self.update_password_strength)
        
        # Confirm New Password
        ttk.Label(form_frame, text="Confirm New Password:").grid(row=3, column=0, pady=(0, 5), sticky='w')
        self.confirm_password_entry = ttk.Entry(form_frame, show="•")
        self.confirm_password_entry.grid(row=3, column=1, sticky='ew', pady=(0, 10))
        
        # Change Button
        change_btn = ttk.Button(
            form_frame,
            text="Change Password",
            style='TButton',
            command=self.change_password
        )
        change_btn.grid(row=4, column=1, pady=(20, 0), sticky='ew')
        
    def update_password_strength(self, event=None):
        password = self.new_password_entry.get()
        if len(password) == 0:
            self.password_strength.config(text="", foreground='red')
            return
            
        strength = validate_password_strength(password)
        if strength == "weak":
            self.password_strength.config(text="Weak", foreground='red')
        elif strength == "medium":
            self.password_strength.config(text="Medium", foreground='orange')
        else:
            self.password_strength.config(text="Strong", foreground='green')
    
    def change_password(self):
        current_password = self.current_password_entry.get()
        new_password = self.new_password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        
        # Validate inputs
        errors = []
        
        if not current_password:
            errors.append("Please enter your current password")
            
        if not verify_password(current_password, self.user['password_hash']):
            errors.append("Current password is incorrect")
            
        password_strength = validate_password_strength(new_password)
        if password_strength == "weak":
            errors.append("New password is too weak")
            
        if new_password != confirm_password:
            errors.append("New passwords do not match")
            
        if errors:
            messagebox.showerror("Error", "\n".join(errors))
            return
            
        # Update password in database
        self.update_user_password(new_password)
        
        # Send notification email
        send_password_change_alert(self.user['email'], self.user['username'])
        
        messagebox.showinfo("Success", "Password changed successfully!")
        self.go_back()
        
    def update_user_password(self, new_password):
        try:
            with open('storage/database.json', 'r') as f:
                data = json.load(f)
                
            # Find and update the user
            for i, user in enumerate(data['users']):
                if user['username'] == self.user['username']:
                    data['users'][i]['password_hash'] = hash_password(new_password)
                    break
                    
            with open('storage/database.json', 'w') as f:
                json.dump(data, f, indent=2)
                
            # Update current user in memory
            self.user['password_hash'] = hash_password(new_password)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update password: {str(e)}")
            
    def go_back(self):
        from screens.dashboard import Dashboard
        self.destroy()
        dashboard = Dashboard(self.master, self.app)
        dashboard.pack(fill=tk.BOTH, expand=True)