import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import json
import os
import hashlib
from datetime import datetime
import random
import time
import re
from ui import PassShieldApp  # Import the main app to handle user management

# ========== ADMIN DATABASE FUNCTIONS ==========
ADMINS_FILE = 'admins.json'
MAX_ADMINS = 50
ADMIN_CAPTCHA_QUESTIONS = [
    {"question": "What is 5 + 3?", "answer": "8"},
    {"question": "Capital of France?", "answer": "paris"},
    {"question": "Color of the sky?", "answer": "blue"},
    {"question": "Sides of a triangle?", "answer": "3"},
    {"question": "Opposite of day?", "answer": "night"}
]
ADMIN_SECRET_KEYS = ["P@SS2023", "SHIELD#99", "ADMIN$KEY", "SECURE*123"]

def get_admins():
    try:
        with open(ADMINS_FILE, 'r') as f:
            admins = json.load(f)
            if isinstance(admins, list):
                admins = {admin['username']: admin for admin in admins}
                save_admins(admins)
            return admins
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_admins(admins):
    with open(ADMINS_FILE, 'w') as f:
        json.dump(admins, f, indent=2)

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ========== ADMIN MANAGEMENT SYSTEM ==========
class AdminDashboard(tk.Tk):
    def __init__(self, username):
        super().__init__()
        self.title("Admin Dashboard")
        self.geometry("1200x800")
        self.configure(bg='#e0f0ff')
        self.username = username
        
        self.create_widgets()
        self.load_stats()
        self.load_activity_log()
    
    def create_widgets(self):
        # Main container frame
        main_frame = tk.Frame(self, bg='#e0f0ff')
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Header
        header = tk.Frame(main_frame, bg='#57a1f8', bd=2, relief='groove')
        header.pack(fill='x', pady=(0, 20))
        tk.Label(header, text=f"Admin Dashboard - Welcome {self.username}", 
                font=('Arial', 18, 'bold'), bg='#57a1f8', fg='black', 
                height=2, padx=20, anchor='w').pack(fill='x')
        
        # Stats Frame
        stats_frame = tk.Frame(main_frame, bg='#e0f0ff', bd=2, relief='groove', padx=10, pady=10)
        stats_frame.pack(fill='x', padx=20, pady=10)
        
        self.stats = {
            'total_users': tk.StringVar(),
            'active_today': tk.StringVar(),
            'total_admins': tk.StringVar(),
            'active_admins': tk.StringVar()
        }
        
        stat_box_style = {
            'bg': 'white', 
            'padx': 20, 
            'pady': 10, 
            'relief': 'groove', 
            'bd': 1,
            'font': ('Arial', 14),
            'fg': 'black',
            'width': 15
        }
        
        tk.Label(stats_frame, textvariable=self.stats['total_users'], 
                text="Total Users\n0", **stat_box_style).grid(row=0, column=0, padx=5, sticky='nsew')
        tk.Label(stats_frame, textvariable=self.stats['active_today'], 
                text="Active Today\n0", **stat_box_style).grid(row=0, column=1, padx=5, sticky='nsew')
        tk.Label(stats_frame, textvariable=self.stats['total_admins'], 
                text="Total Admins\n0", **stat_box_style).grid(row=0, column=2, padx=5, sticky='nsew')
        tk.Label(stats_frame, textvariable=self.stats['active_admins'], 
                text="Active Admins\n0", **stat_box_style).grid(row=0, column=3, padx=5, sticky='nsew')
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Create tabs
        self.create_user_tab()
        self.create_admin_tab()
        self.create_activity_tab()
        self.create_settings_tab()
        
        # Logout button
        tk.Button(main_frame, text="Logout", command=self.logout,
                bg='#57a1f8', fg='black', font=('Arial', 12), width=15).pack(pady=10)
    
    def create_user_tab(self):
        user_tab = tk.Frame(self.notebook, bg='#e0f0ff')
        self.notebook.add(user_tab, text="User Management")
        
        # Container frame for user tab
        user_container = tk.Frame(user_tab, bg='#e0f0ff', bd=2, relief='groove', padx=10, pady=10)
        user_container.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Search Frame
        search_frame = tk.Frame(user_container, bg='#e0f0ff', bd=1, relief='sunken', padx=5, pady=5)
        search_frame.pack(fill='x', padx=10, pady=10)
        
        self.search_var = tk.StringVar()
        tk.Entry(search_frame, textvariable=self.search_var, font=('Arial', 12), width=30).pack(side='left', padx=5)
        tk.Button(search_frame, text="Search", command=self.search_users,
                bg='#57a1f8', fg='black', width=10).pack(side='left', padx=5)
        
        # User List Frame
        list_frame = tk.Frame(user_container, bg='#e0f0ff', bd=1, relief='sunken', padx=5, pady=5)
        list_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.user_tree = ttk.Treeview(list_frame, columns=('username', 'email', 'created_at'), show='headings')
        self.user_tree.heading('username', text='Username')
        self.user_tree.heading('email', text='Email')
        self.user_tree.heading('created_at', text='Registration Date')
        
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.user_tree.yview)
        self.user_tree.configure(yscrollcommand=scrollbar.set)
        
        self.user_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Context Menu
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="View Details", command=self.view_user_details)
        self.context_menu.add_command(label="Reset Password", command=self.reset_user_password)
        self.context_menu.add_command(label="Delete User", command=self.delete_user)
        self.context_menu.add_command(label="Copy Info", command=self.copy_user_info)
        self.context_menu.add_command(label="Export Data", command=self.export_user_data)
        self.user_tree.bind('<Button-3>', self.show_context_menu)
        
        self.load_users()
    
    def create_admin_tab(self):
        admin_tab = tk.Frame(self.notebook, bg='#e0f0ff')
        self.notebook.add(admin_tab, text="Admin Management")
        
        # Container frame for admin tab
        admin_container = tk.Frame(admin_tab, bg='#e0f0ff', bd=2, relief='groove', padx=10, pady=10)
        admin_container.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Admin List Frame
        list_frame = tk.Frame(admin_container, bg='#e0f0ff', bd=1, relief='sunken', padx=5, pady=5)
        list_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.admin_tree = ttk.Treeview(list_frame, columns=('username', 'email', 'last_login'), show='headings')
        self.admin_tree.heading('username', text='Username')
        self.admin_tree.heading('email', text='Email')
        self.admin_tree.heading('last_login', text='Last Login')
        
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.admin_tree.yview)
        self.admin_tree.configure(yscrollcommand=scrollbar.set)
        
        self.admin_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Button Frame
        button_frame = tk.Frame(admin_container, bg='#e0f0ff', bd=1, relief='sunken', padx=5, pady=5)
        button_frame.pack(fill='x', padx=10, pady=10)
        
        # Add Admin Button
        tk.Button(button_frame, text="Add New Admin", command=self.show_add_admin_dialog,
                bg='#57a1f8', fg='black', width=15).pack(pady=5)
        
        # Admin Context Menu
        self.admin_context_menu = tk.Menu(self, tearoff=0)
        self.admin_context_menu.add_command(label="Reset Password", command=self.reset_admin_password)
        self.admin_context_menu.add_command(label="Deactivate", command=self.deactivate_admin)
        self.admin_tree.bind('<Button-3>', self.show_admin_context_menu)
        
        self.load_admins()
    
    def create_activity_tab(self):
        activity_tab = tk.Frame(self.notebook, bg='#e0f0ff')
        self.notebook.add(activity_tab, text="System Activity")
        
        # Container frame for activity tab
        activity_container = tk.Frame(activity_tab, bg='#e0f0ff', bd=2, relief='groove', padx=10, pady=10)
        activity_container.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.activity_log = tk.Text(activity_container, wrap='word', state='disabled',
                                  font=('Consolas', 10), bg='white', fg='black',
                                  padx=10, pady=10)
        scrollbar = ttk.Scrollbar(activity_container, command=self.activity_log.yview)
        self.activity_log.configure(yscrollcommand=scrollbar.set)
        
        self.activity_log.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
    
    def create_settings_tab(self):
        settings_tab = tk.Frame(self.notebook, bg='#e0f0ff')
        self.notebook.add(settings_tab, text="Settings")
        
        # Container frame for settings tab
        settings_container = tk.Frame(settings_tab, bg='#e0f0ff', bd=2, relief='groove', padx=10, pady=10)
        settings_container.pack(fill='both', expand=True, padx=10, pady=10)
        
        tk.Label(settings_container, text="Admin Panel Settings", 
                font=('Arial', 16), bg='#e0f0ff', fg='black').pack(pady=10)
        
        # Settings Frame
        settings_frame = tk.Frame(settings_container, bg='#e0f0ff', bd=1, relief='sunken', padx=10, pady=10)
        settings_frame.pack(fill='x', padx=20, pady=10)
        
        # Notification settings
        self.notif_var = tk.IntVar(value=1)
        tk.Checkbutton(settings_frame, text="Enable email notifications", 
                      variable=self.notif_var, bg='#e0f0ff', fg='black').pack(anchor='w', padx=20, pady=5)
        
        # Max admins setting
        max_admin_frame = tk.Frame(settings_frame, bg='#e0f0ff')
        max_admin_frame.pack(anchor='w', padx=20, pady=5, fill='x')
        
        tk.Label(max_admin_frame, text="Maximum Admins:", 
                font=('Arial', 12), bg='#e0f0ff', fg='black').pack(side='left')
        
        self.max_admin_var = tk.StringVar(value=str(MAX_ADMINS))
        tk.Entry(max_admin_frame, textvariable=self.max_admin_var, width=5).pack(side='left', padx=10)
        
        # Save button frame
        button_frame = tk.Frame(settings_container, bg='#e0f0ff', bd=1, relief='sunken', padx=5, pady=5)
        button_frame.pack(pady=20)
        
        # Save button
        tk.Button(button_frame, text="Save Settings", command=self.save_settings,
                bg='#57a1f8', fg='black', width=15).pack()
    
    def load_stats(self):
        user_app = PassShieldApp()
        users = user_app.users_db
        self.stats['total_users'].set(f"Total Users\n{len(users)}")
        
        admins = get_admins()
        self.stats['total_admins'].set(f"Total Admins\n{len(admins)}")
        
        self.stats['active_today'].set("Active Today\n0")
        self.stats['active_admins'].set("Active Admins\n0")
    
    def load_users(self):
        for item in self.user_tree.get_children():
            self.user_tree.delete(item)
            
        user_app = PassShieldApp()
        users = user_app.users_db
        for username, data in users.items():
            self.user_tree.insert('', 'end', values=(
                username,
                data['email'],
                data.get('created_at', 'N/A')
            ))
    
    def load_admins(self):
        for item in self.admin_tree.get_children():
            self.admin_tree.delete(item)
            
        admins = get_admins()
        for username, data in admins.items():
            self.admin_tree.insert('', 'end', values=(
                username,
                data['email'],
                data.get('last_login', 'Never')
            ))
    
    def load_activity_log(self):
        sample_log = """[2023-08-01 10:00] Admin login successful
[2023-08-01 10:15] User 'john_doe' deleted
[2023-08-01 11:30] Password reset for user 'jane_smith'
[2023-08-01 12:45] New admin 'admin2' added to system"""
        
        self.activity_log.configure(state='normal')
        self.activity_log.insert('end', sample_log)
        self.activity_log.configure(state='disabled')
    
    def search_users(self, event=None):
        query = self.search_var.get().lower()
        for child in self.user_tree.get_children():
            values = self.user_tree.item(child)['values']
            if query in str(values).lower():
                self.user_tree.selection_set(child)
                self.user_tree.focus(child)
                break
    
    def show_context_menu(self, event):
        item = self.user_tree.identify_row(event.y)
        if item:
            self.user_tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def show_admin_context_menu(self, event):
        item = self.admin_tree.identify_row(event.y)
        if item:
            self.admin_tree.selection_set(item)
            self.admin_context_menu.post(event.x_root, event.y_root)
    
    def view_user_details(self):
        selected = self.user_tree.selection()
        if not selected:
            return
        
        username = self.user_tree.item(selected[0])['values'][0]
        user_app = PassShieldApp()
        if username in user_app.users_db:
            user_data = user_app.users_db[username]
            
            details_window = tk.Toplevel(self)
            details_window.title(f"User Details - {username}")
            details_window.geometry("500x400")
            
            # Create a frame for the details
            details_frame = tk.Frame(details_window, padx=10, pady=10)
            details_frame.pack(fill='both', expand=True)
            
            # Display user details
            tk.Label(details_frame, text=f"Username: {username}", font=('Arial', 12), anchor='w').pack(fill='x')
            tk.Label(details_frame, text=f"Email: {user_data['email']}", font=('Arial', 12), anchor='w').pack(fill='x')
            tk.Label(details_frame, text=f"Registration Date: {user_data.get('created_at', 'N/A')}", 
                   font=('Arial', 12), anchor='w').pack(fill='x')
            
            # Add a close button
            tk.Button(details_frame, text="Close", command=details_window.destroy).pack(pady=10)
    
    def reset_user_password(self):
        selected = self.user_tree.selection()
        if not selected:
            return
        
        username = self.user_tree.item(selected[0])['values'][0]
        if messagebox.askyesno("Confirm", f"Reset password for {username}?"):
            new_password = simpledialog.askstring("Password Reset", 
                                               "Enter new password:", show='*')
            if new_password:
                user_app = PassShieldApp()
                if username in user_app.users_db:
                    user_app.users_db[username]['password'] = hash_password(new_password)
                    with open('users_db.json', 'w') as f:
                        json.dump(user_app.users_db, f)
                    messagebox.showinfo("Success", "Password reset successfully")
                    self.log_activity(f"Password reset for user {username}")
    
    def delete_user(self):
        selected = self.user_tree.selection()
        if not selected:
            return
        
        username = self.user_tree.item(selected[0])['values'][0]
        if messagebox.askyesno("Confirm", f"Delete user {username} permanently?"):
            user_app = PassShieldApp()
            if username in user_app.users_db:
                del user_app.users_db[username]
                with open('users_db.json', 'w') as f:
                    json.dump(user_app.users_db, f)
                self.load_users()
                self.load_stats()
                self.log_activity(f"Deleted user {username}")
                messagebox.showinfo("Success", "User deleted successfully")
    
    def copy_user_info(self):
        selected = self.user_tree.selection()
        if not selected:
            return
        
        username = self.user_tree.item(selected[0])['values'][0]
        user_app = PassShieldApp()
        if username in user_app.users_db:
            user_data = user_app.users_db[username]
            info = f"Username: {username}\nEmail: {user_data['email']}\nRegistered: {user_data.get('created_at', 'N/A')}"
            
            self.clipboard_clear()
            self.clipboard_append(info)
            messagebox.showinfo("Copied", "User information copied to clipboard")
    
    def export_user_data(self):
        selected = self.user_tree.selection()
        if not selected:
            return
        
        username = self.user_tree.item(selected[0])['values'][0]
        user_app = PassShieldApp()
        if username in user_app.users_db:
            user_data = user_app.users_db[username]
            
            # Create a simple export dialog
            export_window = tk.Toplevel(self)
            export_window.title(f"Export Data - {username}")
            export_window.geometry("400x300")
            
            # Format options
            tk.Label(export_window, text="Export Format:").pack(pady=10)
            format_var = tk.StringVar(value="txt")
            tk.Radiobutton(export_window, text="Text File (.txt)", variable=format_var, value="txt").pack()
            tk.Radiobutton(export_window, text="JSON File (.json)", variable=format_var, value="json").pack()
            
            # Export button
            tk.Button(export_window, text="Export", 
                    command=lambda: self.perform_export(username, user_data, format_var.get(), export_window)).pack(pady=20)
    
    def perform_export(self, username, user_data, format_type, window):
        filename = f"{username}_data.{format_type}"
        
        if format_type == "txt":
            with open(filename, 'w') as f:
                f.write(f"Username: {username}\n")
                f.write(f"Email: {user_data['email']}\n")
                f.write(f"Registration Date: {user_data.get('created_at', 'N/A')}\n")
        else:  # json
            with open(filename, 'w') as f:
                json.dump(user_data, f, indent=2)
        
        messagebox.showinfo("Export Complete", f"User data exported to {filename}")
        window.destroy()
    
    def reset_admin_password(self):
        selected = self.admin_tree.selection()
        if not selected:
            return
        
        username = self.admin_tree.item(selected[0])['values'][0]
        if username == self.username:
            messagebox.showerror("Error", "Cannot reset your own password from here")
            return
            
        if messagebox.askyesno("Confirm", f"Reset password for admin {username}?"):
            new_password = simpledialog.askstring("Password Reset", 
                                                "Enter new password:", show='*')
            if new_password:
                admins = get_admins()
                if username in admins:
                    admins[username]['password'] = hash_password(new_password)
                    save_admins(admins)
                    messagebox.showinfo("Success", "Password reset successfully")
                    self.log_activity(f"Password reset for admin {username}")
    
    def deactivate_admin(self):
        selected = self.admin_tree.selection()
        if not selected:
            return
        
        username = self.admin_tree.item(selected[0])['values'][0]
        if username == self.username:
            messagebox.showerror("Error", "Cannot deactivate yourself")
            return
            
        if messagebox.askyesno("Confirm", f"Deactivate admin {username}?"):
            admins = get_admins()
            if username in admins:
                del admins[username]
                save_admins(admins)
                self.load_admins()
                self.load_stats()
                self.log_activity(f"Deactivated admin {username}")
                messagebox.showinfo("Success", "Admin deactivated successfully")
    
    def show_add_admin_dialog(self):
        dialog = tk.Toplevel(self)
        dialog.title("Add New Admin")
        dialog.geometry("400x600")
        dialog.resizable(False, False)
        dialog.configure(bg='#e0f0ff')
        
        # Main container
        container = tk.Frame(dialog, bg='#e0f0ff', bd=2, relief='groove', padx=10, pady=10)
        container.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Form fields
        tk.Label(container, text="Username (min 8 chars):", bg='#e0f0ff', fg='black').pack(pady=(10, 0))
        username_entry = tk.Entry(container, width=30)
        username_entry.pack(pady=5)
        
        tk.Label(container, text="Email:", bg='#e0f0ff', fg='black').pack(pady=(10, 0))
        email_entry = tk.Entry(container, width=30)
        email_entry.pack(pady=5)
        
        # Password frame with show/hide button
        tk.Label(container, text="Password (min 12 chars):", bg='#e0f0ff', fg='black').pack(pady=(10, 0))
        password_frame = tk.Frame(container, bg='#e0f0ff')
        password_frame.pack()
        password_entry = tk.Entry(password_frame, show="*", width=25)
        password_entry.pack(side='left')
        tk.Button(password_frame, text="👁", command=lambda: self.toggle_password(password_entry), 
                bg='#e0f0ff', fg='black', relief='flat').pack(side='left')
        
        # Confirm password frame
        tk.Label(container, text="Confirm Password:", bg='#e0f0ff', fg='black').pack(pady=(10, 0))
        confirm_frame = tk.Frame(container, bg='#e0f0ff')
        confirm_frame.pack()
        confirm_entry = tk.Entry(confirm_frame, show="*", width=25)
        confirm_entry.pack(side='left')
        tk.Button(confirm_frame, text="👁", command=lambda: self.toggle_password(confirm_entry), 
                bg='#e0f0ff', fg='black', relief='flat').pack(side='left')
        
        # Security question
        tk.Label(container, text="Security Question:", bg='#e0f0ff', fg='black').pack(pady=(10, 0))
        security_question = ttk.Combobox(container, values=[
            "What was your first pet's name?",
            "What city were you born in?",
            "What is your mother's maiden name?",
    "What is your favorite food?",
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
        ], width=28)
        security_question.pack(pady=5)
        
        tk.Label(container, text="Answer:", bg='#e0f0ff', fg='black').pack(pady=(10, 0))
        security_answer = tk.Entry(container, width=30)
        security_answer.pack(pady=5)
        
        # Secret Key
        tk.Label(container, text="Admin Secret Key:", bg='#e0f0ff', fg='black').pack(pady=(10, 0))
        secret_key_entry = ttk.Combobox(container, values=ADMIN_SECRET_KEYS, width=30)
        secret_key_entry.pack(pady=5)
        
        # CAPTCHA
        captcha_question = random.choice(ADMIN_CAPTCHA_QUESTIONS)
        tk.Label(container, text=f"CAPTCHA: {captcha_question['question']}", 
               bg='#e0f0ff', fg='black').pack(pady=(10, 0))
        captcha_answer = tk.Entry(container, width=30)
        captcha_answer.pack(pady=5)
        
        # Status label
        status = tk.Label(container, text="", fg="red", bg='#e0f0ff')
        status.pack()
        
        # Buttons
        button_frame = tk.Frame(container, bg='#e0f0ff', bd=1, relief='sunken', padx=5, pady=5)
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="Cancel", command=dialog.destroy,
                bg='#57a1f8', fg='black', width=10).pack(side='left', padx=5)
        tk.Button(button_frame, text="Register", 
                command=lambda: self.register_admin(
                    username_entry.get(),
                    email_entry.get(),
                    password_entry.get(),
                    confirm_entry.get(),
                    security_question.get(),
                    security_answer.get(),
                    secret_key_entry.get(),
                    captcha_question['answer'],
                    captcha_answer.get(),
                    status,
                    dialog
                ), bg='#57a1f8', fg='black', width=10).pack(side='right', padx=5)
    
    def toggle_password(self, entry):
        if entry.cget('show') == '*':
            entry.config(show='')
        else:
            entry.config(show='*')
    
    def register_admin(self, username, email, password, confirm, question, answer, secret_key, captcha_correct, captcha_user, status, dialog):
        if not all([username, email, password, confirm, question, answer, secret_key, captcha_user]):
            status.config(text="All fields are required")
            return
        
        if len(username) < 8:
            status.config(text="Username must be at least 8 characters")
            return
        
        if not validate_email(email):
            status.config(text="Invalid email format")
            return
        
        if len(password) < 12:
            status.config(text="Password must be at least 12 characters")
            return
        
        if password != confirm:
            status.config(text="Passwords don't match")
            return
        
        if secret_key not in ADMIN_SECRET_KEYS:
            status.config(text="Invalid admin secret key")
            return
        
        if captcha_user.lower() != captcha_correct.lower():
            status.config(text="Incorrect CAPTCHA answer")
            return
        
        admins = get_admins()
        if username in admins:
            status.config(text="Admin already exists")
            return
        
        if len(admins) >= MAX_ADMINS:
            status.config(text=f"Maximum of {MAX_ADMINS} admins reached")
            return
        
        admins[username] = {
            'email': email,
            'password': hash_password(password),
            'security_question': question,
            'security_answer': hash_password(answer.lower()),
            'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'last_login': None,
            'active': True
        }
        
        save_admins(admins)
        status.config(text="Admin created successfully!", fg="green")
        self.load_admins()
        self.load_stats()
        self.log_activity(f"New admin {username} added")
        dialog.after(2000, dialog.destroy)
    
    def save_settings(self):
        try:
            max_admins = int(self.max_admin_var.get())
            if max_admins < 1 or max_admins > 20:
                raise ValueError
            messagebox.showinfo("Success", "Settings saved successfully")
            self.log_activity("Settings updated")
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number (1-20)")
    
    def log_activity(self, message):
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M]")
        self.activity_log.configure(state='normal')
        self.activity_log.insert('end', f"\n{timestamp} {message}")
        self.activity_log.configure(state='disabled')
        self.activity_log.see('end')
    
    def logout(self):
        self.destroy()
        AdminSignIn().mainloop()

# ========== ADMIN SIGN IN ==========
class AdminSignIn(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Admin Authentication")
        self.geometry("400x400")
        self.configure(bg='#e0f0ff')
        
        self.username = tk.StringVar()
        self.password = tk.StringVar()
        
        self.create_widgets()
    
    def create_widgets(self):
        main_frame = tk.Frame(self, bg='#e0f0ff', bd=2, relief='groove', padx=10, pady=10)
        main_frame.pack(pady=20, padx=20, fill='both', expand=True)
        
        tk.Label(main_frame, text="Admin Portal", font=('Arial', 24, 'bold'),
               bg='#e0f0ff', fg='black').pack(pady=20)
        
        # Form container
        form_frame = tk.Frame(main_frame, bg='#e0f0ff', bd=1, relief='sunken', padx=10, pady=10)
        form_frame.pack(pady=10)
        
        # Username
        tk.Label(form_frame, text="Username/Email:", font=('Arial', 12), 
               bg='#e0f0ff', fg='black').pack(pady=(10, 0))
        tk.Entry(form_frame, textvariable=self.username, font=('Arial', 12), width=25).pack(pady=5)
        
        # Password
        tk.Label(form_frame, text="Password:", font=('Arial', 12), 
               bg='#e0f0ff', fg='black').pack(pady=(10, 0))
        
        password_frame = tk.Frame(form_frame, bg='#e0f0ff')
        password_frame.pack()
        
        pass_entry = tk.Entry(password_frame, textvariable=self.password, show='*', 
                            font=('Arial', 12), width=20)
        pass_entry.pack(side='left')
        
        tk.Button(password_frame, text="👁", command=lambda: self.toggle_password(pass_entry),
                bg='#e0f0ff', fg='black', relief='flat').pack(side='left')
        
        # Status label
        self.status_label = tk.Label(main_frame, text="", fg="red", bg='#e0f0ff')
        self.status_label.pack(pady=10)
        
        # Buttons
        button_frame = tk.Frame(main_frame, bg='#e0f0ff', bd=1, relief='sunken', padx=5, pady=5)
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="Sign In", command=self.authenticate,
                bg='#57a1f8', fg='black', font=('Arial', 12), width=10).pack(side='left', padx=5)
        
        tk.Button(button_frame, text="Change Password", command=self.change_password,
                bg='#57a1f8', fg='black', font=('Arial', 12), width=15).pack(side='left', padx=5)
        
        # Links
        link_frame = tk.Frame(main_frame, bg='#e0f0ff')
        link_frame.pack(pady=10)
        
        tk.Button(link_frame, text="Forgot Password?", command=self.forgot_password,
                bg='#e0f0ff', fg='black', relief='flat', font=('Arial', 10)).pack(side='left', padx=5)
        
        tk.Button(link_frame, text="Register Admin", command=self.register_admin,
                bg='#e0f0ff', fg='black', relief='flat', font=('Arial', 10)).pack(side='right', padx=5)
    
    def toggle_password(self, entry):
        if entry.cget('show') == '*':
            entry.config(show='')
        else:
            entry.config(show='*')
    
    def authenticate(self):
        admins = get_admins()
        username = self.username.get()
        password = self.password.get()
        
        if not all([username, password]):
            self.status_label.config(text="All fields are required")
            return
        
        if username in admins:
            stored_hash = admins[username]['password']
            if hashlib.sha256(password.encode()).hexdigest() == stored_hash:
                admins[username]['last_login'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                save_admins(admins)
                
                self.destroy()
                AdminDashboard(username).mainloop()
                return
        
        self.status_label.config(text="Invalid credentials")
    
    def change_password(self):
        self.destroy()
        AdminChangePassword().mainloop()
    
    def forgot_password(self):
        self.destroy()
        AdminForgotPassword().mainloop()
    
    def register_admin(self):
        self.destroy()
        AdminRegister().mainloop()

# ========== ADMIN CHANGE PASSWORD ==========
class AdminChangePassword(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Admin Password Change")
        self.geometry("400x500")
        self.configure(bg='#e0f0ff')
        
        self.username = tk.StringVar()
        self.current_password = tk.StringVar()
        self.new_password = tk.StringVar()
        self.confirm_password = tk.StringVar()
        
        self.create_widgets()
    
    def create_widgets(self):
        main_frame = tk.Frame(self, bg='#e0f0ff', bd=2, relief='groove', padx=10, pady=10)
        main_frame.pack(pady=20, padx=20, fill='both', expand=True)
        
        tk.Label(main_frame, text="Change Password", font=('Arial', 24, 'bold'),
               bg='#e0f0ff', fg='black').pack(pady=20)
        
        # Form container
        form_frame = tk.Frame(main_frame, bg='#e0f0ff', bd=1, relief='sunken', padx=10, pady=10)
        form_frame.pack(pady=10)
        
        # Username
        tk.Label(form_frame, text="Username/Email:", font=('Arial', 12), 
               bg='#e0f0ff', fg='black').pack(pady=(10, 0))
        tk.Entry(form_frame, textvariable=self.username, font=('Arial', 12), width=25).pack(pady=5)
        
        # Current Password
        tk.Label(form_frame, text="Current Password:", font=('Arial', 12), 
               bg='#e0f0ff', fg='black').pack(pady=(10, 0))
        
        current_frame = tk.Frame(form_frame, bg='#e0f0ff')
        current_frame.pack()
        
        current_entry = tk.Entry(current_frame, textvariable=self.current_password, show='*', 
                            font=('Arial', 12), width=20)
        current_entry.pack(side='left')
        
        tk.Button(current_frame, text="👁", command=lambda: self.toggle_password(current_entry),
                bg='#e0f0ff', fg='black', relief='flat').pack(side='left')
        
        # New Password
        tk.Label(form_frame, text="New Password (min 12 chars):", font=('Arial', 12), 
               bg='#e0f0ff', fg='black').pack(pady=(10, 0))
        
        new_frame = tk.Frame(form_frame, bg='#e0f0ff')
        new_frame.pack()
        
        new_entry = tk.Entry(new_frame, textvariable=self.new_password, show='*', 
                            font=('Arial', 12), width=20)
        new_entry.pack(side='left')
        
        tk.Button(new_frame, text="👁", command=lambda: self.toggle_password(new_entry),
                bg='#e0f0ff', fg='black', relief='flat').pack(side='left')
        
        # Confirm Password
        tk.Label(form_frame, text="Confirm New Password:", font=('Arial', 12), 
               bg='#e0f0ff', fg='black').pack(pady=(10, 0))
        
        confirm_frame = tk.Frame(form_frame, bg='#e0f0ff')
        confirm_frame.pack()
        
        confirm_entry = tk.Entry(confirm_frame, textvariable=self.confirm_password, show='*', 
                            font=('Arial', 12), width=20)
        confirm_entry.pack(side='left')
        
        tk.Button(confirm_frame, text="👁", command=lambda: self.toggle_password(confirm_entry),
                bg='#e0f0ff', fg='black', relief='flat').pack(side='left')
        
        # Status label
        self.status_label = tk.Label(main_frame, text="", fg="red", bg='#e0f0ff')
        self.status_label.pack(pady=10)
        
        # Buttons
        button_frame = tk.Frame(main_frame, bg='#e0f0ff', bd=1, relief='sunken', padx=5, pady=5)
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="Change Password", command=self.change_password,
                bg='#57a1f8', fg='black', font=('Arial', 12), width=15).pack(side='left', padx=5)
        
        tk.Button(button_frame, text="Back", command=self.go_back,
                bg='#57a1f8', fg='black', font=('Arial', 12), width=10).pack(side='right', padx=5)
    
    def toggle_password(self, entry):
        if entry.cget('show') == '*':
            entry.config(show='')
        else:
            entry.config(show='*')
    
    def change_password(self):
        username = self.username.get()
        current_pass = self.current_password.get()
        new_pass = self.new_password.get()
        confirm_pass = self.confirm_password.get()
        
        if not all([username, current_pass, new_pass, confirm_pass]):
            self.status_label.config(text="All fields are required")
            return
        
        if len(new_pass) < 12:
            self.status_label.config(text="Password must be at least 12 characters")
            return
        
        if new_pass != confirm_pass:
            self.status_label.config(text="New passwords don't match")
            return
        
        admins = get_admins()
        if username not in admins:
            self.status_label.config(text="Admin not found")
            return
        
        current_hash = hashlib.sha256(current_pass.encode()).hexdigest()
        if current_hash != admins[username]['password']:
            self.status_label.config(text="Current password is incorrect")
            return
        
        # Update password
        admins[username]['password'] = hashlib.sha256(new_pass.encode()).hexdigest()
        save_admins(admins)
        
        self.status_label.config(text="Password changed successfully!", fg="green")
        self.after(2000, self.go_back)
    
    def go_back(self):
        self.destroy()
        AdminSignIn().mainloop()

# ========== ADMIN FORGOT PASSWORD ==========
class AdminForgotPassword(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Admin Password Recovery")
        self.geometry("400x500")
        self.configure(bg='#e0f0ff')
        
        self.username = tk.StringVar()
        self.security_answer = tk.StringVar()
        self.new_password = tk.StringVar()
        self.confirm_password = tk.StringVar()
        
        self.current_question = ""
        
        self.create_widgets()
    
    def create_widgets(self):
        main_frame = tk.Frame(self, bg='#e0f0ff', bd=2, relief='groove', padx=10, pady=10)
        main_frame.pack(pady=20, padx=20, fill='both', expand=True)
        
        tk.Label(main_frame, text="Password Recovery", font=('Arial', 24, 'bold'),
               bg='#e0f0ff', fg='black').pack(pady=20)
        
        # Form container
        form_frame = tk.Frame(main_frame, bg='#e0f0ff', bd=1, relief='sunken', padx=10, pady=10)
        form_frame.pack(pady=10)
        
        # Username
        tk.Label(form_frame, text="Username/Email:", font=('Arial', 12), 
               bg='#e0f0ff', fg='black').pack(pady=(10, 0))
        tk.Entry(form_frame, textvariable=self.username, font=('Arial', 12), width=25).pack(pady=5)
        
        # Security Question
        self.question_label = tk.Label(form_frame, text="Security Question:", font=('Arial', 12), 
               bg='#e0f0ff', fg='black')
        self.question_label.pack(pady=(10, 0))
        
        self.question_text = tk.Label(form_frame, text="[Enter username first]", font=('Arial', 12), 
               bg='#e0f0ff', fg='black', wraplength=300)
        self.question_text.pack(pady=5)
        
        # Security Answer
        tk.Label(form_frame, text="Answer:", font=('Arial', 12), 
               bg='#e0f0ff', fg='black').pack(pady=(10, 0))
        tk.Entry(form_frame, textvariable=self.security_answer, font=('Arial', 12), width=25).pack(pady=5)
        
        # New Password
        tk.Label(form_frame, text="New Password (min 12 chars):", font=('Arial', 12), 
               bg='#e0f0ff', fg='black').pack(pady=(10, 0))
        
        new_frame = tk.Frame(form_frame, bg='#e0f0ff')
        new_frame.pack()
        
        new_entry = tk.Entry(new_frame, textvariable=self.new_password, show='*', 
                            font=('Arial', 12), width=20)
        new_entry.pack(side='left')
        
        tk.Button(new_frame, text="👁", command=lambda: self.toggle_password(new_entry),
                bg='#e0f0ff', fg='black', relief='flat').pack(side='left')
        
        # Confirm Password
        tk.Label(form_frame, text="Confirm New Password:", font=('Arial', 12), 
               bg='#e0f0ff', fg='black').pack(pady=(10, 0))
        
        confirm_frame = tk.Frame(form_frame, bg='#e0f0ff')
        confirm_frame.pack()
        
        confirm_entry = tk.Entry(confirm_frame, textvariable=self.confirm_password, show='*', 
                            font=('Arial', 12), width=20)
        confirm_entry.pack(side='left')
        
        tk.Button(confirm_frame, text="👁", command=lambda: self.toggle_password(confirm_entry),
                bg='#e0f0ff', fg='black', relief='flat').pack(side='left')
        
        # Status label
        self.status_label = tk.Label(main_frame, text="", fg="red", bg='#e0f0ff')
        self.status_label.pack(pady=10)
        
        # Buttons
        button_frame = tk.Frame(main_frame, bg='#e0f0ff', bd=1, relief='sunken', padx=5, pady=5)
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="Verify", command=self.verify_security,
                bg='#57a1f8', fg='black', font=('Arial', 12), width=10).pack(side='left', padx=5)
        
        tk.Button(button_frame, text="Back", command=self.go_back,
                bg='#57a1f8', fg='black', font=('Arial', 12), width=10).pack(side='right', padx=5)
    
    def toggle_password(self, entry):
        if entry.cget('show') == '*':
            entry.config(show='')
        else:
            entry.config(show='*')
    
    def verify_security(self):
        username = self.username.get()
        
        if not username:
            self.status_label.config(text="Please enter your username")
            return
        
        admins = get_admins()
        if username not in admins:
            self.status_label.config(text="Admin not found")
            return
        
        # If we haven't shown the question yet, show it
        if not self.current_question:
            self.current_question = admins[username]['security_question']
            self.question_text.config(text=self.current_question)
            return
        
        # If we have the question, verify the answer
        answer = self.security_answer.get()
        new_pass = self.new_password.get()
        confirm_pass = self.confirm_password.get()
        
        if not answer:
            self.status_label.config(text="Please answer the security question")
            return
        
        stored_hash = admins[username]['security_answer']
        if hashlib.sha256(answer.lower().encode()).hexdigest() != stored_hash:
            self.status_label.config(text="Incorrect security answer")
            return
        
        if not new_pass or not confirm_pass:
            self.status_label.config(text="Please enter and confirm your new password")
            return
        
        if len(new_pass) < 12:
            self.status_label.config(text="Password must be at least 12 characters")
            return
        
        if new_pass != confirm_pass:
            self.status_label.config(text="Passwords don't match")
            return
        
        # Update password
        admins[username]['password'] = hashlib.sha256(new_pass.encode()).hexdigest()
        save_admins(admins)
        
        self.status_label.config(text="Password reset successfully!", fg="green")
        self.after(2000, self.go_back)
    
    def go_back(self):
        self.destroy()
        AdminSignIn().mainloop()

# ========== ADMIN REGISTRATION ==========
class AdminRegister(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Admin Registration")
        self.geometry("500x700")
        self.configure(bg='#e0f0ff')
        
        self.username = tk.StringVar()
        self.email = tk.StringVar()
        self.password = tk.StringVar()
        self.confirm_password = tk.StringVar()
        self.security_question = tk.StringVar()
        self.security_answer = tk.StringVar()
        self.secret_key = tk.StringVar()
        
        self.create_widgets()
    
    def create_widgets(self):
        main_frame = tk.Frame(self, bg='#e0f0ff', bd=2, relief='groove', padx=10, pady=10)
        main_frame.pack(pady=20, padx=20, fill='both', expand=True)
        
        tk.Label(main_frame, text="Admin Registration", font=('Arial', 24, 'bold'),
               bg='#e0f0ff', fg='black').pack(pady=20)
        
        # Form container
        form_frame = tk.Frame(main_frame, bg='#e0f0ff', bd=1, relief='sunken', padx=10, pady=10)
        form_frame.pack(pady=10)
        
        # Username
        tk.Label(form_frame, text="Username (min 8 chars):", font=('Arial', 12), 
               bg='#e0f0ff', fg='black').pack(pady=(10, 0))
        tk.Entry(form_frame, textvariable=self.username, font=('Arial', 12), width=30).pack(pady=5)
        
        # Email
        tk.Label(form_frame, text="Email:", font=('Arial', 12), 
               bg='#e0f0ff', fg='black').pack(pady=(10, 0))
        tk.Entry(form_frame, textvariable=self.email, font=('Arial', 12), width=30).pack(pady=5)
        
        # Password
        tk.Label(form_frame, text="Password (min 12 chars):", font=('Arial', 12), 
               bg='#e0f0ff', fg='black').pack(pady=(10, 0))
        
        password_frame = tk.Frame(form_frame, bg='#e0f0ff')
        password_frame.pack()
        
        password_entry = tk.Entry(password_frame, textvariable=self.password, show='*', 
                            font=('Arial', 12), width=25)
        password_entry.pack(side='left')
        
        tk.Button(password_frame, text="👁", command=lambda: self.toggle_password(password_entry),
                bg='#e0f0ff', fg='black', relief='flat').pack(side='left')
        
        # Confirm Password
        tk.Label(form_frame, text="Confirm Password:", font=('Arial', 12), 
               bg='#e0f0ff', fg='black').pack(pady=(10, 0))
        
        confirm_frame = tk.Frame(form_frame, bg='#e0f0ff')
        confirm_frame.pack()
        
        confirm_entry = tk.Entry(confirm_frame, textvariable=self.confirm_password, show='*', 
                            font=('Arial', 12), width=25)
        confirm_entry.pack(side='left')
        
        tk.Button(confirm_frame, text="👁", command=lambda: self.toggle_password(confirm_entry),
                bg='#e0f0ff', fg='black', relief='flat').pack(side='left')
        
        # Security Question
        tk.Label(form_frame, text="Security Question:", font=('Arial', 12), 
               bg='#e0f0ff', fg='black').pack(pady=(10, 0))
        
        questions = [
            "What was your first pet's name?",
            "What city were you born in?",
            "What is your mother's maiden name?",
            "What was the name of your first school?",
            "What was your childhood nickname?",
    "What is your favorite food?",
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
        
        ttk.Combobox(form_frame, textvariable=self.security_question, 
                    values=questions, width=28).pack(pady=5)
        
        # Security Answer
        tk.Label(form_frame, text="Answer:", font=('Arial', 12), 
               bg='#e0f0ff', fg='black').pack(pady=(10, 0))
        tk.Entry(form_frame, textvariable=self.security_answer, font=('Arial', 12), width=30).pack(pady=5)
        
        # Secret Key
        tk.Label(form_frame, text="Admin Secret Key:", font=('Arial', 12), 
               bg='#e0f0ff', fg='black').pack(pady=(10, 0))
        ttk.Combobox(form_frame, textvariable=self.secret_key, 
                    values=ADMIN_SECRET_KEYS, width=30).pack(pady=5)
        
        # CAPTCHA
        self.captcha_question = random.choice(ADMIN_CAPTCHA_QUESTIONS)
        tk.Label(form_frame, text=f"CAPTCHA: {self.captcha_question['question']}", 
               font=('Arial', 12), bg='#e0f0ff', fg='black').pack(pady=(10, 0))
        self.captcha_answer = tk.Entry(form_frame, font=('Arial', 12), width=30)
        self.captcha_answer.pack(pady=5)
        
        # Status label
        self.status_label = tk.Label(main_frame, text="", fg="red", bg='#e0f0ff')
        self.status_label.pack(pady=10)
        
        # Buttons
        button_frame = tk.Frame(main_frame, bg='#e0f0ff', bd=1, relief='sunken', padx=5, pady=5)
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="Register", command=self.register_admin,
                bg='#57a1f8', fg='black', font=('Arial', 12), width=15).pack(side='left', padx=5)
        
        tk.Button(button_frame, text="Back", command=self.go_back,
                bg='#57a1f8', fg='black', font=('Arial', 12), width=10).pack(side='right', padx=5)
    
    def toggle_password(self, entry):
        if entry.cget('show') == '*':
            entry.config(show='')
        else:
            entry.config(show='*')
    
    def register_admin(self):
        username = self.username.get()
        email = self.email.get()
        password = self.password.get()
        confirm = self.confirm_password.get()
        question = self.security_question.get()
        answer = self.security_answer.get()
        secret_key = self.secret_key.get()
        captcha = self.captcha_answer.get()
        
        if not all([username, email, password, confirm, question, answer, secret_key, captcha]):
            self.status_label.config(text="All fields are required")
            return
        
        if len(username) < 8:
            self.status_label.config(text="Username must be at least 8 characters")
            return
        
        if not validate_email(email):
            self.status_label.config(text="Invalid email format")
            return
        
        if len(password) < 12:
            self.status_label.config(text="Password must be at least 12 characters")
            return
        
        if password != confirm:
            self.status_label.config(text="Passwords don't match")
            return
        
        if secret_key not in ADMIN_SECRET_KEYS:
            self.status_label.config(text="Invalid admin secret key")
            return
        
        if captcha.lower() != self.captcha_question['answer'].lower():
            self.status_label.config(text="Incorrect CAPTCHA answer")
            return
        
        admins = get_admins()
        if username in admins:
            self.status_label.config(text="Admin already exists")
            return
        
        if len(admins) >= MAX_ADMINS:
            self.status_label.config(text=f"Maximum of {MAX_ADMINS} admins reached")
            return
        
        admins[username] = {
            'email': email,
            'password': hash_password(password),
            'security_question': question,
            'security_answer': hash_password(answer.lower()),
            'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'last_login': None,
            'active': True
        }
        
        save_admins(admins)
        self.status_label.config(text="Admin registered successfully!", fg="green")
        self.after(2000, self.go_back)
    
    def go_back(self):
        self.destroy()
        AdminSignIn().mainloop()

# ========== MAIN APPLICATION ==========
if __name__ == "__main__":
    # Create admin file if it doesn't exist
    if not os.path.exists(ADMINS_FILE):
        with open(ADMINS_FILE, 'w') as f:
            json.dump({}, f)
    
    # Start with the sign-in screen
    app = AdminSignIn()
    app.mainloop()