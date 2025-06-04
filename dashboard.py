import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from utils.encryption import verify_pin, verify_password, hash_password
import json
import datetime
import os
import random
import string
import pyperclip
from PIL import Image, ImageTk

class Dashboard(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.dark_mode = False
        self.current_password = None
        self.password_visible = False
        self.passwords = []
        
        # Initialize styling
        self.setup_style()
        self.create_widgets()
        self.pack(fill=tk.BOTH, expand=True)
        
    def setup_style(self):
        self.style = ttk.Style()
        
        # Light mode colors
        self.bg_color = '#ffffff'
        self.fg_color = '#000000'
        self.header_bg = '#003366'  # Dark blue
        self.button_bg = '#003366'
        self.button_fg = '#ffffff'
        self.sidebar_bg = '#f0f0f0'
        self.form_bg = '#f8f9fa'
        self.form_fg = '#212529'
        self.save_button_bg = '#28a745'  # Green
        self.save_button_fg = '#ffffff'
        
        # Configure base style
        self.style.configure('TFrame', background=self.bg_color)
        self.style.configure('TLabel', background=self.bg_color, foreground=self.fg_color, font=('Arial', 10))
        
        # Button styles
        self.style.configure('TButton', 
                           background=self.button_bg, 
                           foreground=self.button_fg, 
                           font=('Arial', 10), 
                           borderwidth=1,
                           padding=5)
        self.style.map('TButton', 
                      background=[('active', '#004488')],
                      foreground=[('active', 'white')])
        
        self.style.configure('Save.TButton', 
                           background=self.save_button_bg, 
                           foreground=self.save_button_fg,
                           font=('Arial', 10, 'bold'),
                           borderwidth=1,
                           padding=5)
        self.style.map('Save.TButton',
                      background=[('active', '#218838')],
                      foreground=[('active', 'white')])
        
        self.style.configure('Cancel.TButton',
                           background='#dc3545',
                           foreground='white',
                           font=('Arial', 10),
                           borderwidth=1,
                           padding=5)
        self.style.map('Cancel.TButton',
                      background=[('active', '#c82333')],
                      foreground=[('active', 'white')])
        
        # Custom styles
        self.style.configure('Form.TFrame', background=self.form_bg)
        self.style.configure('Form.TLabel', background=self.form_bg, foreground=self.form_fg)
        self.style.configure('Form.TEntry', fieldbackground='white')
        self.style.configure('Header.TLabel', font=('Arial', 14, 'bold'))
        self.style.configure('Subheader.TLabel', font=('Arial', 11, 'bold'))
        self.style.configure('Header.TFrame', background=self.header_bg)
        
    def toggle_dark_mode(self):
        self.dark_mode = not self.dark_mode
        self.update_style()
        
    def update_style(self):
        if self.dark_mode:
            self.bg_color = '#2d2d2d'
            self.fg_color = '#ffffff'
            self.header_bg = '#1a1a1a'
            self.button_bg = '#333333'
            self.button_fg = '#ffffff'
            self.sidebar_bg = '#252525'
            self.form_bg = '#333333'
            self.form_fg = '#ffffff'
            self.save_button_bg = '#28a745'
            self.save_button_fg = '#ffffff'
        else:
            self.bg_color = '#ffffff'
            self.fg_color = '#000000'
            self.header_bg = '#003366'
            self.button_bg = '#003366'
            self.button_fg = '#ffffff'
            self.sidebar_bg = '#f0f0f0'
            self.form_bg = '#f8f9fa'
            self.form_fg = '#212529'
            self.save_button_bg = '#28a745'
            self.save_button_fg = '#ffffff'
            
        self.configure(bg=self.bg_color)
        self.header_frame.configure(style='Header.TFrame')
        self.sidebar.configure(style='TFrame')
        self.details_frame.configure(style='Form.TFrame')
        
        for widget in self.winfo_children():
            if isinstance(widget, ttk.Label):
                widget.configure(style='TLabel')
            elif isinstance(widget, ttk.Frame):
                widget.configure(style='TFrame')
                
        self.style.configure('TFrame', background=self.bg_color)
        self.style.configure('TLabel', background=self.bg_color, foreground=self.fg_color)
        self.style.configure('Form.TFrame', background=self.form_bg)
        self.style.configure('Form.TLabel', background=self.form_bg, foreground=self.form_fg)
        self.style.configure('Header.TFrame', background=self.header_bg)
        
    def create_widgets(self):
        self.configure(bg=self.bg_color)
        
        # Header Frame (dark blue)
        self.header_frame = ttk.Frame(self, style='Header.TFrame')
        self.header_frame.pack(fill=tk.X, padx=0, pady=0)
        
        # Logo and Title
        logo_frame = ttk.Frame(self.header_frame, style='Header.TFrame')
        logo_frame.pack(side=tk.LEFT, padx=10, pady=5)
        
        try:
            logo_img = Image.open("logo.png")
            logo_img = logo_img.resize((40, 40), Image.LANCZOS)
            self.logo_photo = ImageTk.PhotoImage(logo_img)
            ttk.Label(logo_frame, image=self.logo_photo, background=self.header_bg).pack(side=tk.LEFT, padx=(0, 10))
        except:
            pass
        
        ttk.Label(
            logo_frame, 
            text="PassShield", 
            font=('Arial', 18, 'bold'),
            foreground='white',
            background=self.header_bg
        ).pack(side=tk.LEFT)
        
        # User Info and Logout
        user_frame = ttk.Frame(self.header_frame, style='Header.TFrame')
        user_frame.pack(side=tk.RIGHT, padx=10, pady=5)
        
        ttk.Label(
            user_frame, 
            text=f"User: {self.app.current_user['username']}", 
            foreground='white',
            background=self.header_bg
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            user_frame,
            text="Logout",
            command=self.app.logout
        ).pack(side=tk.RIGHT)
        
        # Main Content Area
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Sidebar - 25% width
        self.sidebar = ttk.Frame(main_frame, width=int(self.app.winfo_screenwidth()*0.25), style='TFrame')
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 5))
        
        # Saved Passwords Section
        ttk.Label(self.sidebar, text="📂 Saved Passwords", font=('Arial', 11, 'bold')).pack(anchor=tk.W, pady=(0, 5))
        
        # Treeview with Scrollbar
        tree_frame = ttk.Frame(self.sidebar)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(tree_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.tree = ttk.Treeview(
            tree_frame, 
            columns=('Name', 'Type'), 
            show='headings', 
            height=15,
            yscrollcommand=scrollbar.set,
            selectmode='browse'
        )
        self.tree.heading('Name', text='Name')
        self.tree.heading('Type', text='Type')
        self.tree.column('Name', width=120)
        self.tree.column('Type', width=60)
        self.tree.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.tree.yview)
        self.tree.bind('<<TreeviewSelect>>', self.on_password_selected)
        
        # Password Action Buttons
        btn_frame = ttk.Frame(self.sidebar)
        btn_frame.pack(fill=tk.X, pady=(5, 0))
        
        ttk.Button(
            btn_frame,
            text="Copy",
            command=self.copy_password
        ).pack(side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True)
        
        ttk.Button(
            btn_frame,
            text="Delete",
            command=self.delete_password
        ).pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Add New Button
        ttk.Button(
            self.sidebar,
            text="➕ Add New",
            command=self.add_password
        ).pack(fill=tk.X, pady=(10, 5))
        
        # Settings Button
        ttk.Button(
            self.sidebar,
            text="⚙ Settings",
            command=self.show_settings
        ).pack(fill=tk.X, pady=(0, 5))
        
        # Password Details Panel - 75% width
        self.details_frame = ttk.Frame(main_frame, style='Form.TFrame', padding=15)
        self.details_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Welcome Message (fixed at top)
        self.welcome_label = ttk.Label(
            self.details_frame, 
            text="Welcome to PassShield",
            style='Header.TLabel'
        )
        self.welcome_label.pack(anchor=tk.W, pady=(0, 15))
        
        # Password Details Title
        self.details_label = ttk.Label(
            self.details_frame, 
            text="📝 Password Details", 
            style='Subheader.TLabel'
        )
        self.details_label.pack(anchor=tk.W, pady=(0, 10))
        
        # Form Fields
        fields = [
            ("Password Type:", 'Website', ['Website', 'Application', 'Bank Account', 'Credit Card', 'Other']),
            ("Name:", '', None),
            ("Username/Email:", '', None),
            ("Password:", '', None, True),
            ("URL:", '', None),
            ("Notes:", '', None, False, True)
        ]
        
        self.form_fields = {}
        
        for field in fields:
            label_text, default, options, is_password = field[0], field[1], field[2] if len(field) > 2 else None, field[3] if len(field) > 3 else False
            is_textarea = field[4] if len(field) > 4 else False
            
            field_key = label_text.lower().replace(' ', '_').replace(':', '').replace('/', '_').strip('_')
            
            ttk.Label(self.details_frame, text=label_text, style='Form.TLabel').pack(anchor=tk.W, pady=(0, 5))
            
            if options:
                frame = ttk.Frame(self.details_frame)
                frame.pack(fill=tk.X, pady=(0, 10))
                var = tk.StringVar(value=default)
                ttk.OptionMenu(frame, var, *options).pack(fill=tk.X, expand=True)
                self.form_fields[field_key] = var
            elif is_textarea:
                notes_frame = ttk.Frame(self.details_frame)
                notes_frame.pack(fill=tk.X, pady=(0, 10))
                text_widget = tk.Text(notes_frame, height=4, wrap=tk.WORD)
                text_widget.pack(fill=tk.X, expand=True)
                self.form_fields[field_key] = text_widget
            else:
                entry_frame = ttk.Frame(self.details_frame)
                entry_frame.pack(fill=tk.X, pady=(0, 10))
                
                entry = ttk.Entry(entry_frame, show="•" if is_password else "")
                entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
                self.form_fields[field_key] = entry
                
                if is_password:
                    # Create eye icons for show/hide password
                    try:
                        # Create open eye icon (white)
                        eye_open_img = Image.new('RGBA', (20, 20), (0, 0, 0, 0))
                        for i in range(5, 15):
                            eye_open_img.putpixel((i, 5), (255, 255, 255, 255))
                            eye_open_img.putpixel((i, 15), (255, 255, 255, 255))
                        for i in range(5, 15):
                            eye_open_img.putpixel((5, i), (255, 255, 255, 255))
                            eye_open_img.putpixel((15, i), (255, 255, 255, 255))
                        self.eye_open = ImageTk.PhotoImage(eye_open_img)
                        
                        # Create closed eye icon (white)
                        eye_closed_img = Image.new('RGBA', (20, 20), (0, 0, 0, 0))
                        for i in range(5, 15):
                            eye_closed_img.putpixel((i, 10), (255, 255, 255, 255))
                        self.eye_closed = ImageTk.PhotoImage(eye_closed_img)
                    except:
                        # Fallback if image creation fails
                        self.eye_open = None
                        self.eye_closed = None
                    
                    # Add show/hide button
                    self.toggle_btn = ttk.Button(
                        entry_frame,
                        image=self.eye_closed if self.eye_closed else None,
                        command=lambda e=entry: self.toggle_password_visibility(e),
                        style='TButton',
                        width=0
                    )
                    self.toggle_btn.pack(side=tk.RIGHT, padx=(5, 0))
                    
                    # Add generate button
                    gen_btn = ttk.Button(
                        entry_frame,
                        text="Generate",
                        command=lambda e=entry: self.generate_password(e),
                        style='TButton',
                        width=8
                    )
                    gen_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        # Action Buttons (fixed size)
        btn_frame = ttk.Frame(self.details_frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(
            btn_frame,
            text="Save",
            style='Save.TButton',
            command=self.save_password
        ).pack(side=tk.LEFT, padx=(0, 10), expand=True, fill=tk.X)
        
        ttk.Button(
            btn_frame,
            text="Cancel",
            style='Cancel.TButton',
            command=self.clear_form
        ).pack(side=tk.LEFT, expand=True, fill=tk.X)
        
        # Load initial data
        self.load_passwords()
        
    def toggle_password_visibility(self, entry):
        if self.password_visible:
            entry.config(show="•")
            if hasattr(self, 'eye_closed'):
                self.toggle_btn.config(image=self.eye_closed)
            self.password_visible = False
        else:
            entry.config(show="")
            if hasattr(self, 'eye_open'):
                self.toggle_btn.config(image=self.eye_open)
            self.password_visible = True
            
    def generate_password(self, entry):
        length = 16
        chars = string.ascii_letters + string.digits + "!@#$%^&*()"
        password = ''.join(random.choice(chars) for _ in range(length))
        entry.delete(0, tk.END)
        entry.insert(0, password)
        
    def on_password_selected(self, event):
        selected = self.tree.focus()
        if selected:
            item = self.tree.item(selected)
            password_id = item['tags'][0] if item['tags'] else None
            if password_id:
                password_data = self.get_password_data(password_id)
                if password_data:
                    self.current_password = password_data
                    self.display_password_details(password_data)
                    
    def display_password_details(self, password_data):
        # Keep welcome label visible but update details
        self.details_label.config(text="📝 Password Details")
        
        for field, widget in self.form_fields.items():
            if field in password_data:
                if isinstance(widget, tk.Text):
                    widget.delete(1.0, tk.END)
                    widget.insert(1.0, password_data[field])
                elif isinstance(widget, ttk.Entry):
                    widget.delete(0, tk.END)
                    widget.insert(0, password_data[field])
                elif isinstance(widget, tk.StringVar):
                    widget.set(password_data[field])
            elif field == 'password_type':
                widget.set('Website')
                    
    def clear_form(self):
        self.current_password = None
        self.details_label.config(text="📝 Password Details")
        
        for field, widget in self.form_fields.items():
            if isinstance(widget, tk.Text):
                widget.delete(1.0, tk.END)
            elif isinstance(widget, ttk.Entry):
                widget.delete(0, tk.END)
            elif isinstance(widget, tk.StringVar):
                if field == 'password_type':
                    widget.set('Website')
                else:
                    widget.set('')
                    
    def save_password(self):
        password_data = {
            'id': str(datetime.datetime.now().timestamp()),
            'type': self.form_fields['password_type'].get(),
            'name': self.form_fields['name'].get(),
            'username_email': self.form_fields['username_email'].get(),
            'password': self.form_fields['password'].get(),
            'url': self.form_fields['url'].get(),
            'notes': self.form_fields['notes'].get("1.0", tk.END).strip(),
            'created_at': str(datetime.datetime.now()),
            'updated_at': str(datetime.datetime.now())
        }
        
        if not password_data['name'] or not password_data['password']:
            messagebox.showerror("Error", "Name and Password are required fields")
            return
            
        if self.current_password:
            # Update existing password
            for i, pwd in enumerate(self.passwords):
                if pwd['id'] == self.current_password['id']:
                    password_data['id'] = self.current_password['id']
                    password_data['created_at'] = self.current_password['created_at']
                    self.passwords[i] = password_data
                    break
        else:
            # Add new password
            self.passwords.append(password_data)
            
        self.save_passwords_to_file()
        self.load_passwords()
        self.clear_form()
        messagebox.showinfo("Success", "Password saved successfully")
        
    def copy_password(self):
        selected = self.tree.focus()
        if selected:
            item = self.tree.item(selected)
            password_id = item['tags'][0] if item['tags'] else None
            if password_id:
                password_data = self.get_password_data(password_id)
                if password_data:
                    pyperclip.copy(password_data['password'])
                    messagebox.showinfo("Copied", "Password copied to clipboard")
                    
    def delete_password(self):
        selected = self.tree.focus()
        if selected:
            item = self.tree.item(selected)
            password_id = item['tags'][0] if item['tags'] else None
            if password_id:
                if messagebox.askyesno("Confirm", "Are you sure you want to delete this password?"):
                    self.passwords = [pwd for pwd in self.passwords if pwd['id'] != password_id]
                    self.save_passwords_to_file()
                    self.load_passwords()
                    self.clear_form()
                    
    def add_password(self):
        self.clear_form()
        
    def show_settings(self):
        settings_window = tk.Toplevel(self)
        settings_window.title("Settings")
        settings_window.geometry("400x300")
        
        ttk.Label(settings_window, text="Settings", font=('Arial', 14, 'bold')).pack(pady=10)
        
        # Dark Mode Toggle
        dark_mode_frame = ttk.Frame(settings_window)
        dark_mode_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(dark_mode_frame, text="Dark Mode:").pack(side=tk.LEFT)
        self.dark_mode_var = tk.BooleanVar(value=self.dark_mode)
        ttk.Checkbutton(
            dark_mode_frame,
            variable=self.dark_mode_var,
            command=self.toggle_dark_mode
        ).pack(side=tk.RIGHT)
        
        # Export Button
        ttk.Button(
            settings_window,
            text="Export Passwords",
            command=self.export_passwords
        ).pack(fill=tk.X, padx=20, pady=10)
        
        # Import Button
        ttk.Button(
            settings_window,
            text="Import Passwords",
            command=self.import_passwords
        ).pack(fill=tk.X, padx=20, pady=10)
        
        # Change Master Password Button
        ttk.Button(
            settings_window,
            text="Change Master Password",
            command=self.change_master_password
        ).pack(fill=tk.X, padx=20, pady=10)
        
    def export_passwords(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump(self.passwords, f, indent=4)
                messagebox.showinfo("Success", "Passwords exported successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export passwords: {str(e)}")
                
    def import_passwords(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    imported = json.load(f)
                if isinstance(imported, list):
                    self.passwords = imported
                    self.save_passwords_to_file()
                    self.load_passwords()
                    messagebox.showinfo("Success", "Passwords imported successfully")
                else:
                    messagebox.showerror("Error", "Invalid password file format")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to import passwords: {str(e)}")
                
    def change_master_password(self):
        new_password = simpledialog.askstring(
            "Change Master Password",
            "Enter new master password:",
            show='*'
        )
        if new_password:
            confirm_password = simpledialog.askstring(
                "Confirm Password",
                "Confirm new master password:",
                show='*'
            )
            if new_password == confirm_password:
                self.app.change_master_password(new_password)
                messagebox.showinfo("Success", "Master password changed successfully")
            else:
                messagebox.showerror("Error", "Passwords do not match")
                
    def load_passwords(self):
        self.tree.delete(*self.tree.get_children())
        try:
            user_dir = os.path.join('data', self.app.current_user['username'])
            os.makedirs(user_dir, exist_ok=True)
            password_file = os.path.join(user_dir, 'passwords.json')
            
            if os.path.exists(password_file):
                with open(password_file, 'r') as f:
                    self.passwords = json.load(f)
            else:
                self.passwords = []
                
            for pwd in self.passwords:
                self.tree.insert(
                    '',
                    'end',
                    values=(pwd['name'], pwd['type']),
                    tags=(pwd['id'])
                )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load passwords: {str(e)}")
            self.passwords = []
            
    def save_passwords_to_file(self):
        try:
            user_dir = os.path.join('data', self.app.current_user['username'])
            os.makedirs(user_dir, exist_ok=True)
            password_file = os.path.join(user_dir, 'passwords.json')
            
            with open(password_file, 'w') as f:
                json.dump(self.passwords, f, indent=4)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save passwords: {str(e)}")
            
    def get_password_data(self, password_id):
        for pwd in self.passwords:
            if pwd['id'] == password_id:
                return pwd
        return None