# main.py - Main entry point for the application
import tkinter as tk
from tkinter import messagebox, simpledialog
from admin import AdminSignIn  # Ensure this is correctly implemented
from ui import PassShieldApp  # Import the corrected class
import os
import json

def choose_mode():
    temp_root = tk.Tk()
    temp_root.withdraw()
    mode = simpledialog.askstring("Mode Selection", "Enter 'admin' or 'user':")
    temp_root.destroy()

    if not mode:
        return

    mode = mode.strip().lower()
    if mode == "admin":
        admin_app = AdminSignIn()
        admin_app.mainloop()
    elif mode == "user":
        user_app = PassShieldApp()  # Create instance of the corrected class
        user_app.mainloop()
    else:
        messagebox.showerror("Error", "Invalid mode. Please enter 'admin' or 'user'.")
        choose_mode()

if __name__ == "__main__":
    # Initialize necessary files
    if not os.path.exists('admins.json'):
        with open('admins.json', 'w') as f:
            json.dump({}, f)
            
    if not os.path.exists('users.json'):
        with open('users.json', 'w') as f:
            json.dump({}, f)
    
    choose_mode()