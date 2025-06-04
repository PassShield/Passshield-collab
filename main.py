import tkinter as tk
from tkinter import ttk
from screens.login_screen import LoginScreen
from screens.forgot_password import ForgotPasswordScreen
from screens.signup_screen import SignupScreen
from screens.dashboard import Dashboard


class PassShieldApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PassShield Desktop Manager")
        self.geometry("1000x700")
        self.resizable(True, True)
        self.current_user = None
        self.dark_mode = False
        
        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Create container frame
        self.container = tk.Frame(self)
        self.container.pack(side="top", fill="both", expand=True)
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)
        
        # Dictionary to hold frames
        self.frames = {}
        
        # Initialize all frames
        for F in (LoginScreen, ForgotPasswordScreen, SignupScreen):
            if F == SignupScreen:
                frame = F(self.container, self, LoginScreen)  # Pass LoginScreen as login_screen_class
            else:
                frame = F(self.container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        
        # Show login screen first
        self.show_frame(LoginScreen)
    
    def show_frame(self, cont):
        """Show a frame for the given class"""
        frame = self.frames[cont]
        frame.tkraise()
    
    def switch_to_frame(self, frame_class):
        """Switch to another frame"""
        self.show_frame(frame_class)
    
    def show_dashboard(self, user_data):
        """Show the dashboard screen"""
        self.current_user = user_data
        
        # Destroy all existing frames
        for frame in self.frames.values():
            frame.destroy()
        
        # Create and show dashboard
        self.dashboard = Dashboard(self.container, self)
        self.dashboard.grid(row=0, column=0, sticky="nsew")
        self.dashboard.tkraise()
    
    def logout(self):
        """Logout and return to login screen"""
        self.current_user = None
        if hasattr(self, 'dashboard'):
            self.dashboard.destroy()
        
        # Reinitialize frames
        self.frames = {}
        for F in (LoginScreen, ForgotPasswordScreen, SignupScreen):
            if F == SignupScreen:
                frame = F(self.container, self, LoginScreen)  # Pass LoginScreen as login_screen_class
            else:
                frame = F(self.container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        
        self.show_frame(LoginScreen)
    
    def toggle_dark_mode(self):
        """Toggle dark mode"""
        self.dark_mode = not self.dark_mode
        if hasattr(self, 'dashboard'):
            self.dashboard.toggle_dark_mode()


if __name__ == "__main__":
    app = PassShieldApp()
    app.mainloop()