import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import random
import string
import pyperclip
import json
import os
import hashlib
import sqlite3
from datetime import datetime, timedelta
from PIL import Image, ImageTk
import base64
import secrets

class SecurePassManager:
    def __init__(self, root):
        self.root = root
        self.root.title("SecurePass Manager")
        self.root.geometry("1000x750")
        self.root.minsize(900, 700)
        
        # Initialize database
        self.db_file = "securepass.db"
        self.init_db()
        
        # Security parameters
        self.salt_length = 32
        self.hash_iterations = 100000
        
        # UI Colors and Theme
        self.bg_color = '#f0f5f9'
        self.primary_color = '#1e56a0'
        self.secondary_color = '#163172'
        self.accent_color = '#d6e4f0'
        self.text_color = '#333333'
        self.success_color = '#28a745'
        self.warning_color = '#ffc107'
        self.danger_color = '#dc3545'
        
        # Current user state
        self.current_user = None
        
        # Configure styles
        self.setup_styles()
        
        # Load images
        self.load_images()
        
        # Create authentication UI
        self.create_auth_ui()
        
        # Schedule periodic tasks
        self.root.after(1000, self.periodic_tasks)
    
    def init_db(self):
        """Initialize the SQLite database with secure schema"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_login TEXT
        )
        ''')
        
        # Passwords table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            password TEXT NOT NULL,
            strength TEXT NOT NULL,
            length INTEGER NOT NULL,
            character_sets TEXT NOT NULL,
            created_at TEXT NOT NULL,
            bookmarked INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_id ON passwords(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_bookmarked ON passwords(bookmarked)')
        
        conn.commit()
        conn.close()
    
    def setup_styles(self):
        """Configure application styles"""
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure colors
        self.style.configure('.', 
                           background=self.bg_color,
                           foreground=self.text_color)
        
        # Frame styles
        self.style.configure('TFrame', background=self.bg_color)
        self.style.configure('Auth.TFrame', background=self.accent_color)
        self.style.configure('Card.TFrame', 
                           background='white',
                           relief=tk.RAISED,
                           borderwidth=2)
        
        # Label styles
        self.style.configure('TLabel', 
                           font=('Segoe UI', 10),
                           background=self.bg_color)
        self.style.configure('Header.TLabel', 
                           font=('Segoe UI', 18, 'bold'),
                           foreground=self.primary_color)
        self.style.configure('Secondary.TLabel',
                           foreground=self.secondary_color)
        
        # Button styles
        self.style.configure('TButton',
                           font=('Segoe UI', 10),
                           padding=6)
        self.style.configure('Primary.TButton',
                           background=self.primary_color,
                           foreground='white')
        self.style.configure('Success.TButton',
                           background=self.success_color,
                           foreground='white')
        self.style.configure('Danger.TButton',
                           background=self.danger_color,
                           foreground='white')
        
        # Entry styles
        self.style.configure('TEntry',
                           font=('Segoe UI', 10),
                           padding=5)
        
        # Notebook styles
        self.style.configure('TNotebook', background=self.bg_color)
        self.style.configure('TNotebook.Tab', 
                           font=('Segoe UI', 10),
                           padding=[10, 5])
        
        # Progressbar style
        self.style.configure('Strength.Horizontal.TProgressbar',
                           troughcolor=self.bg_color,
                           background=self.primary_color)
    
    def load_images(self):
        """Load and prepare images for the UI"""
        try:
            # Create a simple gradient background image
            self.bg_image = Image.new('RGB', (100, 100), self.accent_color)
            self.bg_photo = ImageTk.PhotoImage(self.bg_image)
            
            # Logo image (placeholder)
            self.logo_image = Image.new('RGB', (64, 64), self.primary_color)
            self.logo_photo = ImageTk.PhotoImage(self.logo_image)
        except:
            # Fallback if PIL is not available
            self.bg_photo = None
            self.logo_photo = None
    
    def create_auth_ui(self):
        """Create authentication UI (login/signup)"""
        self.clear_window()
        
        # Background frame
        bg_frame = ttk.Frame(self.root)
        bg_frame.pack(fill=tk.BOTH, expand=True)
        
        # Add background image if available
        if self.bg_photo:
            bg_label = tk.Label(bg_frame, image=self.bg_photo)
            bg_label.place(x=0, y=0, relwidth=1, relheight=1)
        
        # Auth card container
        auth_frame = ttk.Frame(bg_frame, style='Card.TFrame')
        auth_frame.place(relx=0.5, rely=0.5, anchor='center', width=400)
        
        # Logo and header
        logo_frame = ttk.Frame(auth_frame)
        logo_frame.pack(pady=20)
        
        if self.logo_photo:
            ttk.Label(logo_frame, image=self.logo_photo).pack()
        
        ttk.Label(logo_frame, 
                 text="SecurePass Manager", 
                 style='Header.TLabel').pack(pady=10)
        
        # Notebook for login/signup tabs
        self.auth_notebook = ttk.Notebook(auth_frame)
        self.auth_notebook.pack(fill=tk.BOTH, padx=20, pady=(0, 20))
        
        # Login tab
        self.create_login_tab()
        
        # Signup tab
        self.create_signup_tab()
    
    def create_login_tab(self):
        """Create the login tab"""
        login_frame = ttk.Frame(self.auth_notebook)
        self.auth_notebook.add(login_frame, text="Login")
        
        # Username field
        ttk.Label(login_frame, text="Username:").pack(anchor='w', pady=(10, 0))
        self.login_username = ttk.Entry(login_frame)
        self.login_username.pack(fill=tk.X, pady=5)
        
        # Password field
        ttk.Label(login_frame, text="Password:").pack(anchor='w', pady=(10, 0))
        self.login_password = ttk.Entry(login_frame, show="•")
        self.login_password.pack(fill=tk.X, pady=5)
        
        # Remember me checkbox
        self.remember_me = tk.BooleanVar()
        ttk.Checkbutton(login_frame, 
                       text="Remember me", 
                       variable=self.remember_me).pack(anchor='w', pady=5)
        
        # Login button
        ttk.Button(login_frame, 
                  text="Login", 
                  style='Primary.TButton',
                  command=self.handle_login).pack(fill=tk.X, pady=10)
        
        # Focus on username field
        self.login_username.focus()
    
    def create_signup_tab(self):
        """Create the signup tab"""
        signup_frame = ttk.Frame(self.auth_notebook)
        self.auth_notebook.add(signup_frame, text="Sign Up")
        
        # Username field
        ttk.Label(signup_frame, text="Username:").pack(anchor='w', pady=(10, 0))
        self.signup_username = ttk.Entry(signup_frame)
        self.signup_username.pack(fill=tk.X, pady=5)
        
        # Password field
        ttk.Label(signup_frame, text="Password:").pack(anchor='w', pady=(10, 0))
        self.signup_password = ttk.Entry(signup_frame, show="•")
        self.signup_password.pack(fill=tk.X, pady=5)
        
        # Confirm password field
        ttk.Label(signup_frame, text="Confirm Password:").pack(anchor='w', pady=(10, 0))
        self.signup_confirm = ttk.Entry(signup_frame, show="•")
        self.signup_confirm.pack(fill=tk.X, pady=5)
        
        # Signup button
        ttk.Button(signup_frame, 
                  text="Create Account", 
                  style='Success.TButton',
                  command=self.handle_signup).pack(fill=tk.X, pady=10)
    
    def create_main_ui(self):
        """Create the main application UI after login"""
        self.clear_window()
        
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header_frame = ttk.Frame(main_frame, style='Card.TFrame')
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Logo and title
        logo_frame = ttk.Frame(header_frame)
        logo_frame.pack(side=tk.LEFT, padx=10)
        
        if self.logo_photo:
            ttk.Label(logo_frame, image=self.logo_photo).pack()
        
        ttk.Label(logo_frame, 
                 text="SecurePass Manager", 
                 style='Header.TLabel').pack()
        
        # User info and logout
        user_frame = ttk.Frame(header_frame)
        user_frame.pack(side=tk.RIGHT, padx=10)
        
        ttk.Label(user_frame, 
                 text=f"Welcome, {self.current_user}",
                 style='Secondary.TLabel').pack(anchor='e')
        
        ttk.Button(user_frame,
                 text="Logout",
                 style='Danger.TButton',
                 command=self.logout).pack(anchor='e', pady=5)
        
        # Main content
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Generator tab
        self.create_generator_tab()
        
        # History tab
        self.create_history_tab()
        
        # Settings tab
        self.create_settings_tab()
    
    def create_generator_tab(self):
        """Create password generator tab"""
        gen_frame = ttk.Frame(self.notebook)
        self.notebook.add(gen_frame, text="Generator")
        
        # Settings frame
        settings_frame = ttk.LabelFrame(gen_frame, text="Settings", padding=15)
        settings_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Length control
        length_frame = ttk.Frame(settings_frame)
        length_frame.pack(fill=tk.X, pady=5)
        ttk.Label(length_frame, text="Password Length:").pack(side=tk.LEFT)
        self.length_var = tk.IntVar(value=16)
        self.length_slider = ttk.Scale(length_frame, from_=8, to=64, variable=self.length_var, 
                                     command=lambda e: self.length_display.config(text=str(self.length_var.get())))
        self.length_slider.pack(side=tk.LEFT, padx=10, expand=True, fill=tk.X)
        self.length_display = ttk.Label(length_frame, text="16", width=3)
        self.length_display.pack(side=tk.LEFT)
        
        # Character sets
        options_frame = ttk.Frame(settings_frame)
        options_frame.pack(fill=tk.X, pady=10)
        
        self.upper_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Uppercase (A-Z)", variable=self.upper_var).pack(side=tk.LEFT, padx=10)
        
        self.lower_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Lowercase (a-z)", variable=self.lower_var).pack(side=tk.LEFT, padx=10)
        
        self.digits_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Digits (0-9)", variable=self.digits_var).pack(side=tk.LEFT, padx=10)
        
        self.special_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Special (!@#\$)", variable=self.special_var).pack(side=tk.LEFT, padx=10)
        
        # Password display
        result_frame = ttk.LabelFrame(gen_frame, text="Generated Password", padding=15)
        result_frame.pack(fill=tk.X, pady=10)
        
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(result_frame, textvariable=self.password_var, 
                                      font=('Consolas', 14), state='readonly')
        self.password_entry.pack(fill=tk.X, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(result_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, 
                  text="Generate", 
                  style='Primary.TButton',
                  command=self.generate_password).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, 
                  text="Copy", 
                  command=self.copy_to_clipboard).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, 
                  text="Save", 
                  style='Success.TButton',
                  command=self.save_to_history).pack(side=tk.LEFT, padx=5)
        
        # Strength meter
        strength_frame = ttk.Frame(result_frame)
        strength_frame.pack(fill=tk.X, pady=5)
        ttk.Label(strength_frame, text="Strength:").pack(side=tk.LEFT)
        self.strength_bar = ttk.Progressbar(strength_frame, length=200, style='Strength.Horizontal.TProgressbar')
        self.strength_bar.pack(side=tk.LEFT, padx=10)
        self.strength_label = ttk.Label(strength_frame, text="")
        self.strength_label.pack(side=tk.LEFT)
        
        # Password details
        details_frame = ttk.Frame(result_frame)
        details_frame.pack(fill=tk.X, pady=5)
        self.detail_label = ttk.Label(details_frame, text="", style='Secondary.TLabel')
        self.detail_label.pack()
        
        # Generate initial password
        self.generate_password()
    
    def create_history_tab(self):
        """Create password history tab"""
        hist_frame = ttk.Frame(self.notebook)
        self.notebook.add(hist_frame, text="History")
        
        # Toolbar
        toolbar_frame = ttk.Frame(hist_frame)
        toolbar_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(toolbar_frame, 
                  text="Refresh", 
                  command=self.load_history_display).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(toolbar_frame, 
                  text="Export Selected", 
                  command=self.export_passwords).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(toolbar_frame, 
                  text="Delete Selected", 
                  style='Danger.TButton',
                  command=self.delete_selected_passwords).pack(side=tk.LEFT, padx=5)
        
        # Search frame
        search_frame = ttk.Frame(hist_frame)
        search_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        self.search_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        self.search_entry.bind('<KeyRelease>', lambda e: self.load_history_display())
        
        # Filter options
        self.filter_var = tk.StringVar(value="all")
        ttk.Radiobutton(search_frame, text="All", variable=self.filter_var, 
                       value="all", command=self.load_history_display).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(search_frame, text="Bookmarked", variable=self.filter_var, 
                       value="bookmarked", command=self.load_history_display).pack(side=tk.LEFT, padx=5)
        
        # History display
        self.history_tree = ttk.Treeview(hist_frame, columns=('date', 'password', 'strength', 'bookmarked'), 
                                       selectmode='extended', show='headings')
        self.history_tree.heading('date', text='Date')
        self.history_tree.heading('password', text='Password')
        self.history_tree.heading('strength', text='Strength')
        self.history_tree.heading('bookmarked', text='Bookmarked')
        
        self.history_tree.column('date', width=150)
        self.history_tree.column('password', width=200)
        self.history_tree.column('strength', width=100)
        self.history_tree.column('bookmarked', width=80)
        
        vsb = ttk.Scrollbar(hist_frame, orient="vertical", command=self.history_tree.yview)
        hsb = ttk.Scrollbar(hist_frame, orient="horizontal", command=self.history_tree.xview)
        self.history_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.history_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Add double-click to toggle bookmark
        self.history_tree.bind('<Double-1>', self.toggle_bookmark)
        
        # Load history
        self.load_history_display()
    
    def create_settings_tab(self):
        """Create settings tab"""
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="Settings")
        
        # Account settings
        account_frame = ttk.LabelFrame(settings_frame, text="Account", padding=15)
        account_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(account_frame, text="Change Password").pack(anchor='w', pady=(5, 0))
        
        # Current password
        ttk.Label(account_frame, text="Current Password:").pack(anchor='w', pady=(10, 0))
        self.current_pass = ttk.Entry(account_frame, show="•")
        self.current_pass.pack(fill=tk.X, pady=5)
        
        # New password
        ttk.Label(account_frame, text="New Password:").pack(anchor='w', pady=(10, 0))
        self.new_pass = ttk.Entry(account_frame, show="•")
        self.new_pass.pack(fill=tk.X, pady=5)
        
        # Confirm new password
        ttk.Label(account_frame, text="Confirm New Password:").pack(anchor='w', pady=(10, 0))
        self.confirm_pass = ttk.Entry(account_frame, show="•")
        self.confirm_pass.pack(fill=tk.X, pady=5)
        
        # Change password button
        ttk.Button(account_frame, 
                  text="Change Password", 
                  style='Primary.TButton',
                  command=self.change_password).pack(fill=tk.X, pady=10)
        
        # App settings
        app_frame = ttk.LabelFrame(settings_frame, text="Application", padding=15)
        app_frame.pack(fill=tk.X, pady=10)
        
        # Auto-clear clipboard
        self.auto_clear = tk.BooleanVar(value=True)
        ttk.Checkbutton(app_frame, 
                       text="Auto-clear clipboard after 30 seconds", 
                       variable=self.auto_clear).pack(anchor='w')
        
        # Auto-logout
        self.auto_logout = tk.BooleanVar(value=True)
        ttk.Checkbutton(app_frame, 
                       text="Auto-logout after 15 minutes of inactivity", 
                       variable=self.auto_logout).pack(anchor='w', pady=(10, 0))
    
    def generate_password(self):
        """Generate a random password based on current settings"""
        char_sets = []
        if self.upper_var.get():
            char_sets.append(string.ascii_uppercase)
        if self.lower_var.get():
            char_sets.append(string.ascii_lowercase)
        if self.digits_var.get():
            char_sets.append(string.digits)
        if self.special_var.get():
            char_sets.append('!@#$%^&*()_+-=[]{}|;:,.<>?')
        
        if not char_sets:
            messagebox.showerror("Error", "Please select at least one character set")
            return
        
        all_chars = ''.join(char_sets)
        length = self.length_var.get()
        
        password = []
        for char_set in char_sets:
            password.append(random.choice(char_set))
        
        remaining_length = length - len(password)
        password.extend(secrets.choice(all_chars) for _ in range(remaining_length))
        random.shuffle(password)
        
        password_str = ''.join(password)
        self.password_var.set(password_str)
        self.update_strength_meter(password_str)
        
        # Update details
        details = []
        if self.upper_var.get():
            details.append("Uppercase")
        if self.lower_var.get():
            details.append("Lowercase")
        if self.digits_var.get():
            details.append("Digits")
        if self.special_var.get():
            details.append("Special")
        
        self.detail_label.config(text=f"Length: {length} | Character sets: {', '.join(details)}")
    
    def update_strength_meter(self, password):
        """Update the password strength meter"""
        length = len(password)
        complexity = sum([self.upper_var.get(), self.lower_var.get(), 
                         self.digits_var.get(), self.special_var.get()])
        
        strength = min(100, (length * 2) + (complexity * 15))
        self.strength_bar['value'] = strength
        
        if strength < 40:
            strength_text = "Weak"
            style = 'Danger.TLabel'
        elif strength < 70:
            strength_text = "Medium"
            style = 'Warning.TLabel'
        else:
            strength_text = "Strong"
            style = 'Success.TLabel'
        
        self.strength_label.config(text=strength_text, style=style)
    
    def copy_to_clipboard(self):
        """Copy current password to clipboard"""
        password = self.password_var.get()
        if password:
            pyperclip.copy(password)
            messagebox.showinfo("Success", "Password copied to clipboard!")
            
            # Schedule clipboard clearing if enabled
            if self.auto_clear.get():
                self.root.after(30000, self.clear_clipboard)
        else:
            messagebox.showerror("Error", "No password to copy")
    
    def clear_clipboard(self):
        """Clear the clipboard"""
        pyperclip.copy('')
    
    def save_to_history(self):
        """Save current password to user's history"""
        password = self.password_var.get()
        if not password:
            messagebox.showerror("Error", "No password to save")
            return
        
        # Get current strength
        strength = self.get_strength_text(self.strength_bar['value'])
        
        # Get character sets used
        char_sets = []
        if self.upper_var.get():
            char_sets.append("upper")
        if self.lower_var.get():
            char_sets.append("lower")
        if self.digits_var.get():
            char_sets.append("digits")
        if self.special_var.get():
            char_sets.append("special")
        
        # Save to database
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Get user ID
        cursor.execute("SELECT id FROM users WHERE username = ?", (self.current_user,))
        user_id = cursor.fetchone()[0]
        
        # Insert password
        cursor.execute('''
        INSERT INTO passwords 
        (user_id, password, strength, length, character_sets, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, password, strength, self.length_var.get(), 
             ','.join(char_sets), datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        # Refresh history display
        self.load_history_display()
        messagebox.showinfo("Saved", "Password added to your history")
    
    def load_history_display(self):
        """Load password history from database"""
        if not self.current_user:
            return
        
        # Clear current display
        self.history_tree.delete(*self.history_tree.get_children())
        
        # Get user ID
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute("SELECT id FROM users WHERE username = ?", (self.current_user,))
        user_id = cursor.fetchone()[0]
        
        # Build query based on filters
        query = '''
        SELECT password, strength, created_at, bookmarked 
        FROM passwords 
        WHERE user_id = ?
        '''
        params = [user_id]
        
        # Apply search filter
        search_term = self.search_var.get()
        if search_term:
            query += " AND password LIKE ?"
            params.append(f"%{search_term}%")
        
        # Apply bookmark filter
        if self.filter_var.get() == "bookmarked":
            query += " AND bookmarked = 1"
        
        query += " ORDER BY created_at DESC"
        
        # Execute query
        cursor.execute(query, params)
        results = cursor.fetchall()
        conn.close()
        
        # Populate treeview
        for password, strength, created_at, bookmarked in results:
            date = datetime.fromisoformat(created_at).strftime('%Y-%m-%d %H:%M')
            bookmark_symbol = "★" if bookmarked else ""
            
            self.history_tree.insert('', 'end', 
                                   values=(date, password, strength, bookmark_symbol),
                                   tags=('bookmarked' if bookmarked else ''))
        
        self.history_tree.tag_configure('bookmarked', foreground='gold')
    
    def toggle_bookmark(self, event):
        """Toggle bookmark status of selected password"""
        item = self.history_tree.selection()[0]
        values = self.history_tree.item(item, 'values')
        
        # Get password and current status
        password = values[1]
        current_status = values[3] == "★"
        new_status = not current_status
        
        # Update database
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
        UPDATE passwords 
        SET bookmarked = ?
        WHERE password = ? AND user_id = (
            SELECT id FROM users WHERE username = ?
        )
        ''', (new_status, password, self.current_user))
        
        conn.commit()
        conn.close()
        
        # Update display
        self.load_history_display()
    
    def export_passwords(self):
        """Export selected passwords to clipboard"""
        selected = self.history_tree.selection()
        if not selected:
            messagebox.showerror("Error", "No passwords selected")
            return
        
        export_text = ""
        for item in selected:
            values = self.history_tree.item(item, 'values')
            export_text += f"{values[0]} | {values[1]} | {values[2]}\n"
        
        pyperclip.copy(export_text)
        messagebox.showinfo("Exported", "Selected passwords copied to clipboard")
    
    def delete_selected_passwords(self):
        """Delete selected passwords from history"""
        selected = self.history_tree.selection()
        if not selected:
            messagebox.showerror("Error", "No passwords selected")
            return
        
        # Confirm deletion
        if not messagebox.askyesno("Confirm", 
                                 f"Delete {len(selected)} password(s) from your history?"):
            return
        
        # Get passwords to delete
        passwords_to_delete = []
        for item in selected:
            values = self.history_tree.item(item, 'values')
            passwords_to_delete.append(values[1])
        
        # Delete from database
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute("SELECT id FROM users WHERE username = ?", (self.current_user,))
        user_id = cursor.fetchone()[0]
        
        cursor.executemany('''
        DELETE FROM passwords 
        WHERE password = ? AND user_id = ?
        ''', [(pwd, user_id) for pwd in passwords_to_delete])
        
        conn.commit()
        conn.close()
        
        # Refresh display
        self.load_history_display()
        messagebox.showinfo("Deleted", f"Removed {len(selected)} password(s)")
    
    def handle_login(self):
        """Handle user login"""
        username = self.login_username.get()
        password = self.login_password.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
        
        # Verify credentials
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT salt, password_hash FROM users WHERE username = ?
        ''', (username,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            messagebox.showerror("Error", "Invalid username or password")
            return
        
        salt, stored_hash = result
        
        # Hash provided password with stored salt
        hashed_password = self.hash_password(password, salt)
        
        if hashed_password == stored_hash:
            # Successful login
            self.current_user = username
            self.create_main_ui()
            
            # Update last login time
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('''
            UPDATE users SET last_login = ? WHERE username = ?
            ''', (datetime.now().isoformat(), username))
            conn.commit()
            conn.close()
        else:
            messagebox.showerror("Error", "Invalid username or password")
    
    def handle_signup(self):
        """Handle new user signup"""
        username = self.signup_username.get()
        password = self.signup_password.get()
        confirm = self.signup_confirm.get()
        
        if not username or not password or not confirm:
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters")
            return
        
        # Check if username exists
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT id FROM users WHERE username = ?
        ''', (username,))
        
        if cursor.fetchone():
            conn.close()
            messagebox.showerror("Error", "Username already exists")
            return
        
        # Create new user
        salt = secrets.token_hex(self.salt_length)
        hashed_password = self.hash_password(password, salt)
        
        cursor.execute('''
        INSERT INTO users (username, salt, password_hash, created_at)
        VALUES (?, ?, ?, ?)
        ''', (username, salt, hashed_password, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        messagebox.showinfo("Success", "Account created successfully!")
        
        # Clear fields and switch to login tab
        self.signup_username.delete(0, tk.END)
        self.signup_password.delete(0, tk.END)
        self.signup_confirm.delete(0, tk.END)
        self.auth_notebook.select(0)
        self.login_username.focus()
    
    def change_password(self):
        """Change user password"""
        current = self.current_pass.get()
        new = self.new_pass.get()
        confirm = self.confirm_pass.get()
        
        if not current or not new or not confirm:
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        if new != confirm:
            messagebox.showerror("Error", "New passwords do not match")
            return
        
        if len(new) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters")
            return
        
        # Verify current password
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT salt, password_hash FROM users WHERE username = ?
        ''', (self.current_user,))
        
        salt, stored_hash = cursor.fetchone()
        
        # Hash provided current password
        hashed_current = self.hash_password(current, salt)
        
        if hashed_current != stored_hash:
            conn.close()
            messagebox.showerror("Error", "Current password is incorrect")
            return
        
        # Update password
        new_salt = secrets.token_hex(self.salt_length)
        new_hash = self.hash_password(new, new_salt)
        
        cursor.execute('''
        UPDATE users 
        SET salt = ?, password_hash = ?
        WHERE username = ?
        ''', (new_salt, new_hash, self.current_user))
        
        conn.commit()
        conn.close()
        
        # Clear fields
        self.current_pass.delete(0, tk.END)
        self.new_pass.delete(0, tk.END)
        self.confirm_pass.delete(0, tk.END)
        
        messagebox.showinfo("Success", "Password changed successfully!")
    
    def logout(self):
        """Log out current user"""
        self.current_user = None
        self.create_auth_ui()
    
    def hash_password(self, password, salt):
        """Hash a password with PBKDF2-HMAC-SHA256"""
        dk = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            self.hash_iterations
        )
        return base64.b64encode(dk).decode('utf-8')
    
    def clear_window(self):
        """Clear all widgets from window"""
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def periodic_tasks(self):
        """Perform periodic maintenance tasks"""
        # Cleanup old passwords (non-bookmarked older than 30 days)
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cutoff = (datetime.now() - timedelta(days=30)).isoformat()
        cursor.execute('''
        DELETE FROM passwords 
        WHERE created_at < ? AND bookmarked = 0
        ''', (cutoff,))
        
        conn.commit()
        conn.close()
        
        # Reschedule in 1 hour
        self.root.after(3600000, self.periodic_tasks)
    
    def get_strength_text(self, strength_value):
        """Convert strength value to text"""
        if strength_value < 40:
            return "Weak"
        elif strength_value < 70:
            return "Medium"
        else:
            return "Strong"

if __name__ == "__main__":
    root = tk.Tk()
    app = SecurePassManager(root)
    root.mainloop()