#Abdulrahman Aldaeaj 443102297


import tkinter as tk
from tkinter import messagebox, ttk
import hashlib
import sqlite3
import re
import csv
import logging

logging.basicConfig(filename='KSUGolfCartsApp.log', level=logging.INFO, format='%(asctime)s:%(levelname)s:%(message)s')
#Abdulrahman Aldaeaj 443102297
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def create_db_connection():
    return sqlite3.connect('KSUGolfCarts.db')

def setup_db_tables(conn):
    with conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS Users (
                            user_id TEXT PRIMARY KEY, 
                            first_name TEXT, 
                            last_name TEXT, 
                            user_class TEXT, 
                            email TEXT, 
                            phone TEXT, 
                            password_hash TEXT)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS GolfCarts (
                            cart_id TEXT PRIMARY KEY,
                            plate_number TEXT,
                            college TEXT)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS Reservations (
                            reservation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id TEXT,
                            cart_id TEXT,
                            start_time DATETIME,
                            end_time DATETIME,
                            FOREIGN KEY(user_id) REFERENCES Users(user_id),
                            FOREIGN KEY(cart_id) REFERENCES GolfCarts(cart_id))''')
        logging.info("Database tables created")

class KSUGolfCartsApp:
    def __init__(self):
        self.conn = create_db_connection()
        setup_db_tables(self.conn)
        self.show_signup_window()
    def show_signup_window(self):
        self.root = tk.Tk()
        self.root.title("Signup")
        self.root.geometry("400x350")  # Set the window size

        labels = ['First Name', 'Last Name', 'ID', 'Password', 'Email Address', 'Phone Number']
        self.entries = {}
        for label in labels:
            frame = tk.Frame(self.root)
            frame.pack(padx=10, pady=5)
            tk.Label(frame, text=label).pack(side=tk.LEFT)
            if label == 'Password':
                entry = tk.Entry(frame, show='*')
            else:
                entry = tk.Entry(frame)
            entry.pack(side=tk.RIGHT) #Abdulrahman Aldaeaj 443102297
            self.entries[label] = entry

        # Dropdown for User Class
        frame = tk.Frame(self.root)
        frame.pack(padx=10, pady=5)
        tk.Label(frame, text="User Class").pack(side=tk.LEFT)
        self.entries['User Class'] = ttk.Combobox(frame, values=['Student', 'Faculty', 'Employee'])
        self.entries['User Class'].pack(side=tk.RIGHT)

        # Signup Button
        tk.Button(self.root, text='Signup', command=self.validate_signup).pack(pady=5)

        # Switch to Login Window Button
        tk.Button(self.root, text='Login', command=self.switch_to_login).pack(pady=5)

        self.root.mainloop()

    def validate_signup(self):
        first_name = self.entries['First Name'].get()
        last_name = self.entries['Last Name'].get()
        user_class = self.entries['User Class'].get()
        user_id = self.entries['ID'].get()
        password = self.entries['Password'].get()
        email = self.entries['Email Address'].get()
        phone = self.entries['Phone Number'].get()

        if not re.match(r"[^@]+@ksu.edu.sa", email):
            messagebox.showerror("Error", "Invalid email format")
            return
        if not re.match(r"05\d{8}", phone):
            messagebox.showerror("Error", "Invalid phone format")
            return
        if user_class == 'Student':
            if len(user_id) != 10:
                messagebox.showerror("Error", "Student ID must be 10 digits long")
                return
        else:
            if len(user_id) != 6:
                messagebox.showerror("Error", "Faculty/Employee ID must be 6 digits long")
                return
        if len(password) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters long")
            return
        password_hash = hash_password(password)
        try:
            with self.conn:
                self.conn.execute('INSERT INTO Users (user_id, first_name, last_name, user_class, email, phone, password_hash) VALUES (?, ?, ?, ?, ?, ?, ?)',
                    (user_id, first_name, last_name, user_class, email, phone, password_hash))
            messagebox.showinfo("Success", "Signup successful")
            logging.info(f"New user signed up: {user_id}")
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "User ID already exists")
            logging.warning(f"Signup failed for user ID {user_id}: User already exists")

    # Abdulrahman Aldaeaj 443102297
    def validate_login(self):
        user_id = self.login_entries['ID'].get()
        password = self.login_entries['Password'].get()
        password_hash = hash_password(password)

        with self.conn:
            cursor = self.conn.cursor()
            cursor.execute('SELECT user_class FROM Users WHERE user_id = ? AND password_hash = ?',
                           (user_id, password_hash))
            result = cursor.fetchone()

            if result is not None:
                self.root.destroy()
                user_class = result[0]
                if user_class == 'Employee':
                    self.show_admin_window()
                else:
                    self.show_user_window(user_id)
                logging.info(f"User logged in: {user_id}")
            else:
                messagebox.showerror("Error", "Invalid ID or Password")
                logging.warning(f"Failed login attempt with ID: {user_id}")
    # Abdulrahman Aldaeaj 443102297[ENDS]
