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

# Abdullah Almaghem 443102199 Starts
    def switch_to_login(self):
        self.root.destroy()
        self.show_login_window()

    def show_login_window(self):
        self.root = tk.Tk()
        self.root.title("Login")
        self.root.geometry("300x250")  # Adjusted window size for better layout

        # Styling
        label_font = ('Arial', 12)
        entry_font = ('Arial', 10)

        # ID Field
        id_frame = tk.Frame(self.root)
        id_frame.pack(padx=20, pady=(20, 10))
        tk.Label(id_frame, text="ID:", font=label_font).pack(side=tk.LEFT)
        self.login_entries = {'ID': tk.Entry(id_frame, font=entry_font)}
        self.login_entries['ID'].pack(side=tk.RIGHT, fill=tk.X, expand=True)

        # Password Field
        password_frame = tk.Frame(self.root)
        password_frame.pack(padx=20, pady=10)
        tk.Label(password_frame, text="Password:", font=label_font).pack(side=tk.LEFT)
        self.login_entries['Password'] = tk.Entry(password_frame, show="*", font=entry_font)
        self.login_entries['Password'].pack(side=tk.RIGHT, fill=tk.X, expand=True)

        # Login Button
        tk.Button(self.root, text='Login', command=self.validate_login, font=label_font).pack(pady=(20, 10))

        self.root.mainloop()



    def show_admin_window(self):
        self.root = tk.Tk()
        self.root.title("Admin Dashboard")
        self.root.geometry("400x300")  # Set window size

        # Golf Cart Plate Number
        plate_frame = tk.Frame(self.root)
        plate_frame.pack(padx=10, pady=10)
        tk.Label(plate_frame, text="Golf Cart Plate Number:").pack(side=tk.LEFT)
        self.plate_number_entry = tk.Entry(plate_frame)
        self.plate_number_entry.pack(side=tk.RIGHT)

        # College
        college_frame = tk.Frame(self.root)
        college_frame.pack(padx=10, pady=10)
        tk.Label(college_frame, text="College:").pack(side=tk.LEFT)
        self.college_entry = tk.Entry(college_frame)
        self.college_entry.pack(side=tk.RIGHT)

        # Create Button
        tk.Button(self.root, text='Create Cart', command=self.create_cart).pack(pady=10)

        # Backup Button
        tk.Button(self.root, text='Backup Database', command=self.backup_database).pack(pady=10)

        # Logout Button
        tk.Button(self.root, text='Logout', command=self.logout).pack(pady=10)

        self.root.mainloop()

    def create_cart(self):
        plate_number = self.plate_number_entry.get()
        college = self.college_entry.get()

        if plate_number and college:
            try:
                with self.conn:
                    self.conn.execute('INSERT INTO GolfCarts (cart_ID,plate_number, college) VALUES (?, ?, ?)',
                                      (plate_number ,plate_number, college))
                messagebox.showinfo("Success", "New cart added successfully")
                logging.info(f"New cart added: Plate {plate_number}, College {college}")
            except sqlite3.IntegrityError:
                messagebox.showerror("Error", "This cart ID already exists")
                logging.warning(f"Cart creation failed: Plate {plate_number} already exists")

    # Abdulrahman Aldaeaj 443102297

    def backup_database(self):
        with self.conn:
            cursor = self.conn.cursor()
            cursor.execute('SELECT * FROM Users')
            users_data = cursor.fetchall()
        headers = ['User ID', 'First Name', 'Last Name', 'User Class', 'Email', 'Phone', 'Password Hash']
        with open('backup_users.csv', 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(users_data)
        messagebox.showinfo("Backup Successful", "Database has been backed up to 'backup_users.csv'")
        logging.info("Database backed up to 'backup_users.csv'")

    def show_user_window(self, user_id):
        self.user_window = tk.Tk()
        self.user_window.title("User Dashboard")
        self.user_window.geometry("500x400")  # Set window size

        tab_control = ttk.Notebook(self.user_window)

        # Tab for Reserving a Cart
        reserve_tab = ttk.Frame(tab_control)
        tab_control.add(reserve_tab, text="Reserve a Cart")
        self.setup_reserve_tab(reserve_tab, user_id)

        # Tab for Viewing Reservations
        view_tab = ttk.Frame(tab_control)
        tab_control.add(view_tab, text="View My Reservations")
        self.setup_view_tab(view_tab, user_id)

        tab_control.pack(expand=1, fill="both")

        # Logout Button
        tk.Button(self.user_window, text='Logout', command=self.logoutuser).pack(pady=10)

        self.user_window.mainloop()
#Abdullah Almaghem 443102199 Ends
    def setup_reserve_tab(self, tab, user_id):
        # College Selection
        colleges = ["CCIS", "BUSINESS", "ENGINEERING"]
        tk.Label(tab, text="Select College:").pack(padx=10, pady=5)
        self.college_combobox = ttk.Combobox(tab, values=colleges)
        self.college_combobox.pack(padx=10, pady=5)
        # Populate the combobox with college names from the database

        # Reservation Start and End Time
        tk.Label(tab, text="Start Time & Date (yyyy-mm-dd hh:mm) :").pack(padx=10, pady=5)
        self.start_time_entry = tk.Entry(tab)
        self.start_time_entry.pack(padx=10, pady=5)

        tk.Label(tab, text="End Time & Date (yyyy-mm-dd hh:mm):").pack(padx=10, pady=5)
        self.end_time_entry = tk.Entry(tab)
        self.end_time_entry.pack(padx=10, pady=5)

        # Reserve Button
        tk.Button(tab, text="Reserve", command=lambda: self.reserve_cart(user_id)).pack(padx=10, pady=10)

    def reserve_cart(self, user_id):
        college = self.college_combobox.get()
        start_time = self.start_time_entry.get()
        end_time = self.end_time_entry.get()

        if not all([college, start_time, end_time]):
            messagebox.showerror("Error", "All fields must be filled")
            return
        if not re.match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$", start_time):
            messagebox.showerror("Error", "Invalid date format")
            return
        if not re.match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$", end_time):
            messagebox.showerror("Error", "Invalid date format")
            return

        # Check reservation time limit based on user class
        if not self.validate_reservation_time(user_id, start_time, end_time):
            return

        # Reservation logic
        try:
            with self.conn:
                # Check for available carts
                cursor = self.conn.cursor()
                cursor.execute('''SELECT cart_id FROM GolfCarts 
                                  WHERE college = ? AND cart_id NOT IN (
                                      SELECT cart_id FROM Reservations 
                                      WHERE start_time < ? AND end_time > ?)''',
                               (college, end_time, start_time))
                available_carts = cursor.fetchall()

                if available_carts:
                    # Reserve the first available cart
                    cursor.execute('''INSERT INTO Reservations 
                                      (user_id, cart_id, start_time, end_time) 
                                      VALUES (?, ?, ?, ?)''',
                                   (user_id, available_carts[0][0], start_time, end_time))
                    messagebox.showinfo("Success", "Cart reserved successfully")
                else:
                    messagebox.showerror("Error", "No carts available for the selected time")
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", str(e))

    def validate_reservation_time(self, user_id, start_time, end_time):
        with self.conn:
            cursor = self.conn.cursor()
            cursor.execute('SELECT user_class FROM Users WHERE user_id = ?', (user_id,))
            result = cursor.fetchone()

            if result:
                user_class = result[0]
                max_duration = self.get_max_reservation_duration(user_class)
                if self.calculate_time_difference(start_time, end_time) > max_duration:
                    messagebox.showerror("Error", f"Reservation exceeds maximum duration for {user_class}")
                    return False
                return True
            else:
                messagebox.showerror("Error", "User not found")
                return False

    # Abdulrahman Aldaeaj 443102297
    def get_max_reservation_duration(self, user_class):
        if user_class == 'Student':
            return 30  # 30 minutes
        elif user_class == 'Employee':
            return 60  # 1 hour
        else:  # Faculty
            return 90  # 1 hour and 30 minutes

    def calculate_time_difference(self, start, end):
        from datetime import datetime

        fmt = '%Y-%m-%d %H:%M'
        start_dt = datetime.strptime(start, fmt)
        end_dt = datetime.strptime(end, fmt)
        delta = end_dt - start_dt
        return delta.total_seconds() / 60
    def load_reservations(self, user_id):
        try:
            with self.conn:
                cursor = self.conn.cursor()
                cursor.execute('''SELECT reservation_id, cart_id, start_time, end_time 
                                  FROM Reservations WHERE user_id = ?''', (user_id,))
                reservations = cursor.fetchall()

                # Clear the listbox before adding new items
                self.reservation_listbox.delete(0, tk.END)

                for res in reservations:
                    self.reservation_listbox.insert(tk.END,
                                                    f"Reservation {res[0]}: Cart {res[1]}, From {res[2]} To {res[3]}")
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", str(e))

    def setup_view_tab(self, tab, user_id):
        # Label for Reservation List
        tk.Label(tab, text="My Reservations:").pack(padx=10, pady=5)

        # Listbox for showing reservations
        self.reservation_listbox = tk.Listbox(tab)
        self.reservation_listbox.pack(padx=10, pady=5, fill='both', expand=True)

        # Button to Refresh/Load Reservations
        tk.Button(tab, text="Refresh", command=lambda: self.load_reservations(user_id)).pack(padx=10, pady=10)

    def logout(self):
        # Destroy the current window
        self.root.destroy()

        # Reopen the login window
        self.show_signup_window()

    def logoutuser(self):
        # Destroy the current window
        self.user_window.destroy()

        # Reopen the login window
        self.show_signup_window()
#Abdulrahman Aldaeaj 443102297

# Main execution
if __name__ == "__main__":
    app = KSUGolfCartsApp()
