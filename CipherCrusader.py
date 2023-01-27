#!/usr/bin/python

# This file is part of 'CipherCrusader'.
#
# 'CipherCrusader' is free software: you can redistribute it and/or modify
# it under the terms of the MIT License.
#
# 'CipherCrusader' is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# MIT License for more details.
#
# You should have received a copy of the MIT License
# along with 'CipherCrusader'.  If not, see <https://opensource.org/licenses/MIT>.


import sqlite3
import re
import os
from os import urandom
import string
import secrets
import hashlib
import pyperclip as clipboard
from Crypto.Cipher import AES
import maskpass


class password_database:

    def derive_key_and_iv(self, password, salt, key_length, iv_length):
        d = d_i = b''
        while len(d) < key_length + iv_length:
            # d_i = md5(d_i + str.encode(password) + salt).digest() #obtain the md5 hash value
            d_i = hashlib.pbkdf2_hmac(
                'sha256', d_i + password.encode() + salt, salt, 100000)
            d += d_i
        return d[:key_length], d[key_length:key_length+iv_length]

    def encrypt_file(self, password):
        with open(self.database_name + ".db", "rb") as in_file, open(self.database_name + ".db.enc", "wb") as out_file:
            bs = AES.block_size  # 16 bytes
            key_length = 32
            salt = urandom(bs)
            key, iv = self.derive_key_and_iv(password, salt, key_length, bs)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            out_file.write(salt)
            finished = False

            while not finished:
                chunk = in_file.read(1024 * bs)
                if len(chunk) == 0 or len(chunk) % bs != 0:
                    padding_length = (bs - len(chunk) % bs) or bs
                    chunk += str.encode(padding_length * chr(padding_length))
                    finished = True
                out_file.write(cipher.encrypt(chunk))

    def decrypt_file(self, prompt: string = "Password: "):
        decryption_successful = False
        while not decryption_successful:
            password = maskpass.askpass(prompt)
            bs = AES.block_size
            key_length = 32
            with open(self.database_name + ".db.enc", "rb") as in_file:
                salt = in_file.read(bs)
                key, iv = self.derive_key_and_iv(
                    password, salt, key_length, bs)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                data = in_file.read()
                decrypted_data = cipher.decrypt(data)
                in_file.close()
                try:
                    with open(self.database_name + ".db", "wb") as out_file:
                        out_file.write(decrypted_data)
                    with open(self.database_name + ".db", "rb") as f:
                        header = f.read(16)
                    if header == b'SQLite format 3\x00':
                        self.password = password
                        decryption_successful = True
                    else:
                        os.remove(self.database_name + ".db")
                        print("Incorrect password, please try again.")
                except ValueError:
                    print("Incorrect password, please try again.")

    def __init__(self, database_name) -> None:
        self.database_name = database_name

        # Check if the database file exists
        if os.path.exists(self.database_name + '.db.enc'):
            # If the file exists, decrypt it
            self.decrypt_file()
        else:
            self.reset_masterpassword(maskpass.askpass("Password: "))
        # Open a connection to the database or create it
        self.db = sqlite3.connect(self.database_name + '.db')
        # Check if the 'websites' table exists
        cursor = self.db.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='websites';")
        result = cursor.fetchone()

        if not result:
            # If the 'websites' table does not exist, create it
            cursor.execute(
                "CREATE TABLE websites (website text, username text, password text)")

        self.locked = False

    def add_entry(self, db, website, username, password):

        # Check for website argument url of IP syntax
        if not re.match(r'^(?:http(s)?:\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#\[\]@!\$&\'\(\)\*\+,;=.]+$', website) and not re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', website):
            return "Error: Invalid website syntax or IP address"

        # Create a cursor to execute queries
        db = sqlite3.connect(self.database_name + '.db')
        cursor = db.cursor()

        # Check if the entry already exists
        cursor.execute("SELECT * FROM websites WHERE website=?", (website,))
        entry = cursor.fetchone()

        # If the entry exists, update it
        if entry:
            cursor.execute("UPDATE websites SET username=?, password=? WHERE website=?",
                           (username, password, website))
        # If the entry does not exist, insert it
        else:
            cursor.execute("INSERT INTO websites (website, username, password) VALUES (?, ?, ?)",
                           (website, username, password))

        # Commit the changes to the database
        db.commit()
        db.close()
        print("Entry added for " + website + ".")

    def remove_entry(self, db, website):

        # Create a cursor to execute queries
        db = sqlite3.connect(self.database_name + '.db')
        cursor = db.cursor()

        # Check if the entry exists
        cursor.execute("SELECT * FROM websites WHERE website=?", (website,))
        entry = cursor.fetchone()

        # If the entry exists, delete it
        if entry:
            cursor.execute("DELETE FROM websites WHERE website=?", (website,))
        # If the entry does not exist, return an error message
        else:
            return "Error: Entry does not exist"

        # Commit the changes to the database
        db.commit()
        db.close()
        print("Entry removed for " + website + ".")

    def carve_credentials(self, db, website):
        # Create a cursor to execute queries
        db = sqlite3.connect(self.database_name + '.db')
        cursor = db.cursor()

        # Retrieve the entry with the specified website name
        cursor.execute("SELECT * FROM websites WHERE website=?", (website,))
        entry = cursor.fetchone()
        db.close()

        # If the entry exists, return the username and password
        if entry:
            return entry[1], entry[2]
        # If the entry does not exist, return an error message
        else:
            return "Error: Entry does not exist"

    def list_websites(self, db):
        # Create a cursor to execute queries
        db = sqlite3.connect(self.database_name + '.db')
        cursor = db.cursor()

        # Retrieve all website names from the 'websites' table, sorted in alphabetical order
        cursor.execute("SELECT website FROM websites ORDER BY website")
        websites = cursor.fetchall()
        db.close()

        # If the table is empty, return an error message
        if not websites:
            return "Error: No websites found"

        # Return the website names as a list
        return [website[0] for website in websites]

    def generate_password(self, length):
      # Exclude certain special characters that are known to cause issues in SQLite queries
        symbols = string.punctuation.replace("'", "").replace("\\", "")

        lower_case = string.ascii_lowercase
        upper_case = string.ascii_uppercase
        numbers = string.digits

        password = ""
        for i in range(length):
            char_type = secrets.SystemRandom().uniform(0, 1)
            if char_type <= 0.2:
                password += secrets.choice(lower_case)
            elif char_type <= 0.4:
                password += secrets.choice(upper_case)
            elif char_type <= 0.7:
                password += secrets.choice(numbers)
            else:
                password += secrets.choice(symbols)

        # Escape any remaining special characters
        password = password.replace("'", "''").replace("\\", "\\\\")

        while not (any(c.isupper() for c in password) and any(c.islower() for c in password) and any(c.isdigit() for c in password) and any(c in symbols for c in password)):
            password = self.generate_password(length)

        return password

    def reset_masterpassword(self, new_password):
        self.password = new_password

    def close_database(self):
        self.db.close()


if __name__ == "__main__":

    # Create the database object
    password_database = password_database(
        input("Name of database: "))
    db = sqlite3.connect(password_database.database_name + '.db')

    # Console interface
    while True:

        # Display a prompt for the user
        command = input("> ")

        match command:

            # Unlock command to decrypt database
            case "unlock":

                if (password_database.locked == False):
                    print("The database is not encrypted.")

                else:
                    password_database.decrypt_file()
                    password_database.locked = False

            # Lock command to encrypt database
            case "lock":

                if (password_database.locked == True):
                    print("The database is already encrypted.")

                else:
                    password_database.encrypt_file(
                        password_database.password)
                    password_database.locked = True

            # Generate command to generate a strong password and copy it to clipboard
            case "generate":

                length = int(
                    input("Password length (int): "))
                result = password_database.generate_password(length)
                print("Generated {} characters long password: ".format(length))
                print(result)
                clipboard.copy(result)
                print("Copied to clipboard.")

            # Add command to add an entry to the database
            case "add":

                if (password_database.locked == True):
                    print("Database is locked, unlock it using the 'unlock' command.")

                else:
                    website = input("Enter website: ")
                    username = input("Enter username: ")
                    password = input("Enter password: ")
                    result = password_database.add_entry(
                        db, website, username, password)

                    # If the add_entry function returned an error message, print it
                    if result:
                        print(result)

            # Remove command to remove an entry from the database
            case "remove":

                if (password_database.locked == True):
                    print("Database is locked, unlock it using the 'unlock' command.")

                else:
                    website = input("Enter website: ")
                    result = password_database.remove_entry(db, website)
                    # If the remove_entry function returned an error message, print it

                    if result:
                        print(result)

            # Get command to list the credentials for a website
            case "get":

                if (password_database.locked == True):
                    password_database.decrypt_file()

                else:
                    website = input("Enter website: ")
                    result = password_database.carve_credentials(db, website)

                    # If the get_credentials function returned an error message, print it
                    if isinstance(result, str):
                        print(result)

                    # If the get_credentials function returned a tuple, print the username and password
                    else:
                        username, password = result
                        print("Username:", username)
                        print("Password:", password)
                        clipboard.copy(password)
                        print(
                            "\nPassword for {} copied to clipboard.".format(website))

            # List command to list all the websites existing in the database
            case "list":

                if (password_database.locked == True):
                    print("Database is locked, unlock it using the 'unlock' command.")

                else:
                    result = password_database.list_websites(db)
                    number_of_sites = 0

                    # If the list_websites function returned an error message, print it
                    if isinstance(result, str):
                        print(result)

                    # If the list_websites function returned a list, print the websites
                    else:

                        for website in result:
                            number_of_sites += 1
                            print(website)

                        print("\nThere are {} credentials in the database.".format(
                            str(number_of_sites)))

            # Change password command to change the master password
            case "resetpw":
                old_password = maskpass.askpass("Old password: ")
                if (old_password == password_database.password):
                    new_password = maskpass.askpass("New password: ")
                    if (new_password == maskpass.askpass("Confirm new password: ")):
                        password_database.reset_masterpassword(new_password)
                    else:
                        print("Incorrect password")
                else:
                    print("Incorrect password")

            # Exit command to exit the program
            case "exit":

                if (password_database.locked == False):
                    password_database.encrypt_file(
                        password_database.password)
                    db.close()
                    password_database.close_database()
                    os.remove(password_database.database_name + ".db")

                break

            # Help command to list all available commands and their functions
            case "help":

                print("\nAvailable commands: \n")
                print("'unlock' - decrypt the database file")
                print("'lock' - encrypt the database file")
                print(
                    "'generate' - generate a strong password and copies it to clipboard")
                print("'add' - add an entry to the database")
                print("'remove' - remove an entry from the database")
                print(
                    "'get' - print the credentials to a website and copy the password to clipboard")
                print("'list' - list all the websites in the database")
                print("'resetpw' - reset master password")
                print("'exit' - exits the program")
                print("'help' - displays this message")

            # Default answer to not valid commands
            case _:
                if command != "":
                    print(
                        "This is not a valid command, use the 'help' command for more information.")

        if (password_database.locked == False and os.path.exists(password_database.database_name + ".db.enc")):
            db.close()
            password_database.close_database()
            os.remove(password_database.database_name + ".db.enc")

        elif (password_database.locked == True and os.path.exists(password_database.database_name + ".db")):
            db.close()
            password_database.close_database()
            os.remove(password_database.database_name + ".db")
