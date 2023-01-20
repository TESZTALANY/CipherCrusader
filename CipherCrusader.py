#!/usr/bin/python

# This file is part of 'CipherCrusader'.
#
# 'CipherCrusader' is free software: you can redistribute it and/or modify
# it under the terms of the MIT License.
#
# My Project is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# MIT License for more details.
#
# You should have received a copy of the MIT License
# along with My Project.  If not, see <https://opensource.org/licenses/MIT>.

import sqlite3
import re
import os
from os import urandom
import string
import random
import hashlib
import pyperclip as clipboard
from Crypto.Cipher import AES
import maskpass


def derive_key_and_iv(password, salt, key_length, iv_length):
    d = d_i = b''
    while len(d) < key_length + iv_length:
        # d_i = md5(d_i + str.encode(password) + salt).digest() #obtain the md5 hash value
        d_i = hashlib.pbkdf2_hmac(
            'sha256', d_i + password.encode() + salt, salt, 100000)
        d += d_i
    return d[:key_length], d[key_length:key_length+iv_length]


def encrypt_file(password):
    with open("database.db", "rb") as in_file, open("database.db.enc", "wb") as out_file:
        bs = AES.block_size  # 16 bytes
        key_length = 32
        salt = urandom(bs)
        key, iv = derive_key_and_iv(password, salt, key_length, bs)
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


def decrypt_file():
    decryption_successful = False
    while not decryption_successful:
        password = maskpass.askpass("Enter the password for the database: ")
        bs = AES.block_size
        key_length = 32
        with open("database.db.enc", "rb") as in_file:
            salt = in_file.read(bs)
            key, iv = derive_key_and_iv(password, salt, key_length, bs)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            data = in_file.read()
            decrypted_data = cipher.decrypt(data)
            in_file.close()
            try:
                with open("database.db", "wb") as out_file:
                    out_file.write(decrypted_data)
                with open("database.db", "rb") as f:
                    header = f.read(16)
                if header == b'SQLite format 3\x00':
                    decryption_successful = True
                else:
                    os.remove("database.db")
                    print("Incorrect password, please try again.")
            except ValueError:
                print("Incorrect password, please try again.")


# Check if the database file exists
if os.path.exists('database.db.enc'):
    # If the file exists, decrypt it
    decrypt_file()

# Open a connection to the database or create it
db = sqlite3.connect('database.db')
# Check if the 'websites' table exists
cursor = db.cursor()
cursor.execute(
    "SELECT name FROM sqlite_master WHERE type='table' AND name='websites';")
result = cursor.fetchone()

if not result:
    # If the 'websites' table does not exist, create it
    cursor.execute(
        "CREATE TABLE websites (website text, username text, password text)")

locked = False


# Functions for the commands


def add_entry(db, website, username, password):

    # Check for website argument url of IP syntax
    if not re.match(r'^(?:http(s)?:\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#\[\]@!\$&\'\(\)\*\+,;=.]+$', website) and not re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', website):
        return "Error: Invalid website syntax or IP address"

    # Create a cursor to execute queries
    db = sqlite3.connect('database.db')
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


def remove_entry(db, website):

    # Create a cursor to execute queries
    db = sqlite3.connect('database.db')
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


def carve_credentials(db, website):
    # Create a cursor to execute queries
    db = sqlite3.connect('database.db')
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


def list_websites(db):
    # Create a cursor to execute queries
    db = sqlite3.connect('database.db')
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


def generate_password(length):
  # Exclude certain special characters that are known to cause issues in SQLite queries
    symbols = string.punctuation.replace("'", "").replace("\\", "")

    lower_case = string.ascii_lowercase
    upper_case = string.ascii_uppercase
    numbers = string.digits

    password = ""
    for i in range(length):
        char_type = random.uniform(0, 1)
        if char_type <= 0.2:
            password += random.choice(lower_case)
        elif char_type <= 0.4:
            password += random.choice(upper_case)
        elif char_type <= 0.7:
            password += random.choice(numbers)
        else:
            password += random.choice(symbols)

    # Escape any remaining special characters
    password = password.replace("'", "''").replace("\\", "\\\\")

    while not (any(c.isupper() for c in password) and any(c.islower() for c in password) and any(c.isdigit() for c in password) and any(c in symbols for c in password)):
        password = generate_password(length)

    return password


# Console interface
while True:

    # Display a prompt for the user
    command = input("\nEnter a command: ")
    print("\n")

    match command:

        # Unlock command to decrypt database
        case "unlock":

            if (locked == False):
                print("The database is not encrypted.")

            else:
                decrypt_file()
                locked = False

        # Lock command to encrypt database
        case "lock":

            if (locked == True):
                print("The database is already encrypted.")

            else:
                encrypt_file(maskpass.askpass("Enter password to encrypt: "))
                locked = True

        # Generate command to generate a strong password and copy it to clipboard
        case "generate":

            length = int(input("Enter password length (must be an integer): "))
            result = generate_password(length)
            print("Generated {} Characters long password: ".format(length))
            print(result)
            clipboard.copy(result)
            print("\nPassword copied to clipboard.")

        # Add command to add an entry to the database
        case "add":

            if (locked == True):
                print("Database is locked, unlock it using the 'unlock' command.")

            else:
                website = input("Enter the website: ")
                username = input("Enter the username: ")
                password = input("Enter the password: ")
                result = add_entry(db, website, username, password)

                # If the add_entry function returned an error message, print it
                if result:
                    print(result)

        # Remove command to remove an entry from the database
        case "remove":

            if (locked == True):
                print("Database is locked, unlock it using the 'unlock' command.")

            else:
                website = input("Enter the website: ")
                result = remove_entry(db, website)
                # If the remove_entry function returned an error message, print it

                if result:
                    print(result)

        # Get command to list the credentials for a website
        case "get":

            if (locked == True):
                print("Database is locked, unlock it using the 'unlock' command.")

            else:
                website = input("Enter the website: ")
                result = carve_credentials(db, website)

                # If the get_credentials function returned an error message, print it
                if isinstance(result, str):
                    print(result)

                # If the get_credentials function returned a tuple, print the username and password
                else:
                    username, password = result
                    print("Username:", username)
                    print("Password:", password)
                    clipboard.copy(password)
                    print("\nPassword for {} copied to clipboard.".format(website))

        # List command to list all the websites existing in the database
        case "list":

            if (locked == True):
                print("Database is locked, unlock it using the 'unlock' command.")

            else:
                result = list_websites(db)
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

        # Exit command to exit the program
        case "exit":

            if (locked == False):
                encrypt_file(maskpass.askpass("Enter password to encrypt: "))
                db.close()
                os.remove("database.db")

            break

        # Help command to list all available commands and their functions
        case "help":

            print("Available commands: \n")
            print("'unlock' - decrypt the database file")
            print("'lock' - encrypt the database file")
            print("'generate' - generate a strong password and copies it to clipboard")
            print("'add' - add an entry to the database")
            print("'remove' - remove an entry from the database")
            print(
                "'get' - print the credentials to a website and copy the password to clipboard")
            print("'list' - list all the websites in the database")
            print("'exit' - exits the program")
            print("'help' - displays this message")

        # Default answer to not valid commands
        case _:

            print(
                "This is not a valid command, use the 'help' command for more information.")

    if (locked == False and os.path.exists("database.db.enc")):
        db.close()
        os.remove("database.db.enc")

    elif (locked == True and os.path.exists("database.db")):
        db.close()
        os.remove("database.db")
