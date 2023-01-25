# CipherCrusader
CipherCrusader is an open-source command-line password manager created in Python 3.10. The program requires Python 3.10 or later to be installed on the user's device. Instructions on how to install Python can be found on the official Python website (https://www.python.org/).

CipherCrusader utilizes AES encryption to secure the user's login information stored in an SQLite database. The database is encrypted by default and can only be accessed by providing the correct password. The user can also manually lock and unlock the database.

CipherCrusader offers a variety of commands for the user to manage their login information. These include:
- `unlock`: Decrypts the database using the user's password.
- `lock`: Encrypts the database using the user's password.
- `generate`: Generates a strong, unique password of a user-specified length.
- `add`: Adds an entry to the database, including a website, username, and password.
- `remove`: Removes an entry from the database.
- `get`: Retrieves the credentials for a specific website.
- `list`: Lists all websites for which the user has stored credentials in the database.
- `exit`: Encrypts the database and exits the program.
- `help`: Lists all available commands and their functions.

The first time the program is run, the program will ask the user for a name for the database which will be created in the program's directory. When encrypted, the file extension will change to '.db.enc'.

If you encounter any issues or bugs with the program, please feel free to submit an issue or submit a pull request with your suggested changes.

Thank you for using CipherCrusader and have a great day! ☺️



## Installation:

1. Make sure you have Python 3.10 or later installed on your device. If you don't have Python installed, you can download it from the official Python website (https://www.python.org/).

2. Download the source code for CipherCrusader from the repository.

3. Install the dependencies listed in the requirements.txt file by running the following command:
    ```
    pip install -r requirements.txt
    ```

4. Run the script using the command:
    ```
    python CipherCrusader.py
    ```