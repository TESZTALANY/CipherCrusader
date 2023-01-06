# CipherCrusader
CipherCrusader is an open source command line password manager made in python.

The script is made using Python 3.10 and will not work with previous Python versions.

List of commands:
  - unlock: Used for decrypting the database using the password.
  - lock: Used for encrypting the database using the password.
  - generate: Used for creating a strong password using random characters after asking for a length.
  - add: Adds an entry to the database, containing a website, username and password.
  - remove: Removes an entry from the database.
  - get: Lists the credentials for a website the user provides.
  - list: Lists all the websites the user has a credential stored in the database.
  - exit: Encrypts the database and exits the program.
  - help: Lists all available commands and their functions.

After the first run, a file named 'database.db' will be placed in the directory of the program. When encrypted, the name of the file will be changed to 'database.db.enc'. The program uses AES encryption to provide security to the database when it is not in use.
