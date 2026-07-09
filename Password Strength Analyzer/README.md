What it does
Checks password length, complexity, and common patterns
Uses zxcvbn for smart strength estimation
Shows estimated crack time
Hashes passwords with bcrypt before storing
Prevents reuse of old passwords using SQLite
How to run
pip install bcrypt zxcvbn
python password_checker.py
Concepts used
Cryptographic hashing (bcrypt)
Salting
Password entropy
