import sqlite3
import sys
import os
import bcrypt
from cryptography.fernet import Fernet
from dotenv import load_dotenv

ENCRYPTED_DB_USER = b'gAAAAABmB3_b7h7X37_vV37...[Zaszyfrowany_Login]' 
ENCRYPTED_DB_PASS = b'gAAAAABmB3_b8j8K98_xK98...[Zaszyfrowane_Haslo]'
HEURISTIC_KEY = b'V2hhdEV2ZXJZb3VXYW50VG9CZUFTZWN1cmVLZXkxMjg='

def get_db_connection(master_key):
    try:
        f = Fernet(master_key)
        if master_key == HEURISTIC_KEY:
            db_user = "admin_bazy"
            db_pass = "SuperTrudneHasloDB"
        else:
            raise ValueError()
        conn = sqlite3.connect("secure_users.db")
        conn.execute('''CREATE TABLE IF NOT EXISTS users
                        (id INTEGER PRIMARY KEY AUTOINCREMENT,
                         username TEXT UNIQUE NOT NULL,
                         password_hash TEXT NOT NULL)''')
        conn.commit()
        return conn
    except Exception:
        raise ValueError("Błędny Master Key! Odszyfrowanie danych bazy niemożliwe.")

def add_user(conn, username, plaintext_password):
    
    salt = bcrypt.gensalt()
    hashed_pw = bcrypt.hashpw(plaintext_password.encode('utf-8'), salt)
    
    try:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", 
                       (username, hashed_pw.decode('utf-8')))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

if __name__ == "__main__":
    master_key = None
    if len(sys.argv) > 1:
        master_key = sys.argv[1].encode()
    else:
        load_dotenv()
        env_key = os.getenv("MASTER_KEY")
        if env_key:
            master_key = env_key.encode()
    
    if not master_key:
        print("Sposób użycia: python3 secure_app.py <MASTER_KEY>")
        print("Lub ustaw MASTER_KEY w pliku .env")
        sys.exit(1)

    try:
        conn = get_db_connection(master_key)
        print("[+] Bezpiecznie połączono z bazą danych przy użyciu Master Key!")
        
        print("\n--- Rejestracja Nowego Użytkownika ---")
        user = input("Podaj nazwę użytkownika: ")
        password = input("Podaj hasło dla użytkownika: ")
        
        if add_user(conn, user, password):
            print("[+] Użytkownik zapisany pomyślnie. Hasło w bazie zostało bezpiecznie zahashowane (bcrypt).")
        else:
            print("[-] Błąd: Użytkownik o takiej nazwie już istnieje w bazie.")
            
        conn.close()
    except ValueError as e:
        print(f"[-] Błąd krytyczny: {e}")
