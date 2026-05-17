import unittest
import sqlite3
import bcrypt
import os
from secure_app import get_db_connection, add_user, HEURISTIC_KEY

class TestSecureApp(unittest.TestCase):
    def setUp(self):
        if os.path.exists("secure_users.db"):
            try:
                os.remove("secure_users.db")
            except OSError:
                pass
            
    def tearDown(self):
        if os.path.exists("secure_users.db"):
            try:
                os.remove("secure_users.db")
            except OSError:
                pass

    def test_valid_db_connection(self):
        # TEST 1
        conn = get_db_connection(HEURISTIC_KEY)
        self.assertIsInstance(conn, sqlite3.Connection)
        conn.close()

    def test_invalid_db_connection(self):
        # TEST 2
        wrong_key = b'ZlyKluczMaskujacyBazeDanych123456789012345='
        with self.assertRaises(ValueError):
            get_db_connection(wrong_key)

    def test_password_is_not_plaintext(self):
        # TEST 3
        conn = get_db_connection(HEURISTIC_KEY)
        add_user(conn, "unikalny_user_1", "tajne_haslo_123")
        
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE username='unikalny_user_1'")
        saved_hash = cursor.fetchone()[0]
        
        self.assertNotEqual(saved_hash, "tajne_haslo_123")
        self.assertTrue(saved_hash.startswith("$2b$") or saved_hash.startswith("$2a$") or saved_hash.startswith("$2y$"))
        conn.close()

    def test_password_verification_logic(self):
        # TEST 4
        conn = get_db_connection(HEURISTIC_KEY)
        add_user(conn, "unikalny_admin_2", "admin123")
        
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE username='unikalny_admin_2'")
        saved_hash = cursor.fetchone()[0].encode('utf-8')
        
        self.assertTrue(bcrypt.checkpw(b"admin123", saved_hash))
        conn.close()

    def test_duplicate_user_handling(self):
        # TEST 5
        conn = get_db_connection(HEURISTIC_KEY)
        first_attempt = add_user(conn, "unikalny_student_3", "haslo")
        second_attempt = add_user(conn, "unikalny_student_3", "inne_haslo")
        
        self.assertTrue(first_attempt)
        self.assertFalse(second_attempt)
        conn.close()

if __name__ == "__main__":
    unittest.main()