import sys
import os
import json
import sqlite3
import base64
import secrets
from datetime import datetime
from getpass import getpass

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    print("ERREUR CRITIQUE: 'cryptography' manquant.")
    sys.exit(1)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, "mskstar.db")

class CryptoEngine:
    def kdf(self, secret: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000,
        )
        return kdf.derive(secret.encode())

    def encrypt_aes(self, key: bytes, plaintext: str) -> str:
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        data = plaintext.encode('utf-8')
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return base64.b64encode(nonce + ciphertext).decode('utf-8')

    def decrypt_aes(self, key: bytes, blob_b64: str) -> str:
        try:
            full_blob = base64.b64decode(blob_b64)
            nonce = full_blob[:12]
            ciphertext = full_blob[12:]
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
        except Exception:
            return None

class VaultDB:
    def __init__(self):
        self.exists = os.path.exists(DB_PATH)
        self.conn = sqlite3.connect(DB_PATH)
        self.cursor = self.conn.cursor()
        self._setup()

    def _setup(self):
        self.cursor.execute('CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, val TEXT)')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS data_store (
                id INTEGER PRIMARY KEY,
                col1 TEXT, col2 TEXT, col3 TEXT, created_at TEXT
            )
        ''')
        self.conn.commit()

    def set_cfg(self, k, v):
        self.cursor.execute('INSERT OR REPLACE INTO config VALUES (?, ?)', (k, v))
        self.conn.commit()

    def get_cfg(self, k):
        res = self.cursor.execute('SELECT val FROM config WHERE key=?', (k,)).fetchone()
        return res[0] if res else None

    def add_entry(self, c1, c2, c3):
        self.cursor.execute('INSERT INTO data_store (col1, col2, col3, created_at) VALUES (?,?,?,?)',
                           (c1, c2, c3, datetime.now().isoformat()))
        self.conn.commit()

    def get_all(self):
        return self.cursor.execute('SELECT id, col1, col2, col3 FROM data_store').fetchall()

    def delete(self, eid):
        self.cursor.execute('DELETE FROM data_store WHERE id=?', (eid,))
        self.conn.commit()
        return self.cursor.rowcount > 0

class MSKstarApp:
    def __init__(self):
        print(f"[*] Base de données : {DB_PATH}")
        self.db = VaultDB()
        self.crypto = CryptoEngine()
        self.vault_key = None

    def _generate_seed(self):
        words = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel",
                 "india", "juliet", "kilo", "lima", "mike", "november", "oscar", "papa"]
        return " ".join(secrets.choice(words) for _ in range(12))

    def _init_new_vault(self):
        print("\n=== INITIALISATION (NOUVEAU COFFRE) ===")
        while True:
            pwd = getpass("Nouveau mot de passe maître : ")
            if len(pwd) >= 8: break
            print("Trop court (min 8).")

        seed = self._generate_seed()
        print(f"\n[IMPORTANT] SEED PHRASE (Gardez-la précieusement !) :\n>> {seed} <<\n")
        input("Appuyez sur Entrée après l'avoir notée...")

        vault_salt = secrets.token_bytes(16)
        vault_key = self.crypto.kdf(seed, vault_salt)

        pwd_salt = secrets.token_bytes(16)
        pwd_key = self.crypto.kdf(pwd, pwd_salt)
        encrypted_seed = self.crypto.encrypt_aes(pwd_key, seed)

        self.db.set_cfg("vault_salt", base64.b64encode(vault_salt).decode())
        self.db.set_cfg("pwd_salt", base64.b64encode(pwd_salt).decode())
        self.db.set_cfg("enc_seed", encrypted_seed)

        self.db.set_cfg("check", self.crypto.encrypt_aes(vault_key, "OK"))

        self.vault_key = vault_key
        print("✓ Coffre initialisé.")

    def _recovery_process(self):
        print("\n=== MODE RÉCUPÉRATION (SEED) ===")
        print("Entrez votre Seed Phrase de 12 mots pour réinitialiser le mot de passe.")
        seed_input = input("Seed Phrase > ").strip()

        vault_salt = base64.b64decode(self.db.get_cfg("vault_salt"))
        recovered_vault_key = self.crypto.kdf(seed_input, vault_salt)

        check_enc = self.db.get_cfg("check")
        if self.crypto.decrypt_aes(recovered_vault_key, check_enc) == "OK":
            print("✓ Seed valide ! Accès restauré.")

            while True:
                new_pwd = getpass("Choisissez un NOUVEAU mot de passe : ")
                if len(new_pwd) >= 8: break
                print("Trop court.")

            new_pwd_salt = secrets.token_bytes(16)
            new_pwd_key = self.crypto.kdf(new_pwd, new_pwd_salt)
            new_enc_seed = self.crypto.encrypt_aes(new_pwd_key, seed_input)

            self.db.set_cfg("pwd_salt", base64.b64encode(new_pwd_salt).decode())
            self.db.set_cfg("enc_seed", new_enc_seed)

            self.vault_key = recovered_vault_key
            print("✓ Mot de passe mis à jour avec succès.")
            return True
        else:
            print("⛔ Seed invalide. Impossible de restaurer.")
            return False

    def login(self):
        if not self.db.get_cfg("enc_seed"):
            self._init_new_vault()
            return

        print("\n=== CONNEXION ===")
        attempts = 0
        while attempts < 3:
            pwd = getpass(f"Mot de passe (Essai {attempts+1}/3) : ")

            pwd_salt = base64.b64decode(self.db.get_cfg("pwd_salt"))
            vault_salt = base64.b64decode(self.db.get_cfg("vault_salt"))

            pwd_key = self.crypto.kdf(pwd, pwd_salt)

            enc_seed = self.db.get_cfg("enc_seed")
            decrypted_seed = self.crypto.decrypt_aes(pwd_key, enc_seed)

            if decrypted_seed:
                self.vault_key = self.crypto.kdf(decrypted_seed, vault_salt)
                print("✓ Accès autorisé.")
                return
            else:
                print("⛔ Mot de passe incorrect.")
                attempts += 1

        print("\n!!! TROP D'ÉCHECS !!!")
        choice = input("Voulez-vous utiliser votre SEED PHRASE pour récupérer l'accès ? (o/N) : ")
        if choice.lower() == 'o':
            if self._recovery_process():
                return

        print("Fermeture de l'application.")
        sys.exit(1)

    def run(self):
        self.login()
        while True:
            print(f"\n--- MSKstar ---")
            print("1. Ajouter")
            print("2. Consulter")
            print("3. Supprimer")
            print("4. Quitter")

            c = input("> ")
            if c == "1":
                svc = input("Svc : ")
                usr = input("Usr : ")
                pwd = getpass("Pwd : ")
                self.db.add_entry(
                    self.crypto.encrypt_aes(self.vault_key, svc),
                    self.crypto.encrypt_aes(self.vault_key, usr),
                    self.crypto.encrypt_aes(self.vault_key, pwd)
                )
                print("✓ OK.")
            elif c == "2":
                rows = self.db.get_all()
                if not rows: print("Vide.")
                for r in rows:
                    s = self.crypto.decrypt_aes(self.vault_key, r[1])
                    u = self.crypto.decrypt_aes(self.vault_key, r[2])
                    p = self.crypto.decrypt_aes(self.vault_key, r[3])
                    if s: print(f"[{r[0]}] {s} | {u} | {p}")
            elif c == "3":
                tid = input("ID : ")
                if tid and self.db.delete(tid): print("✓ Supprimé.")
            elif c == "4": break

if __name__ == "__main__":
    MSKstarApp().run()
