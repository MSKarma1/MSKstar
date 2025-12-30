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
    print("CRITICAL ERROR: 'cryptography' library is missing.")
    print("Please install it: pip install cryptography")
    sys.exit(1)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, "mskstar.db")

LANG = {
    'fr': {
        'db_path': "[*] Chemin de la base : {}",
        'init_new': "\n=== INITIALISATION (NOUVEAU COFFRE) ===",
        'ask_master': "Créez votre mot de passe maître : ",
        'too_short': "Trop court (min 8 caractères).",
        'seed_intro': "\n[IMPORTANT] SEED DE RÉCUPÉRATION (Notez-la !) :",
        'press_enter': "Appuyez sur Entrée une fois notée...",
        'vault_ready': "✓ Coffre initialisé avec succès.",
        'rec_mode': "\n=== MODE RÉCUPÉRATION (SEED) ===",
        'ask_seed': "Entrez votre Seed Phrase de 12 mots :",
        'seed_ok': "✓ Seed Valide ! Accès restauré.",
        'ask_new_master': "Définissez le NOUVEAU mot de passe maître : ",
        'master_updated': "✓ Mot de passe maître mis à jour.",
        'seed_bad': "⛔ Seed invalide.",
        'rec_err': "⛔ Erreur de récupération.",
        'login_title': "\n=== CONNEXION ===",
        'login_prompt': "Mot de passe maître (Essai {}/3) : ",
        'access_ok': "✓ Accès autorisé.",
        'access_bad': "⛔ Mot de passe incorrect.",
        'login_err': "⛔ Erreur technique.",
        'fail_title': "\n!!! TROP D'ÉCHECS !!!",
        'ask_rec': "Voulez-vous utiliser la SEED DE RÉCUPÉRATION ? (o/N) : ",
        'bye': "Fermeture de l'application.",
        'menu_title': "\n--- MSKstar ---",
        'm_add': "1. Ajouter un compte",
        'm_view': "2. Voir les comptes",
        'm_del': "3. Supprimer un compte",
        'm_exit': "4. Quitter",
        'choice': "Choix > ",
        'svc': "Service : ",
        'usr': "Utilisateur : ",
        'pwd': "Mot de passe : ",
        'saved': "✓ Enregistré.",
        'empty': "Le coffre est vide.",
        'del_title': "Liste des comptes :",
        'del_ask': "Entrez l'ID à supprimer : ",
        'deleted': "✓ Supprimé.",
        'nothing': "Rien à supprimer.",
        'col_id': 'ID', 'col_svc': 'SERVICE', 'col_usr': 'UTILISATEUR', 'col_pwd': 'MOT DE PASSE'
    },
    'en': {
        'db_path': "[*] Database Path: {}",
        'init_new': "\n=== INITIALIZATION (NEW VAULT) ===",
        'ask_master': "Create Master Password: ",
        'too_short': "Too short (min 8 chars).",
        'seed_intro': "\n[IMPORTANT] RECOVERY SEED PHRASE (Write it down!) :",
        'press_enter': "Press Enter once written down...",
        'vault_ready': "✓ Vault Initialized Successfully.",
        'rec_mode': "\n=== RECOVERY MODE (SEED) ===",
        'ask_seed': "Enter your 12-word Seed Phrase:",
        'seed_ok': "✓ Seed Valid! Access Restored.",
        'ask_new_master': "Set NEW Master Password: ",
        'master_updated': "✓ Master Password Updated.",
        'seed_bad': "⛔ Invalid Seed.",
        'rec_err': "⛔ Recovery Error.",
        'login_title': "\n=== LOGIN ===",
        'login_prompt': "Master Password (Attempt {}/3): ",
        'access_ok': "✓ Access Granted.",
        'access_bad': "⛔ Incorrect Password.",
        'login_err': "⛔ Technical Error.",
        'fail_title': "\n!!! TOO MANY FAILED ATTEMPTS !!!",
        'ask_rec': "Do you want to use your RECOVERY SEED? (y/N): ",
        'bye': "Exiting application.",
        'menu_title': "\n--- MSKstar ---",
        'm_add': "1. Add Account",
        'm_view': "2. View Accounts",
        'm_del': "3. Delete Account",
        'm_exit': "4. Exit",
        'choice': "Choice > ",
        'svc': "Service: ",
        'usr': "Username: ",
        'pwd': "Password: ",
        'saved': "✓ Saved.",
        'empty': "Vault is empty.",
        'del_title': "Account List:",
        'del_ask': "Enter ID to delete: ",
        'deleted': "✓ Deleted.",
        'nothing': "Nothing to delete.",
        'col_id': 'ID', 'col_svc': 'SERVICE', 'col_usr': 'USERNAME', 'col_pwd': 'PASSWORD'
    }
}

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
        self.db = VaultDB()
        self.crypto = CryptoEngine()
        self.vault_key = None
        self.lang = 'en'

    def print_banner(self):
        """Affiche le cadenas en ASCII Art"""
        banner = r"""
 ___ __ __   ______   ___   ___   ______   _________  ________   ______       
/__//_//_/\ /_____/\ /___/\/__/\ /_____/\ /________/\/_______/\ /_____/\      MSKtar framework v1.0
\::\| \| \ \\::::_\/_\::.\ \\ \ \\::::_\/_\__.::.__\/\::: _  \ \\:::_ \ \     
 \:.      \ \\:\/___/\\:: \/_) \ \\:\/___/\  \::\ \   \::(_)  \ \\:(_) ) )_   
  \:.\-/\  \ \\_::._\:\\:. __  ( ( \_::._\:\  \::\ \   \:: __  \ \\: __ `\ \  
   \. \  \  \ \ /____\:\\: \ )  \ \  /____\:\  \::\ \   \:.\ \  \ \\ \ `\ \ \ 
    \__\/ \__\/ \_____\/ \__\/\__\/  \_____\/   \__\/    \__\/\__\/ \_\/ \_\/ 
    
        """
        print(banner)

    def select_language(self):
        """Demande la langue au démarrage"""
        print("Language Selection / Sélection de la langue")
        while True:
            choice = input("[1] English  [2] Français : ").strip()
            if choice == '1':
                self.lang = 'en'
                break
            elif choice == '2':
                self.lang = 'fr'
                break

    def t(self, key):
        """Helper pour récupérer le texte traduit"""
        return LANG[self.lang].get(key, key)

    def _generate_seed(self):
        words = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", 
                 "india", "juliet", "kilo", "lima", "mike", "november", "oscar", "papa", "zulu"]
        return " ".join(secrets.choice(words) for _ in range(12))

    def _init_new_vault(self):
        print(self.t('init_new'))
        while True:
            pwd = getpass(self.t('ask_master'))
            if len(pwd) >= 8: break
            print(self.t('too_short'))

        seed = self._generate_seed()
        print(f"{self.t('seed_intro')}\n>> {seed} <<\n")
        input(self.t('press_enter'))

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
        print(self.t('vault_ready'))

    def _recovery_process(self):
        print(self.t('rec_mode'))
        seed_input = input(f"{self.t('ask_seed')} ").strip()

        try:
            vault_salt = base64.b64decode(self.db.get_cfg("vault_salt"))
            recovered_vault_key = self.crypto.kdf(seed_input, vault_salt)
            check_enc = self.db.get_cfg("check")
            
            if self.crypto.decrypt_aes(recovered_vault_key, check_enc) == "OK":
                print(self.t('seed_ok'))
                while True:
                    new_pwd = getpass(self.t('ask_new_master'))
                    if len(new_pwd) >= 8: break
                    print(self.t('too_short'))

                new_pwd_salt = secrets.token_bytes(16)
                new_pwd_key = self.crypto.kdf(new_pwd, new_pwd_salt)
                new_enc_seed = self.crypto.encrypt_aes(new_pwd_key, seed_input)

                self.db.set_cfg("pwd_salt", base64.b64encode(new_pwd_salt).decode())
                self.db.set_cfg("enc_seed", new_enc_seed)
                self.vault_key = recovered_vault_key
                print(self.t('master_updated'))
                return True
            else:
                print(self.t('seed_bad'))
                return False
        except Exception:
            print(self.t('rec_err'))
            return False

    def login(self):
        if not self.db.get_cfg("enc_seed"):
            self._init_new_vault()
            return

        print(self.t('login_title'))
        attempts = 0
        while attempts < 3:
            pwd = getpass(self.t('login_prompt').format(attempts+1))
            try:
                pwd_salt = base64.b64decode(self.db.get_cfg("pwd_salt"))
                vault_salt = base64.b64decode(self.db.get_cfg("vault_salt"))
                pwd_key = self.crypto.kdf(pwd, pwd_salt)
                enc_seed = self.db.get_cfg("enc_seed")
                
                decrypted_seed = self.crypto.decrypt_aes(pwd_key, enc_seed)
                if decrypted_seed:
                    self.vault_key = self.crypto.kdf(decrypted_seed, vault_salt)
                    print(self.t('access_ok'))
                    return
                else:
                    print(self.t('access_bad'))
                    attempts += 1
            except Exception:
                print(self.t('login_err'))
                attempts += 1

        print(self.t('fail_title'))
        choice = input(self.t('ask_rec'))
        if choice.lower() in ['y', 'o', 'yes', 'oui']:
            if self._recovery_process(): return 
        
        print(self.t('bye'))
        sys.exit(1)

    def run(self):
        self.print_banner()
        self.select_language()
        print(self.t('db_path').format(DB_PATH))
        self.login()
        
        while True:
            print(self.t('menu_title'))
            print(self.t('m_add'))
            print(self.t('m_view'))
            print(self.t('m_del'))
            print(self.t('m_exit'))
            
            c = input(self.t('choice'))
            if c == "1":
                svc = input(self.t('svc'))
                usr = input(self.t('usr'))
                pwd = getpass(self.t('pwd'))
                self.db.add_entry(
                    self.crypto.encrypt_aes(self.vault_key, svc),
                    self.crypto.encrypt_aes(self.vault_key, usr),
                    self.crypto.encrypt_aes(self.vault_key, pwd)
                )
                print(self.t('saved'))
            elif c == "2":
                rows = self.db.get_all()
                if not rows: print(self.t('empty'))
                else:
                    h_id, h_sv, h_us, h_pw = self.t('col_id'), self.t('col_svc'), self.t('col_usr'), self.t('col_pwd')
                    print(f"\n{h_id:<4} | {h_sv:<20} | {h_us:<20} | {h_pw}")
                    print("-" * 75)
                    for r in rows:
                        s = self.crypto.decrypt_aes(self.vault_key, r[1])
                        u = self.crypto.decrypt_aes(self.vault_key, r[2])
                        p = self.crypto.decrypt_aes(self.vault_key, r[3])
                        if s: print(f"{r[0]:<4} | {s:<20} | {u:<20} | {p}")
            elif c == "3":
                rows = self.db.get_all()
                if rows:
                    print(f"\n{self.t('del_title')}")
                    for r in rows:
                        s = self.crypto.decrypt_aes(self.vault_key, r[1])
                        if s: print(f"ID {r[0]}: {s}")
                    tid = input(self.t('del_ask'))
                    if tid and self.db.delete(tid): print(self.t('deleted'))
                else:
                    print(self.t('nothing'))
            elif c == "4": break

if __name__ == "__main__":
    MSKstarApp().run()
