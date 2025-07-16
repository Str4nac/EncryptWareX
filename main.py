import os
import sys
import hashlib
import secrets
import base64
import shutil
import json
from datetime import datetime
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
import webbrowser

class EncryptWareX:
    def __init__(self):
        self.setup_directories()
        self.algorithms = {
            '1': 'AES-256-GCM (Recommended)',
            '2': 'RSA-2048 (Asymmetric)',
            '3': 'ChaCha20-Poly1305 (Modern)'
        }

    def setup_directories(self):
        Path("logs").mkdir(exist_ok=True)
        Path("backups").mkdir(exist_ok=True)
        Path("keys").mkdir(exist_ok=True)

    def log_action(self, action, details=""):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {action} - {details}\n"
        with open("logs/logs.txt", "a", encoding="utf-8") as f:
            f.write(log_entry)

    def create_backup(self, filepath):
        if os.path.exists(filepath):
            filename = os.path.basename(filepath)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"{timestamp}_{filename}"
            backup_path = f"backups/{backup_name}"
            shutil.copy2(filepath, backup_path)
            self.log_action("BACKUP", f"Created backup: {backup_name}")
            return backup_path
        return None

    def secure_delete(self, filepath):
        if os.path.exists(filepath):
            filesize = os.path.getsize(filepath)
            with open(filepath, "r+b") as f:
                for _ in range(3):
                    f.seek(0)
                    f.write(secrets.token_bytes(filesize))
                    f.flush()
                    os.fsync(f.fileno())
            os.remove(filepath)
            self.log_action("SECURE_DELETE", f"File securely deleted: {filepath}")
            return True
        return False

    def derive_key(self, password, salt=None):
        if salt is None:
            salt = secrets.token_bytes(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password.encode())
        return key, salt

    def aes_encrypt(self, data, password):
        key, salt = self.derive_key(password)
        iv = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag
        return salt + iv + tag + ciphertext

    def aes_decrypt(self, encrypted_data, password):
        try:
            salt = encrypted_data[:16]
            iv = encrypted_data[16:28]
            tag = encrypted_data[28:44]
            ciphertext = encrypted_data[44:]
            key, _ = self.derive_key(password, salt)
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()
        except Exception:
            raise ValueError("Invalid password or corrupted data")

    def generate_rsa_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def save_rsa_keys(self, private_key, public_key, password):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )
        private_key_path = f"keys/private_key_{timestamp}.pem"
        with open(private_key_path, 'wb') as f:
            f.write(private_pem)
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_path = f"keys/public_key_{timestamp}.pem"
        with open(public_key_path, 'wb') as f:
            f.write(public_pem)
        return private_key_path, public_key_path

    def load_rsa_private_key(self, key_path, password):
        try:
            with open(key_path, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=password.encode(),
                )
            return private_key
        except Exception:
            raise ValueError("Invalid password or corrupted key file")

    def load_rsa_public_key(self, key_path):
        try:
            with open(key_path, 'rb') as f:
                public_key = serialization.load_pem_public_key(f.read())
            return public_key
        except Exception:
            raise ValueError("Invalid or corrupted key file")

    def rsa_encrypt(self, data, public_key_path=None):
        if public_key_path is None:
            private_key, public_key = self.generate_rsa_keys()
            password = input("🔑 Enter password to protect private key: ")
            private_key_path, public_key_path = self.save_rsa_keys(private_key, public_key, password)
            print(f"📁 Private key saved: {private_key_path}")
            print(f"📁 Public key saved: {public_key_path}")
        else:
            public_key = self.load_rsa_public_key(public_key_path)
        max_chunk_size = 190
        chunks = [data[i:i+max_chunk_size] for i in range(0, len(data), max_chunk_size)]
        encrypted_chunks = []
        for chunk in chunks:
            encrypted_chunk = public_key.encrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_chunks.append(encrypted_chunk)
        metadata = {
            'chunk_count': len(encrypted_chunks),
            'chunk_sizes': [len(chunk) for chunk in encrypted_chunks]
        }
        result = json.dumps(metadata).encode() + b'\n' + b''.join(encrypted_chunks)
        return result

    def rsa_decrypt(self, encrypted_data, private_key_path, password):
        try:
            private_key = self.load_rsa_private_key(private_key_path, password)
            lines = encrypted_data.split(b'\n', 1)
            metadata = json.loads(lines[0].decode())
            encrypted_chunks_data = lines[1]
            chunks = []
            offset = 0
            for size in metadata['chunk_sizes']:
                chunks.append(encrypted_chunks_data[offset:offset+size])
                offset += size
            decrypted_chunks = []
            for chunk in chunks:
                decrypted_chunk = private_key.decrypt(
                    chunk,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                decrypted_chunks.append(decrypted_chunk)
            return b''.join(decrypted_chunks)
        except Exception:
            raise ValueError("Invalid password or corrupted data")

    def chacha20_encrypt(self, data, password):
        key, salt = self.derive_key(password)
        nonce = secrets.token_bytes(16)
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return salt + nonce + ciphertext

    def chacha20_decrypt(self, encrypted_data, password):
        try:
            salt = encrypted_data[:16]
            nonce = encrypted_data[16:32]
            ciphertext = encrypted_data[32:]
            key, _ = self.derive_key(password, salt)
            cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()
        except Exception:
            raise ValueError("Invalid password or corrupted data")

    def encrypt_file(self, filepath, password, algorithm, create_backup=True, log_action=True):
        if not os.path.exists(filepath):
            return False, "File not found"
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            if algorithm == '1':
                encrypted = self.aes_encrypt(data, password)
                ext = '.aes'
            elif algorithm == '2':
                encrypted = self.rsa_encrypt(data)
                ext = '.rsa'
            elif algorithm == '3':
                encrypted = self.chacha20_encrypt(data, password)
                ext = '.cha'
            else:
                return False, "Invalid algorithm"
            encrypted_filepath = filepath + ext
            with open(encrypted_filepath, 'wb') as f:
                f.write(encrypted)
            if log_action:
                self.log_action("ENCRYPT", f"File encrypted: {filepath} -> {encrypted_filepath}")
            return True, encrypted_filepath
        except Exception as e:
            return False, str(e)

    def decrypt_file(self, filepath, password, algorithm, log_action=True):
        if not os.path.exists(filepath):
            return False, "File not found"
        try:
            with open(filepath, 'rb') as f:
                encrypted_data = f.read()
            if algorithm == '1':
                decrypted = self.aes_decrypt(encrypted_data, password)
            elif algorithm == '2':
                private_key_path = input("🔑 Enter private key path: ")
                decrypted = self.rsa_decrypt(encrypted_data, private_key_path, password)
            elif algorithm == '3':
                decrypted = self.chacha20_decrypt(encrypted_data, password)
            else:
                return False, "Invalid algorithm"
            original_filepath = filepath
            for ext in ['.aes', '.rsa', '.cha']:
                if original_filepath.endswith(ext):
                    original_filepath = original_filepath[:-len(ext)]
                    break
            if os.path.exists(original_filepath):
                base, ext = os.path.splitext(original_filepath)
                counter = 1
                while os.path.exists(f"{base}_decrypted_{counter}{ext}"):
                    counter += 1
                original_filepath = f"{base}_decrypted_{counter}{ext}"
            with open(original_filepath, 'wb') as f:
                f.write(decrypted)
            if log_action:
                self.log_action("DECRYPT", f"File decrypted: {filepath} -> {original_filepath}")
            return True, original_filepath
        except ValueError as e:
            return False, str(e)
        except Exception as e:
            return False, f"Decryption error: {str(e)}"

def delete_rsa_keys():
    print("\n🗑️ DELETE RSA KEYS")
    print("═" * 50)
    key_files = list(Path("keys").glob("*.pem"))
    if not key_files:
        print("🔑 No RSA keys found.")
        return
    print("Available RSA keys:")
    for idx, key in enumerate(key_files, start=1):
        key_type = "🔐 Private" if "private" in key.name else "🔓 Public"
        print(f"{idx}. {key_type} Key: {key.name}")
    try:
        choice = int(input("\nEnter the number of the key to delete: "))
        if 1 <= choice <= len(key_files):
            selected_key = key_files[choice - 1]
            print("\n⚠️ WARNING:")
            print("   - If you delete a PRIVATE key, you will NO LONGER be able to decrypt files.")
            print("   - Public keys can be safely deleted if you have the private key elsewhere.")
            confirm = input(f"\nAre you sure you want to delete '{selected_key.name}'? (y/n): ").lower()
            if confirm == 'y':
                os.remove(selected_key)
                show_success(f"Key '{selected_key.name}' deleted successfully!")
            else:
                print("❌ Deletion canceled.")
        else:
            show_error("Invalid selection.")
    except ValueError:
        show_error("Please enter a valid number.")

def open_github():
    url = "https://github.com/Str4nac/EncryptWareX  "
    print("\n🔗 Opening EncryptWareX GitHub repository...")
    webbrowser.open(url)

def print_banner():
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 28 + "EncryptWareX" + " " * 28 + "║")
    print("║" + " " * 29 + "Beta 0.1.0" + " " * 29 + "║")
    print("║" + " " * 29 + "By Stranac" + " " * 29 + "║")
    print("║" + " " * 68 + "║")
    print("║" + " " * 24 + "AES • RSA • ChaCha20" + " " * 24 + "║")
    print("║" + " " * 24 + "Open-Source & Simple" + " " * 24 + "║")
    print("╚" + "═" * 68 + "╝")
    print()

def print_menu():
    print("┌" + "─" * 50 + "┐")
    print("│" + " " * 23 + "MENU" + " " * 23 + "│")
    print("├" + "─" * 50 + "┤")
    print("│ 1. 🔒 Encrypt File" + " " * 31 + "│")
    print("│ 2. 🔓 Decrypt File" + " " * 31 + "│")
    print("│ 3. 📋 View Logs" + " " * 34 + "│")
    print("│ 4. 💾 View Backups" + " " * 31 + "│")
    print("│ 5. 🔑 View Keys" + " " * 34 + "│")
    print("│ 6. 🧹 Clear Logs" + " " * 33 + "│")
    print("│ 7. 🗑️ Delete RSA Keys" + " " * 28 + "│")
    print("│ 8. ❌ Exit" + " " * 39 + "│")
    print("│ 9. 🔗 Visit GitHub" + " " * 31 + "│")
    print("└" + "─" * 50 + "┘")
    print()

def get_algorithm_choice():
    print("🔐 Available Algorithms:")
    print("┌" + "─" * 60 + "┐")
    print("│ 1. AES-256-GCM - Fast & Secure                             │")
    print("│ 2. RSA-2048 - Public Key Encryption                        │")
    print("│ 3. ChaCha20 - Google's Algorithm                           │")
    print("└" + "─" * 60 + "┘")
    while True:
        choice = input("\n🎯 Select algorithm (1-3): ").strip()
        if choice in ['1', '2', '3']:
            return choice
        print("❌ Invalid choice. Please enter 1, 2, or 3.")

def get_user_preferences():
    print("\n📋 Encryption Options:")
    backup_choice = input("📁 Create backup of original file? (y/n) [y]: ").lower()
    create_backup = backup_choice != 'n'
    log_choice = input("📝 Log this action? (y/n) [y]: ").lower()
    log_action = log_choice != 'n'
    return create_backup, log_action

def show_error(message):
    print("\n" + "┌" + "─" * (len(message) + 4) + "┐")
    print("│ ❌ " + message + "│")
    print("└" + "─" * (len(message) + 4) + "┘")

def show_success(message):
    print("\n" + "┌" + "─" * (len(message) + 4) + "┐")
    print("│ ✅ " + message + "│")
    print("└" + "─" * (len(message) + 4) + "┘")

def main():
    crypto = EncryptWareX()
    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        print_banner()
        print_menu()
        choice = input("🎯 Select option (1-9): ").strip()

        if choice == '1':
            print("\n🔒 FILE ENCRYPTION")
            print("═" * 50)
            filepath = input("📂 Enter file path to encrypt: ").strip()
            if not os.path.exists(filepath):
                show_error("File not found!")
                input("\n⏎ Press Enter to continue...")
                continue
            algorithm = get_algorithm_choice()
            create_backup, log_action = get_user_preferences()
            if algorithm != '2':
                password = input("🔑 Enter password: ")
            else:
                password = None
            if create_backup:
                backup_path = crypto.create_backup(filepath)
                if backup_path:
                    show_success(f"Backup created: {backup_path}")
            success, result = crypto.encrypt_file(filepath, password, algorithm, create_backup, log_action)
            if success:
                show_success("File encrypted successfully!")
                print(f"📁 Encrypted file: {result}")
                delete_choice = input("\n🗑️ Securely delete original file? (y/n): ").lower()
                if delete_choice == 'y':
                    if crypto.secure_delete(filepath):
                        show_success("Original file securely deleted")
                    else:
                        show_error("Failed to delete original file")
            else:
                show_error(f"Encryption failed: {result}")

        elif choice == '2':
            print("\n🔓 FILE DECRYPTION")
            print("═" * 50)
            filepath = input("📂 Enter encrypted file path: ").strip()
            if not os.path.exists(filepath):
                show_error("File not found!")
                input("\n⏎ Press Enter to continue...")
                continue
            algorithm = get_algorithm_choice()
            log_choice = input("📝 Log this action? (y/n) [y]: ").lower()
            log_action = log_choice != 'n'
            if algorithm == '2':
                password = input("🔑 Enter private key password: ")
            else:
                password = input("🔑 Enter password: ")
            success, result = crypto.decrypt_file(filepath, password, algorithm, log_action)
            if success:
                show_success("File decrypted successfully!")
                print(f"📁 Decrypted file: {result}")
            else:
                if "Invalid password" in result:
                    show_error("Wrong password!")
                    print("   Please check your password and try again.")
                else:
                    show_error(f"Decryption failed: {result}")

        elif choice == '3':
            print("\n📋 SYSTEM LOGS")
            print("═" * 50)
            if os.path.exists("logs/logs.txt"):
                with open("logs/logs.txt", "r", encoding="utf-8") as f:
                    logs = f.read()
                    if logs:
                        print(logs)
                    else:
                        print("📝 No logs found.")
            else:
                print("📝 No log file found.")

        elif choice == '4':
            print("\n💾 BACKUP FILES")
            print("═" * 50)
            backup_files = list(Path("backups").glob("*"))
            if backup_files:
                for backup in backup_files:
                    size = backup.stat().st_size
                    modified = datetime.fromtimestamp(backup.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                    print(f"📁 {backup.name}")
                    print(f"   Size: {size:,} bytes | Modified: {modified}")
                    print()
            else:
                print("💾 No backups found.")

        elif choice == '5':
            print("\n🔑 RSA KEYS")
            print("═" * 50)
            key_files = list(Path("keys").glob("*.pem"))
            if key_files:
                for key in key_files:
                    size = key.stat().st_size
                    modified = datetime.fromtimestamp(key.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                    key_type = "🔐 Private" if "private" in key.name else "🔓 Public"
                    print(f"{key_type} Key: {key.name}")
                    print(f"   Size: {size:,} bytes | Created: {modified}")
                    print()
            else:
                print("🔑 No RSA keys found.")

        elif choice == '6':
            print("\n🧹 CLEAR LOGS")
            print("═" * 50)
            confirm = input("⚠️ Are you sure you want to clear all logs? (y/n): ").lower()
            if confirm == 'y':
                try:
                    if os.path.exists("logs/logs.txt"):
                        os.remove("logs/logs.txt")
                        show_success("Logs cleared successfully!")
                    else:
                        print("📝 No logs to clear.")
                except Exception as e:
                    show_error(f"Error clearing logs: {e}")

        elif choice == '7':
            delete_rsa_keys()

        elif choice == '8':
            print("\n" + "┌" + "─" * 48 + "┐")
            print("│ 👋 Thank you for using EncryptWareX!           │")
            print("│ 🔐 Stay secure! Open-Source & Simple           │")
            print("└" + "─" * 48 + "┘")
            sys.exit(0)

        elif choice == '9':
            open_github()

        else:
            show_error("Invalid option! Please select 1-9.")
        input("\n⏎ Press Enter to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Critical Error: {e}")
        sys.exit(1)
