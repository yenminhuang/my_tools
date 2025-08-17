from cryptography.fernet import Fernet
import argparse
import os

KEY_FILE = "~/.my_key"
CRYPTO_KEY = "CRYPTO_KEY"


def generate_key():
    """Generates a key for encryption and saves it to a file."""
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)


def load_key():
    """Loads the encryption key from a file."""
    return open(KEY_FILE, "rb").read()


def encrypt_file(filename, key, output_file=None):
    """Encrypts a file using the provided key."""
    f = Fernet(key)
    with open(filename, "rb") as file:
        file_data = file.read()
    encrypted_data = f.encrypt(file_data)
    if output_file is None:
        output_file = filename + ".enc"
    with open(output_file, "wb") as file:
        file.write(encrypted_data)


def decrypt_file(filename, key, output_file=None):
    """Decrypts a file using the provided key."""
    f = Fernet(key)
    with open(filename, "rb") as file:
        encrypted_data = file.read()
    decrypted_data = f.decrypt(encrypted_data)
    if output_file is None:
        output_file = "out_" + filename[:-4]
    with open(output_file, "wb") as file:
        file.write(decrypted_data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", required=False, default=None)
    parser.add_argument("--encrypt", required=False, default=None, help="read the encrypted file to be decrypted")
    parser.add_argument("--decrypt", required=False, default=None, help="read the decrypted file to be encrypted")
    args = parser.parse_args()
    print(args)
    my_key = None
    if args.key is None:
        if "CRYPTO_KEY" in os.environ:
            my_key = os.environ[CRYPTO_KEY]
        elif os.path.exists(KEY_FILE):
            my_key = load_key()
        else:
            # Generate a key (only need to do this once)
            generate_key()
            # Load the key
            my_key = load_key()
    else:
        my_key = args.key

    # Encrypt a file
    if args.encrypt is not None:
        encrypt_file(args.encrypt, my_key)

    # Decrypt the file
    if args.decrypt is not None:
        decrypt_file(args.decrypt, my_key)
