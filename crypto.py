# Copyright © 2025 Jędrzej Ganabisiński. All rights reserved.
# This software may not be copied, modified, distributed, or used without prior written permission from the author.

import base64
import sys
from getpass import getpass
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def convert_to_key(pwd: str) -> bytes:
    kdf = PBKDF2HMAC(hashes.SHA256(), 32, b'in the end it doesnt really matter', 2_000_000)
    return base64.urlsafe_b64encode(kdf.derive(pwd.encode("ascii")))


def encrypt(file_path: Path, key: bytes, out_file: Path) -> bytes:
    fernet = Fernet(key)
    encrypted_data_base64 = fernet.encrypt(file_path.read_bytes())
    out_file.write_bytes(encrypted_data_base64)
    return key


def decrypt(file_path: Path, key: bytes, output_file: Path):
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(file_path.read_bytes())
    output_file.write_bytes(decrypted_data)


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise Exception("usage: <'encrypt'/'decrypt'> <input_file> <output_file>")

    in_file = sys.argv[2]
    out_file = sys.argv[3]
    pwd = getpass("Password: ")

    if sys.argv[1] == "encrypt":
        pwd2 = getpass("Password again: ")
        if pwd2 != pwd:
            raise Exception("passwords don't match")

        key = convert_to_key(pwd)
        encrypt(Path(in_file), key, Path(out_file))
    elif sys.argv[1] == "decrypt":
        key = convert_to_key(pwd)
        decrypt(Path(in_file), key, Path(out_file))
    else:
        raise Exception(f"invalid command: {sys.argv[1]!r}")
