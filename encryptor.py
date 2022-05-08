import os
import time
from Crypto.Cipher import AES
import hashlib
import sys
import progressbar

extension = 'enc'  # new extension for the encrypted file(s)

# in case user types wrong command
class WrongCommandError(Exception):
    pass


# in case the extension is not the same as the given one
class FileTypeError(Exception):
    pass


# adding zeros to the file's bytes
def pad_file(file):
    while len(file) % 16 != 0:
        file = file + b'0'
    return file


# encrypt, then remove the file
def encrypt_file(path, cipher):
    with open(path, 'rb') as f:
        original_file = f.read()
        padded_file = pad_file(original_file)
        encrypted_message = cipher.encrypt(padded_file)
        with open(f'{path}.{extension}', 'wb') as e:
            e.write(encrypted_message)
    os.remove(path)


# decrypt, then remove the file
def decrypt_file(path, cipher):
    if not path.endswith(f'.{extension}'):
        raise FileTypeError(path)
    with open(path, 'rb') as e:
        encrypted_file = e.read()
        decrypted_file = cipher.decrypt(encrypted_file)
        with open(path[:-(len(extension) + 1)], 'wb') as f:
            f.write(decrypted_file.rstrip(b'0'))
    os.remove(path)


# function for getting every files and subfolders in a directory
def scan_dir(dir):
    subfolders, files = [], []

    for f in os.scandir(dir):
        if f.is_dir():
            subfolders.append(f.path)
        if f.is_file():
            files.append(f.path)

    for dir in list(subfolders):
        sf, f = scan_dir(dir)
        subfolders.extend(sf)
        files.extend(f)
    return subfolders, files


try:
    # first param is the directory we want to encrypt
    dir = sys.argv[1]
    decryption = False
    # encoding the given password
    password = sys.argv[2].encode()

    # checking if user typed any command
    if len(sys.argv) > 3:
        if sys.argv[3] == '-dec':
            decryption = True
        else:
            raise WrongCommandError(sys.argv[3])

    # getting files recursively
    _, f = scan_dir(dir)

    # building the cipher
    key = hashlib.sha256(password).digest()
    mode = AES.MODE_CBC
    cipher = AES.new(key, mode)

    # for print
    mode = 'Decrypt' if decryption else 'Encrypt'
    count = len(f)

    print(f"{mode}ing {count} file(s)...\n")
    # showing progressbar
    bar = progressbar.ProgressBar(maxval=len(f), widgets=[progressbar.Bar(
        '=', '[', ']'), ' ', progressbar.Percentage()])
    bar.start()
    for i in range(count):
        if decryption:
            decrypt_file(f[i], cipher)
        else:
            encrypt_file(f[i], cipher)
        bar.update(i+1)
    bar.finish()
    print(f"\n{mode}ion of {count} file(s) is done")

except IndexError:
    print('Not enough params')
except WrongCommandError as e:
    print(f'Wrong command at {e}')
except FileTypeError as e:
    print(f'File type is not supported: {e}')
except NotADirectoryError as e:
    print(f'Not a directory: {e}')
except FileNotFoundError as e:
    print(e)
