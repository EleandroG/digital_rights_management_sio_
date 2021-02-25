import os
from math import ceil
from argparse import ArgumentParser
from base64 import b64encode, b64decode
from getpass import getpass
from secrets import token_bytes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes 
from cryptography.hazmat.backends import default_backend

cipherModes = ["ECB", "CFB", "OFB"]
cipherAlgorithms = ['AES', '3DES', 'ChaCha20']

def add_padding(message_block, algorithm_name):
    if algorithm_name == "3DES":
        length_block = 8
    else:
        length_block = 16

    size_padding = length_block - (len(message_block) % length_block)

    message_block = message_block + bytes([size_padding] * size_padding)
    return message_block


def remove_padding(message_block):
    length_block = len(message_block)

    size_padding = int(message_block[-1])

    message_block = message_block[:length_block - size_padding]
    return message_block


def generate_key(algorithm_name, salt, password):
    if type(password) != type(b""):
        password = password.encode()

    if algorithm_name == '3DES':
        length = 24
    elif algorithm_name == 'ChaCha20':
        length = 32
    else:
        length = 16
    pbkdf = PBKDF2HMAC(salt=salt, algorithm=hashes.SHA256(), iterations=10**5, length=length,
                       backend=default_backend())

    key = pbkdf.derive(password)    #type key == byte

    return key


def encrypt(password, message, algorithm_name, cipherMode_name=None):
    if type(message) != type(b""):
        message = message.encode()

    salt = os.urandom(16)

    key = generate_key(algorithm_name, salt, password)

    if algorithm_name == 'ChaCha20':
        nonce = token_bytes(16)
        algorithm = algorithms.ChaCha20(key, nonce)
        block_length = 128
    elif algorithm_name == '3DES':
        block_length = 8
        algorithm = algorithms.TripleDES(key)
    else:
        block_length = 16
        algorithm = algorithms.AES(key)

    iv = None
    if algorithm_name != "ChaCha20" and cipherMode_name != "ECB":
        iv = token_bytes(block_length)

    if cipherMode_name == "CFB":
        cipher_mode = modes.CFB(iv)
    elif cipherMode_name == "OFB":
        cipher_mode = modes.OFB(iv)
    elif cipherMode_name == "ECB":
        cipher_mode = modes.ECB()
    else:
        cipher_mode = None

    cipher = Cipher(algorithm, cipher_mode)
    encryptor = cipher.encryptor()
    encrypted_message = b""

    encrypted_message = encrypted_message + b64encode(salt)
    if iv != None:
        encrypted_message = encrypted_message + b64encode(iv)
    if algorithm_name == "ChaCha20":
        encrypted_message = encrypted_message + b64encode(nonce)

    pointer = 0
    while True:
        block = message[pointer:pointer + block_length]
        pointer += block_length

        if block == "":
            break

        if len(block) != block_length:
            break

        block = encryptor.update(block)
        encrypted_message = encrypted_message + b64encode(block)

    if algorithm_name != "ChaCha20":
        block = add_padding(block, algorithm_name)
    block = encryptor.update(block)
    encrypted_message = encrypted_message + b64encode(block)

    return encrypted_message


def decrypt(password, encrypted_message, algorithm_name, cipherMode=None):
    message = b""
    pointer = 0

    salt = encrypted_message[pointer:pointer + ceil(16 / 3) * 4]
    pointer += ceil(16 / 3) *4
    salt = b64decode(salt)
    key = generate_key(algorithm_name, salt, password)


    if algorithm_name == 'ChaCha20':
        nonce = encrypted_message[pointer:pointer + ceil( 16 / 3) *4]
        pointer += ceil(16/3)*4
        nonce = b64decode(nonce)
        algorithm = algorithms.ChaCha20(key, nonce)
        block_length = 128
    elif algorithm_name == '3DES':
        block_length = 8
        algorithm = algorithms.TripleDES(key)
    else:
        block_length = 16
        algorithm = algorithms.AES(key)

    if algorithm_name != "ChaCha20" and cipherMode != "ECB":
        iv =  encrypted_message[pointer:pointer + ceil(block_length / 3) *4]
        pointer+=ceil(block_length / 3) *4
        iv = b64decode(iv)

    if cipherMode == "CFB":
        cipher_mode = modes.CFB(iv)
    elif cipherMode == "OFB":
        cipher_mode = modes.OFB(iv)
    elif cipherMode == "ECB":
        cipher_mode = modes.ECB()
    else:
        cipher_mode = None

    cipher = Cipher(algorithm, cipher_mode)
    decryptor = cipher.decryptor()
    next_block = b64decode(encrypted_message[pointer:pointer+ ceil(block_length / 3) *4])
    pointer+=ceil(block_length / 3) *4

    while True:
        block = next_block
        next_block = b64decode(encrypted_message[pointer:pointer + ceil(block_length /3 ) *4])
        pointer+=ceil(block_length/3)*4
        block = decryptor.update(block)

        if next_block == b"":
            break
        message = message + block

    if algorithm_name != "ChaCha20":
        block = remove_padding(block)

    message = message + block

    return message


def decrypt_file(password, file_to_be_decrypted, fileToSave_name, algorithm_name, cipherMode=None):
    file_to_decrypt = open(file_to_be_decrypted, 'rb')
    file_to_save = open(fileToSave_name, 'wb')

    salt = file_to_decrypt.read(ceil(16 / 3) *4)
    salt = b64decode(salt)
    key = generate_key(algorithm_name, salt, password)

    if algorithm_name == 'ChaCha20':
        nonce = file_to_decrypt.read(ceil(16 / 3) *4)
        nonce = b64decode(nonce)
        algorithm = algorithms.ChaCha20(key, nonce)
        block_length = 128
    elif algorithm_name == '3DES':
        block_length = 8
        algorithm = algorithms.TripleDES(key)
    else:
        block_length = 16
        algorithm = algorithms.AES(key)

    if algorithm_name != "ChaCha20" and cipherMode != "ECB":
        iv = file_to_decrypt.read(ceil(block_length / 3) *4)
        iv = b64decode(iv)

    if cipherMode == "CFB":
        cipher_mode = modes.CFB(iv)
    elif cipherMode == "OFB":
        cipher_mode = modes.OFB(iv)
    elif cipherMode == "ECB":
        cipher_mode = modes.ECB()
    else:
        cipher_mode = None

    cipher = Cipher(algorithm, cipher_mode)
    decryptor = cipher.decryptor()
    
    nextBlock = b64decode(file_to_decrypt.read(ceil(block_length / 3) *4))
    while True:
        block = nextBlock
        nextBlock = b64decode(file_to_decrypt.read(ceil(block_length /3) *4))
        block = decryptor.update(block)

        if nextBlock == b"":
            break
        file_to_save.write(block)

    if algorithm_name != "ChaCha20":
        block = remove_padding(block)

    file_to_save.write(block)
    file_to_decrypt.close()
    file_to_save.close()
