import sys
import os
import logging
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import dsa, utils, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ALGORITHMS = ["3DES", "AES-128"]

logger = logging.getLogger("root")

def key_generator(password,alg_name,digest_alg = None):
    if digest_alg != None:
        if digest_alg == "SHA256":
            hash_algorithm = hashes.SHA256()
        elif digest_alg == "SHA512":
            hash_algorithm = hashes.SHA512()
        elif digest_alg == "BLAKE2":
            hash_algorithm = hashes.BLAKE2b(64)
        else:
            raise Exception("Hash Algorithm name not found")
    else:
        hash_algorithm = hashes.SHA256
    
    password = password.encode()
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hash_algorithm,
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    key = kdf.derive(password)

    if ( alg_name == "AES256"):
        key = key[:16]
    elif (alg_name == "3DES"):
        key = key[:8]
    
    return key


def digest_generator(message, algorithm):
    hash_algorithm = None

    if algorithm == "SHA256":
        hash_algorithm = hashes.SHA256()
    elif algorithm == "SHA512":
        hash_algorithm = hashes.SHA512()
    elif algorithm == "BLAKE2":
        hash_algorithm = hashes.BLAKE2b(64)
    else:
        raise Exception("Hash Algorithm name not found")

    digest = hashes.Hash(hash_algorithm,backend=default_backend)
    digest.update(message)

    return digest.finalize()


def diffie_hellman_client():
    parameters = dh.generate_parameters(
        generator=2, key_size=512, backend=default_backend()
    )

    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    p = parameters.parameter_numbers().p
    g = parameters.parameter_numbers().g

    public_key_pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    logger.debug(f"My Public Key: {public_key}")
    logger.debug(f"My Public Key in Bytes: {public_key_pem}")

    return p, g, private_key, public_key_pem


"""2. This function is used to apply the Diffie-Helman algorithm in the server 
and calculates the private and public component"""
def diffie_hellman_server(p, g, public_key_pem):
    pn = dh.DHParameterNumbers(p, g)
    parameters = pn.parameters(default_backend())

    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    p = parameters.parameter_numbers().p
    g = parameters.parameter_numbers().g

    public_key_pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    logger.debug(f"Public Key: {public_key}")
    logger.debug(f"Public Key in Bytes: {public_key_pem}")

    return private_key, public_key_pem


"""3. This function is used to encrypt a message using a symmetric key, a given algorithm and a mode"""
def symmetric_encrypt(message, key, algorithm_name, mode_name):
    cipher = None
    mode = None
    iv = None
    nonce = None
    tag = None

    #Check which mode we'll be using
    if mode_name == "ECB":
        mode = modes.ECB()
    elif mode_name == "CBC":
        if algorithm_name == "AES":
            iv = os.urandom(16)
        elif algorithm_name == "3DES":
            iv = os.urandom(8)
        mode = modes.CBC(iv)
    elif mode_name == "GCM":
        iv = os.urandom(12)
        mode = modes.GCM(iv)
    elif mode_name == "None":
        mode = None
    else:
        raise Exception("Mode name not found")


"""3. This function is used to apply a digest function to a message"""
def mac_generator(message, key, algorithm):
    hash_algorithm = None

    #Check which digest algorithm we'll be using
    if algorithm == "SHA256":
        hash_algorithm = hashes.SHA256()
    elif algorithm == "SHA512":
        hash_algorithm = hashes.SHA512()
    elif algorithm == "BLAKE2":
        hash_algorithm = hashes.BLAKE2b(64)
    else:
        raise Exception("Hash Algorithm name not found")

    mac = hmac.HMAC(key, hash_algorithm, backend=default_backend())

    mac.update(message)
    return mac.finalize()


"""3. This function is used to create a message that encapsulates a given message"""
def create_secure_message(
    message_to_encrypt, shared_key, symmetric_cipher, cipher_mode, digest_algorithm
):
    message = {
        "type": "MEDIA_FILES",
        "payload": None,
        "mac": None,
        "iv": None,
        "nonce": None,
        "tag": None,
    }

    cryptogram, iv, nonce, tag = symmetric_encrypt(
        str.encode(json.dumps(message_to_encrypt)),
        shared_key,
        symmetric_cipher,
        cipher_mode,
    )

    #Encrypt our message
    digest = mac_generator(cryptogram, shared_key, digest_algorithm)

    message["payload"] = base64.b64encode(cryptogram).decode()
    message["mac"] = base64.b64encode(digest).decode()

    if iv != None:
        message["iv"] = base64.b64encode(iv).decode()
    if nonce != None:
        message["nonce"] = base64.b64encode(nonce).decode()
    if tag != None:
        message["tag"] = base64.b64encode(tag).decode()

    return message


"""3. This function is used to encrypt a message using a symmetric key, a given algorithm and a mode"""
def symmetric_encryptor(message, key, algorithm_name, mode_name):
    cipher = None
    mode = None
    iv = None
    nonce = None
    tag = None

    #Check which mode we'll be using
    if mode_name == "ECB":
        mode = modes.ECB()
    elif mode_name == "CBC":
        if algorithm_name == "AES":
            iv = os.urandom(16)
        elif algorithm_name == "3DES":
            iv = os.urandom(8)
        mode = modes.CBC(iv)
    elif mode_name == "GCM":
        iv = os.urandom(12)
        mode = modes.GCM(iv)
    elif mode_name == "None":
        mode = None
    else:
        raise Exception("Mode name not found")

    #Check which algorithm we'll be using
    if algorithm_name == "AES":
        if mode == None:
            raise Exception("No mode was provided for AES")
        key = key[:16]
        block_size = algorithms.AES(key).block_size
        cipher = Cipher(algorithms.AES(key), mode, backend=default_backend())

    elif algorithm_name == "3DES":
        if mode == None or mode_name == "GCM":
            raise Exception("Mode provided isn't supported by 3DES")
        key = key[:8]
        block_size = algorithms.TripleDES(key).block_size
        cipher = Cipher(algorithms.TripleDES(key), mode, backend=default_backend())

    elif algorithm_name == "ChaCha20":
        if mode != None:
            raise Exception("ChaCha20 doesn't support any modes")
        key = key[:32]
        nonce = os.urandom(16)
        block_size = len(message)

        cipher = Cipher(
            algorithms.ChaCha20(key, nonce), mode=mode, backend=default_backend()
        )

    else:
        raise Exception("Algorithm name not found")

    encryptor = cipher.encryptor()
    padding = block_size - len(message) % block_size

    if algorithm_name == "AES":
        padding = 16 if padding == 0 else padding
    elif algorithm_name == "3DES":
        padding = 8 if padding == 0 else padding

    if algorithm_name != "ChaCha20":
        message += bytes([padding] * padding)

    cryptogram = encryptor.update(message) + encryptor.finalize()

    if mode_name == "GCM":
        tag = encryptor.tag

    return cryptogram, iv, nonce, tag

def symmetric_decryptor(
    cryptogram, key, algorithm_name, mode_name, iv=None, nonce=None, tag=None
):
    cipher = None
    mode = None

    if mode_name == "ECB":
        mode = modes.ECB()

    elif mode_name == "CBC":
        if iv == None:
            raise Exception("No IV was provided for the CBC mode")

        mode = modes.CBC(iv)

    elif mode_name == "GCM":
        if iv == None:
            raise Exception("No IV was provided for the GCM mode")
        if tag == None:
            raise Exception("No Tag was provided for the GCM mode")

        mode = modes.GCM(iv, tag)

    elif mode_name == "None":
        mode = None

    else:
        raise Exception("Mode name not found")

    if algorithm_name == "AES":
        if mode == None:
            raise Exception("No mode was provided for AES")
        key = key[:16]
        cipher = Cipher(algorithms.AES(key), mode, backend=default_backend())

    elif algorithm_name == "3DES":
        if mode == None or mode_name == "GCM":
            raise Exception("Mode provided isn't supported by 3DES")
        key = key[:8]
        cipher = Cipher(algorithms.TripleDES(key), mode, backend=default_backend())

    elif algorithm_name == "ChaCha20":
        if nonce == None:
            raise Exception("No Nonce was provided for ChaCha20")

        if mode != None:
            raise Exception("ChaCha20 doesn't support any modes")

        key = key[:32]

        cipher = Cipher(
            algorithms.ChaCha20(key, nonce), mode=mode, backend=default_backend()
        )

    else:
        raise Exception("Algorithm name not found")

    decryptor = cipher.decryptor()
    ct = decryptor.update(cryptogram) + decryptor.finalize()
    return ct