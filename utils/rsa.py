from argparse import ArgumentParser
from getpass import getpass
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

hash_functions = ["SHA-256", "SHA-384", "SHA-512"]

def generate_rsa_public_key(private_key, file_to_save=None):
    public_key = private_key.public_key()
    if file_to_save != None:

        pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                      format=serialization.PublicFormat.SubjectPublicKeyInfo)

        fileToSave_public_key = open(file_to_save, 'wb')
        fileToSave_public_key.write(pem)
        fileToSave_public_key.close()

    return public_key


def generate_rsa_private_key(keySize, file_to_save=None, password=None):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=keySize)

    if file_to_save != None:
        if password != None:
            password = password.encode()
            encrypt_algorithm = serialization.BestAvailableEncryption(password) 
        else:
            encrypt_algorithm = serialization.NoEncryption()

        pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL,
                                        encryption_algorithm=encrypt_algorithm)
        #write private key
        fileToSave_private_key = open(file_to_save,'wb')
        fileToSave_private_key.write(pem)
        fileToSave_private_key.close()

    return private_key


def generate_rsa_key_pair(keySize, file_to_save=None, password=None):
    private_key = generate_rsa_private_key(keySize, file_to_save, password)

    if file_to_save != None:
        file_to_save = str(file_to_save + ".pub")
    public_key = generate_rsa_public_key(private_key, file_to_save)
    
    return(private_key, public_key)


def load_rsa_public_key(source_file):
    key_file = open(source_file, 'rb')

    public_key = serialization.load_pem_public_key(key_file.read())
    key_file.close()

    return public_key


def load_rsa_private_key(source_file, password=None):
    if password != None:
        password = password.encode()
    key_file = open(source_file, 'rb')
    private_key = serialization.load_pem_private_key(key_file.read(), password=password)

    key_file.close()

    return private_key

def rsa_encryption(message, public_key, hash_function=None):
    if hash_function == "SHA-384":
        hashFunction = hashes.SHA384()
    elif hash_function == "SHA-512":
        hashFunction = hashes.SHA512()
    else:
        hashFunction = hashes.SHA256()

    message = message.encode()
    ciphertext = public_key.encrypt(message, padding.OAEP(mgf=padding.MGF1(hashFunction), algorithm=hashFunction,
                                                 label=None))
    return ciphertext


def rsa_decryption(ciphertext, private_key, hash_function=None):
    if hash_function == "SHA-384":
        hashFunction = hashes.SHA384()
    elif hash_function == "SHA-512":
        hashFunction = hashes.SHA512()
    elif hash_function == "BLAKE-2":
        hashFunction = hashes.BLAKE2s(32)
    else:
        hashFunction = hashes.SHA256()

    plaintext = private_key.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashFunction), algorithm=hashFunction,
                                                 label=None))
    plaintext = plaintext.decode()

    return plaintext


def rsa_sign(private_key, message):
    signature = private_key.sign(message,
                                 padding.PSS(mgf=padding.MGF1(hashes.SHA384()),
                                             salt_length=padding.PSS.MAX_LENGTH),
                                 hashes.SHA384())
    return signature


def rsa_verify(public_key, message, signature):
    try:
        public_key.verify(signature, message, padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=padding.PSS.MAX_LENGTH),
                      hashes.SHA384())
    except:
        return False
    else:
        return True