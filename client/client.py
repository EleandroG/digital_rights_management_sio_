"""
83069 - Eleandro Laureano
78444 - Nuno Matamba
"""
from datetime import datetime, timedelta
import requests
import logging
import binascii
import json
import os
import subprocess
import time
import sys
sys.path.append(os.path.abspath('../utils'))
import utils
import rsa
import diffie_hellman
import secure

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
import random
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

"""Cookies used to determine the client ID"""
cookies = {'session_id': 'noID'}

"""Used in the server-client communication"""
CSUIT = ""

ciphers = []
dKey = b""

SERVER_URL = 'http://127.0.0.1:8083'

licenses = {}
OID_CLIENT = ''


"""This function is used to initialize hmac based on the communication"""
def start_hmac(key):
    global CSUIT

    alg, mod, dige = CSUIT.split("_")
    if (dige == "SHA256"):
        digest = hashes.SHA256()
    elif (dige == "SHA512"):
        digest = hashes.SHA512()
    elif (dige == "SHA3256"):
        digest = hashes.SHA3_256()
    return hmac.HMAC(key, digest, backend=default_backend())


"""This function is used to initialize the cipher based on the communication"""
def cipher(key, iv):
    global CSUIT

    alg, modo, dige = CSUIT.split("_")
    if (modo == 'CFB'):
        mode = modes.CFB(iv)
    elif (modo == 'ECB'):
        mode = modes.ECB(iv)
    elif (modo == 'OFB'):
        mode = modes.OFB(iv)
    if (alg == 'AES'):
        algorithm = algorithms.AES(key)
    elif (alg == '3DES'):
        algorithm = algorithms.TripleDES(key)

    cifra = Cipher(algorithm, mode)
    return cifra


"""This function is used to encrypt the data"""
def encrypt_data(data):
    global ciphers

    crypt = ciphers[1].encryptor()
    encrypted = crypt.update(data.encode('latin')) + crypt.finalize()
    crypt = ciphers[2].copy()
    crypt.update(encrypted)
    MAC = crypt.finalize()
    dict = {'data': encrypted.decode('latin'), 'HMAC': MAC.decode('latin')}
    crypt = ciphers[0].encryptor()
    return crypt.update(json.dumps(dict, indent=4).encode('latin')) + crypt.finalize()


"""This function is used to decrypt the data"""
def decrypt_data(data):
    global ciphers

    dcrypt = ciphers[0].decryptor()
    decrypted = dcrypt.update(data) + dcrypt.finalize()
    decrypted = json.loads(decrypted.decode('latin'))
    dcrypt = ciphers[2].copy()
    dcrypt.update(decrypted['data'].encode('latin'))
    MAC = dcrypt.finalize()
    if (MAC != decrypted['HMAC'].encode('latin')):
        return "ERROR 500"

    dcrypt = ciphers[1].decryptor()
    decrypted = dcrypt.update(decrypted['data'].encode('latin')) + dcrypt.finalize()
    return decrypted.decode('latin')


#activesession é usado para ver se ja temos alguma sessao ja aberta ou nao
activesession = False
def cryptography():
    #diffie helman
    req = requests.get(f'{SERVER_URL}/api/dh-parameters')
    if req.status_code == 200:
        print("Got dh-parameters")
    dh_parameters = req.json()
    #Get the private key and the number
    dh_private_k = diffie_hellman.diffie_hellman_generate_private_key(dh_parameters)
    dh_public_num = diffie_hellman.diffie_hellman_generate_public_key(dh_private_k)

    #getting the server public number
    req = requests.post(f'{SERVER_URL}/api/dh-handshake', data=json.dumps([dh_public_num]).encode('latin'))
    if req.status_code == 200:
        print("Got server public number")
    server_public_number_y = req.json()[0]

    #Calculate secret key to encrypt com
    secret_key = diffie_hellman.diffie_hellman_common_secret(dh_private_k, server_public_number_y)
    print("Got the key to encrypt communication")

    #Negotiate a cipher suite
    req = requests.get(f'{SERVER_URL}/api/cipher-suite')
    if req.status_code == 200:
        print("Got ciphers list")
    cipher_list = req.json()
    cipher_list[0] = random.choice(cipher_list[0]) #Algorithm
    cipher_list[1] = random.choice(cipher_list[1]) #Cipher
    cipher_list[2] = random.choice(cipher_list[2]) #Digest
    print(f"Chosen ciphers:\n\tAlgorithm: {cipher_list[0]}\n\tCipher Mode: "
          f"{cipher_list[1]}\n\tHash Function: {cipher_list[2]}")

    #Comunicate chosen cyphers to server
    req = requests.post(f'{SERVER_URL}/api/chosen-ciphers', data=json.dumps(cipher_list).encode('latin'))
    if req.status_code == 200:
        print("Got server encrypted message")
    message = req.json()
    message = message["data"].encode('latin')
    #decrypt message
    message = secure.decrypt(secret_key,message,cipher_list[0], cipher_list[1]).decode()
    print(f"server message:  {message}")
    return dh_parameters,dh_private_k,secret_key,cipher_list


def authentication():
    global OID_CLIENT

    client_nonce = os.urandom(64)
    encripted_client_nonce = secure.encrypt(secret_key,client_nonce,
    cipher_list[0],cipher_list[1]).decode('latin')
    req = requests.post(f'{SERVER_URL}/api/server_auth',data = json.dumps({"nonce":encripted_client_nonce}).encode())

    if req.status_code == 200:
        print("Received Certificated and Signed Nonce")

    data = req.json() #Validate the server certificate

    #decrypt the data
    server_nonce = data["server_nonce"].encode('latin')
    server_nonce = secure.decrypt(secret_key,server_nonce,
    cipher_list[0],cipher_list[1])
    signed_client_nonce = data["signed_client_nonce"].encode('latin')
    signed_client_nonce = secure.decrypt(secret_key,signed_client_nonce,cipher_list[0],cipher_list[1])
    server_cert = data["server_certificate"].encode('latin')
    server_cert = secure.decrypt(secret_key,server_cert,cipher_list[0],cipher_list[1])

    server_cert = utils.certificate_object_from_pem(server_cert)

    cert_data = utils.load_cert_from_disk("../server_CA/SIOServerCA.pem")
    cert = utils.certificate_object_from_pem(cert_data)

    certificates = {}
    certificates[cert.subject.rfc4514_string()] = cert

    chain = []

    chain_completed = utils.build_certificate_chain(chain,server_cert,certificates)

    if not chain_completed:
        print("Certificated Chain is not completed")
        return False

    else:
        complete_Chain,error = utils.validate_certificate_chain(chain)

        if not complete_Chain:
            print(error)
            return False
        else:
            if not utils.verify_signature(server_cert,signed_client_nonce,client_nonce):
                return False
    print("SUCCESS..Validated the server certificate chain and nonce signed by the server! ")


def rsa_exchange():
    private_key,public_key = rsa.generate_rsa_key_pair(2048, "../rsa_keys/cliente.pem")

    pubk_enc = secure.encrypt(secret_key,
        public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
        cipher_list[0],
        cipher_list[1]
    ).decode('latin')

    req = requests.post(f'{SERVER_URL}/api/rsa_exchange', data = json.dumps({"client_rsa_pub_key": pubk_enc}).encode())

    if req.status_code == 200:
        print("Received Server public rsa key")

    data = req.json()

    server_rsa_public_key = data["server_rsa_public_key"].encode()
    server_rsa_public_key = secure.decrypt(secret_key,server_rsa_public_key,
    cipher_list[0],cipher_list[1])

    fileToSave_public_key = open("../rsa_keys/server_rsa_pub_key.pub", 'wb')
    fileToSave_public_key.write(server_rsa_public_key)
    fileToSave_public_key.close()


def main():
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    global activesession
    global ciphers
    global CSUIT
    global dKey

    #Get a list of media files
    print("...Contacting Server...")

    headers = {"oid":OID_CLIENT}

    request = requests.Session()
    request.headers.update(headers)

    """Get the music list now that we have permission"""
    req = requests.get(f'{SERVER_URL}/api/list', cookies=cookies)
    if req.status_code == 200:
        print("Got Server List")
    else:
        print(secure.decrypt(secret_key,req.json(),cipher_list[0],
        cipher_list[1]).decode())
        sys.exit(0)

    media_list_enc = req.json()
    media_list = []
    id = 0
    for item in media_list_enc:
        media_list.append({
            "id" : secure.decrypt(secret_key, media_list_enc[id]["id"], cipher_list[0], cipher_list[1]).decode(),
            "name" : secure.decrypt(secret_key, media_list_enc[id]["name"], cipher_list[0], cipher_list[1]).decode(),
            "description" : secure.decrypt(secret_key, media_list_enc[id]["description"], cipher_list[0], cipher_list[1]).decode(),
            "chunks" : int(secure.decrypt(secret_key, media_list_enc[id]["chunks"], cipher_list[0], cipher_list[1]).decode()),
            "duration" : int(secure.decrypt(secret_key, media_list_enc[id]["duration"], cipher_list[0], cipher_list[1]).decode())
        })
        id += 1

    #media_list = json.loads(decrypt_data(req.content))

    """Menu"""
    index = 0
    print("MEDIA CATALOG\n")
    for item in media_list:
        d = datetime.now() + timedelta(minutes=5)
        print("TEMPO", d)
        licenses[index] = [1, d.timestamp()]
        print(f'{index} - {media_list[index]["name"]}')
        index += index
        print("Index", index)
    print("--------------------------------------------------------------------------------")

    while True:
        selection = input("Select a media file number (q to quit): ")
        if selection.strip() == 'q':
            posting = requests.post(f'{SERVER_URL}/api/bye', cookies=cookies,
                                    data=encrypt_data("bye message encrypted"))
            sys.exit(0)

        if not selection.isdigit():
            continue

        selection = int(selection)
        if 0 <= selection < len(media_list):
            if licenses.get(int(selection))[0] == 0 or datetime.now().timestamp() > licenses.get(int(selection))[1]:
                continue
            licenses[selection][0] -= 1
            print(licenses.get(int(selection))[0])
            break


    media_item = media_list[selection]
    print(f"Playing {media_item['name']}")
    print(media_item['chunks'])
    # Detect if we are running on Windows or Linux
    # You need to have ffplay or ffplay.exe in the current folder
    # In alternative, provide the full path to the executable
    if os.name == 'nt':
        proc = subprocess.Popen(['ffplay.exe', '-i', '-'], stdin=subprocess.PIPE)
    else:
        proc = subprocess.Popen(['ffplay', '-i', '-'], stdin=subprocess.PIPE)

    #Get data from server and send it to the ffplay stdin through a pipe
    for chunk in range(media_item['chunks'] + 1):
        """Decrypt based on key rotation"""
        req = requests.get(f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}')

        if not req.status_code == 200:
            print(secure.decrypt(secret_key,req.json()['error'],cipher_list[0],cipher_list[1]).decode())

        chunk = req.json()

        data = binascii.a2b_base64(secure.decrypt(secret_key,chunk['data'].encode('latin'),
        cipher_list[0],cipher_list[1]))
        data_signature = secure.decrypt(secret_key,chunk['data_signature'], cipher_list[0],cipher_list[1])

        if not rsa.rsa_verify(rsa.load_rsa_public_key("../rsa_keys/server_rsa_pub_key.pub"), data,data_signature):
            print("The file sent from the server is not of trust")
            sys.exit(0)
        print("Chunk has a valid signature")
        try:
            proc.stdin.write(data)
        except:
            request.get(f'{SERVER_URL}/api/finished?id={media_item["id"]}')
            if req.status_code == 200:
                print(secure.decrypt(secret_key,req.json(),cipher_list[0],cipher_list[1]).decode())
            break


if __name__ == '__main__':
    dh_parameters, dh_private_key, secret_key, cipher_list = cryptography()

    authen = authentication()
    while True:
        rsa_exchange()
        main()
        time.sleep(1)
