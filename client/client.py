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
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

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

"""Parameters"""
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2
params_numbers = dh.DHParameterNumbers(p, g)
parameters = params_numbers.parameters(default_backend())

SERVER_URL = 'http://127.0.0.1:8083'

licenses = {}

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
    elif (dige == "SHA3512"):
        digest = hashes.SHA3_512()
    return hmac.HMAC(key, digest, backend=default_backend())


"""This function is used to initialize the cipher based on the communication"""


def cipher(key, iv):
    global CSUIT

    alg, modo, dige = CSUIT.split("_")
    if (modo == 'CFB'):
        mode = modes.CFB(iv)
    elif (modo == 'CTR'):
        mode = modes.CTR(iv)
    elif (modo == 'OFB'):
        mode = modes.OFB(iv)
    if (alg == 'AES'):
        algorithm = algorithms.AES(key)
    elif (alg == 'SEED'):
        algorithm = algorithms.SEED(key)
    elif (alg == 'CAST5'):
        algorithm = algorithms.CAST5(key)
    elif (alg == 'TripleDES'):
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


# activesession é usado para ver se ja temos alguma sessao ja aberta ou nao
activesession = False


def main():
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    global activesession
    global ciphers
    global CSUIT
    global dKey

    if not activesession:
        # Get a list of media files
        print("...Contacting Server...")

        """Server receives "Hello" message"""
        posting = requests.post(f'{SERVER_URL}/api/hello', cookies=cookies, data="Hello")

        if posting.text != "hello":
            """Receive a user ID"""
            cookies['session_id'] = posting.text

            algorithms = ['AES', 'SEED', 'CAST5', 'TripleDES']
            modes = ['CFB', 'CTR', 'OFB']
            diges = ['SHA256', 'SHA512', 'SHA3256', 'SHA3512']
            code = 0

            for alg in algorithms:
                for mod in modes:
                    for dig in diges:
                        message = alg + '_' + mod + '_' + dig
                        posting = requests.post(f'{SERVER_URL}/api/csuit', data=message, cookies=cookies)
                        code = posting.status_code
                        if code == 200:
                            CSUIT = message
                            break
                    if code == 200:
                        break
                if code == 200:
                    break
            if (code != 200):
                return

            """Generate a private key for use in the exchange"""
            private_key = parameters.generate_private_key()

            """Generate a public key"""
            public_key = private_key.public_key()

            """Transform public key to be a readable and a sendable object"""
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)

            """Send the public key to the server and receive the server public key"""
            posting = requests.post(f'{SERVER_URL}/api/diffiehellman', data=pem, cookies=cookies)
            info = posting.json()

            """Get the IVs"""
            ivs = info['ivs']

            """Get the server public key"""
            server_public_key = serialization.load_pem_public_key(
                info['pem'].encode('latin'))

            """Exchange using our private key and the server's public key"""
            shared_key = private_key.exchange(server_public_key)

            """Key derivation"""
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=96,
                salt=None,
                info=b'handshake data').derive(shared_key)

            key1 = HKDF(
                algorithm=hashes.SHA256(),
                length=16,
                salt=None,
                info=b'handshake data').derive(derived_key[0:31])

            key2 = HKDF(
                algorithm=hashes.SHA256(),
                length=16,
                salt=None,
                info=b'handshake data').derive(derived_key[32:63])

            key3 = HKDF(
                algorithm=hashes.SHA256(),
                length=16,
                salt=None,
                info=b'handshake data').derive(derived_key[64:95])

            dKey = HKDF(
                algorithm=hashes.SHA256(),
                length=16,
                salt=None,
                info=b'handshake data').derive(key1 + key2 + key3)

            """Create and save ciphers + HMAC"""
            ciphers += [cipher(key1, ivs[0].encode('latin'))]
            ciphers += [cipher(key2, ivs[1].encode('latin'))]
            ciphers += [start_hmac(key3)]

        """Active session is true because there is an active session up and running"""
        activesession = True

    """Get the music list now that we have permission"""
    req = requests.get(f'{SERVER_URL}/api/list', cookies=cookies)
    if req.status_code == 200:
        print("Got Server List")

    media_list = json.loads(decrypt_data(req.content))

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

    # Detect if we are running on Windows or Linux
    # You need to have ffplay or ffplay.exe in the current folder
    # In alternative, provide the full path to the executable
    if os.name == 'nt':
        proc = subprocess.Popen(['ffplay.exe', '-i', '-'], stdin=subprocess.PIPE)
    else:
        proc = subprocess.Popen(['ffplay', '-i', '-'], stdin=subprocess.PIPE)

    # Get data from server and send it to the ffplay stdin through a pipe
    for chunk in range(media_item['chunks'] + 1):
        """Decrypt based on key rotation"""
        req = requests.get(f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}', cookies=cookies)
        encrypted_data = json.loads(decrypt_data(req.content))
        if ("error" in encrypted_data.keys()):
            break
        data_cypher = cipher(dKey, encrypted_data['iv'].encode('latin')).decryptor()
        dKey = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=None,
            info=b'handshake data').derive(dKey + encrypt_data(encrypted_data['data']))

        dcrypt = start_hmac(dKey).copy()
        dcrypt.update(encrypted_data['data'].encode('latin'))
        MAC = dcrypt.finalize()
        if (MAC != encrypted_data['HMAC'].encode('latin')):
            return "ERROR 500"

        decrypted = data_cypher.update(encrypted_data['data'].encode('latin')) + data_cypher.finalize()
        chunk = json.loads(decrypted.decode('latin'))

        data = binascii.a2b_base64(chunk['data'].encode('latin'))
        try:
            proc.stdin.write(data)
        except:
            break
    proc.stdin.close()
    proc.kill()
    proc.terminate()


if __name__ == '__main__':
    while True:
        main()
        time.sleep(1)
