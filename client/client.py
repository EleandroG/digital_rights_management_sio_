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
import server
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

#"""Parameters"""
#p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
#g = 2
#params_numbers = dh.DHParameterNumbers(p, g)
#parameters = params_numbers.parameters(default_backend())

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
def cryptography():
    #diffie helman
    req = requests.get(f'{SERVER_URL}/api/dh-parameters')
    if req.status_code == 200:
        print("Got dh-parameters")
    dh_param = req.json()
    #Get the private key and the number y
    dh_private_k = server.diffie_hellman_generate_private_key(dh_param)
    dh_public_num = server.diffie_hellman_generate_public_key(dh_private_k)

    #getting the server public number
    req = requests.post(f'{SERVER_URL}/api/dh-handshake', data=json.dumps([dh_public_num]).encode('latin'))   
    if req.status_code == 200:
        print("Got server public number")
    server_public_number_y = req.json()[0]

    #Calculate secret key to encrypt com
    secret_key = server.diffie_hellman_common_secret(dh_private_k, server_public_number_y)
    print("Got the key to encrypt communication")

    #Negotiate a cipher suite
    if req.status_code == 200:
        print("Got ciphers list")
    cipher_list = req.json()
    cipher_list[0] = random.choice(cipher_list[0]) # Algorithm
    cipher_list[1] = random.choice(cipher_list[1]) #Cipher
    cipher_list[2] = random.choice(cipher_list[2]) #Digest
    print(f"chosen ciphers:\n\tAlgorithm: {cipher_list[0]}\n\tCipher Mode: {cipher_list[1]}\n\tHash Function: {cipher_list[2]}")

    #Comunicate chosen cyphers to server
    req = requests.post(f'{SERVER_URL}/api/chosen-ciphers', data=json.dumps(cipher_list).encode('latin'))   
    if req.status_code == 200:
        print("Got server encrypted message")
    message = req.json()
    message = message["data"].encode('latin')
    #decrypt message
    message = server.decrypt(secret_key,message,cipher_list[0], cipher_list[1]).decode()
    print(f"server message:  {message}")
    return dh_param,dh_private_k,secret_key,cipher_list

def authentication():
    global OID_CLIENT
    client_nonce = os.urandom(64)
    encripted_client_nonce = server.encrypt(secret_key,client_nonce,
    cipher_list[0],cipher_list[1]).decode('latin')

    req = requests.post(f'{SERVER_URL}/api/server_auth',data = json.dumps(
        {"nonce":encripted_client_nonce}
    ).encode())
    if requests.status_code == 200:
        print("Received Certificated and Signed Nonce")

    data = req.json() #Validate the server certificate

    #decrypt the data
    server_nonce = data["server_nonce"].encode('latin')
    server_nonce = server.decrypt(secret_key,server_nonce,
    cipher_list[0],cipher_list[1])
    signed_client_nonce = data["signed_client_nonce"].encode('latin')
    signed_client_nonce = server.decrypt(secret_key,signed_client_nonce,cipher_list[0],cipher_list[1])
    server_cert = data["server_cert"].encode('latin')
    server_cert = server.decrypt(secret_key,server_cert,cipher_list[0],cipher_list[1])

    server_cert = server.certificate_from_pem(server_cert) # Por fazer

    cert_data = server.load_certificate_from_disk("../server_CA/CA.pem")


    cert = server.certificate_object_from_pem(cert_data)

    certificates = {}
    certificates[cert.subject.rfc4514_string()] = cert

    chain = []

    chain_completed = server.build_certificate_chain(chain,server_cert,certificates)

    if not chain_completed:
        print(" Certificated Chain is not completed")
        return False

    else:
        complete_Chain,error = server.validate_certificate_chain(chain)

        if not complete_Chain:
            print(error)
            return False
        else:
            if not server.verify_signature(server_cert,signed_client_nonce,client_nonce):
                return False
    print("SUCESS..Validated the server certicate chain and nonce signed by the server ")
    # Parte do Cartão de cidadão --->send cc info
    """session_success, session_data = utils.cc_session()

    if not session_success:
        print("Error establishing a new citizen card session: {session_data}")
        return False
    print("Citizen Card Session Open")
    client_cert = utils.certificate_cc(session_data)
    

    
    #encrypt client certs
    client_cert_enc = symmetriccrypt.encrypt(secret_key, client_cert, cipher_list[0], cipher_list[1]).decode('latin')
    signed_server_nonce = utils.sign_nonce_cc(session_data, server_nonce)
    signed_server_nonce_enc = symmetriccrypt.encrypt(secret_key, signed_server_nonce, cipher_list[0], cipher_list[1]).decode('latin')
    
    client_certs = {}
    client_certs["client_cc_certificate"] = client_cert_enc
    client_certs["signed_server_nonce"] = signed_server_nonce_enc

    #finalize auth
    req = requests.post(f'{SERVER_URL}/api/client_auth', data=json.dumps(client_certs).encode())
    if req.status_code == 200:
       print("Server finished citizen card certificatcion chain")
    
    data = req.json()
    status = symmetriccrypt.decrypt(secret_key, data["status"], cipher_list[0], cipher_list[1])
    if  status.decode() == "True":
        print("Sucessfully authenticated CC")
        oid = ObjectIdentifier("2.5.4.5")
        CLIENT_OID = utils.certificate_object(client_cert).subject.get_attributes_for_oid(oid)[0].value
        return True
    else:
        print("Could not authenticated CC")
        return False

    """
def rsa_exchange():
    private_key,public_key = server.generate_rsa_key_pair(2048, "../rsa_keys/cliente.pem")

    pubk_enc = server.encrypt(secret_key, 
        public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(), 
        cipher_list[0], 
        cipher_list[1]
    ).decode('latin')
    
    req = requests.post(f'{SERVER_URL}/api/rsa_exchange',
    data = json.dumps({"client_rsa_pub_key": pubk_enc}).encode()
    

    )

    if req.status_code == 200:
        print("Received Server public rsa key")

    data = req.json()

    server_rsa_public_key = data["server_rsa_public_key"].encode()
    server_rsa_public_key = server.decrypt(secret_key,server_rsa_public_key,
    cipher_list[0],cipher_list[1])

    fileToSave_public_key = open("../rsa_keys/server_rsa_pub_key.pub", 'wb')
    fileToSave_public_key.write(server_rsa_public_key)
    fileToSave_public_key.close()
    

def rsa_verify(public_key, message, signature):
    #message = message.encode()
    try:
        public_key.verify(signature,
                      message,
                      padding.PSS(mgf=padding.MGF1(hashes.SHA384()),
                                  salt_length=padding.PSS.MAX_LENGTH),
                      hashes.SHA384())
    except:
        #print("invalid signature")
        return False
    else:
        #print("valid signature")
        return True

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

        headers = {"oid":OID_CLIENT}
        
        """Active session is true because there is an active session up and running"""
        activesession = True

    request = requests.Session()
    request.headers.update(headers)

    """Get the music list now that we have permission"""
    req = requests.get(f'{SERVER_URL}/api/list', cookies=cookies)
    if req.status_code == 200:
        print("Got Server List")
    else:
        print(server.decrypt(secret_key,req.json(),cipher_list[0],
        cipher_list[1]).decode())
        sys.exit(0)

    media_list_enc = req.json()
    media_list = []
    id = 0
    for item in media_list_enc:
        media_list.append({
            "id" : server.decrypt(secret_key, media_list_enc[id]["id"], cipher_list[0], cipher_list[1]).decode(),
            "name" : server.decrypt(secret_key, media_list_enc[id]["name"], cipher_list[0], cipher_list[1]).decode(),
            "description" : server.decrypt(secret_key, media_list_enc[id]["description"], cipher_list[0], cipher_list[1]).decode(),
            "chunks" : int(server.decrypt(secret_key, media_list_enc[id]["chunks"], cipher_list[0], cipher_list[1]).decode()),
            "duration" : int(server.decrypt(secret_key, media_list_enc[id]["duration"], cipher_list[0], cipher_list[1]).decode())
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

    # Get data from server and send it to the ffplay stdin through a pipe
    for chunk in range(media_item['chunks'] + 1):
        """Decrypt based on key rotation"""
        req = requests.get(f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}', cookies=cookies)
        if not req.status_code == 200:
            print(server.decrypt(secret_key,req.json()['error'],cipher_list[0],cipher_list[1]).decode())

        chunk = req.json()

        data = binascii.a2b_base64(server.decrypt(secret_key,chunk['data'].encode('latin'),
        cipher_list[0],cipher_list[1]))
        data_signature = server.decrypt(secret_key,chunk['data_signature'],cipher_list(0),
        cipher_list[1])

        if not rsa_verify(server.load_rsa_private_key("../rsa_keys/server_rsa_pub_key.pub"),data,data_signature):
            print("The file sent from the server is not of trust")
            sys.exit(0)
        print("Chunk has a valid signature")
        try:
            proc.stdin.write(data)
        except:
            request.get(f'{SERVER_URL}/api/finished?id={media_item["id"]}')
            if req.status == 200:
                print(server.decrypt(secret_key,req.json(),cipher_list[0],cipher_list[1]).decode())
            break
        """
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
    """
    proc.kill()
    proc.terminate()


if __name__ == '__main__':
    dh_parameters, dh_private_key, secret_key, cipher_list = cryptography()

    authen = authentication()
    while True:
        rsa_exchange()
        main()
        time.sleep(1)
