#!/usr/bin/env python

"""
83069 - Eleandro Laureano
78444 - Nuno Matamba
"""
from secrets import token_bytes
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from twisted.web import server, resource
from twisted.internet import reactor, defer
from getpass import getpass
from base64 import b64encode, b64decode
from cryptography import x509
from cryptography.x509 import ObjectIdentifier
import logging
import binascii
import json
import os
import math
import requests
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime
from cryptography.x509.oid import ExtensionOID
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.x509.extensions import CRLDistributionPoints
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)

CATALOG = {'898a08080d1840793122b7e118b27a95d117ebce':
    {
        'name': 'Sunny Afternoon - Upbeat Ukulele Background Music',
        'album': 'Upbeat Ukulele Background Music',
        'description': 'Nicolai Heidlas Music: http://soundcloud.com/nicolai-heidlas',
        'duration': 3 * 60 + 33,
        'file_name': '898a08080d1840793122b7e118b27a95d117ebce.mp3',
        'file_size': 3407202
    }
}

CATALOG_BASE = 'catalog'
CHUNK_SIZE = 1024 * 4

algs = ['AES', '3DES', 'ChaCha20']
mods = ['ECB', 'CFB', 'OFB']
digest_algorithms = ['SHA256', 'SHA512', 'SHA3256']

ciphers = {}
dKey = {}
readings = {}
users = []
CSUIT = {}


"""This function is used to generate a key"""
def generate_key(algorithm, salt, password):
    if type(password) != type(b""):
        password = password.encode()

    if algorithm == '3DES':
        length = 24
    elif algorithm == 'ChaCha20':
        length = 32
    else:
        length = 16
    pbkdf = PBKDF2HMAC(salt=salt, algorithm=hashes.SHA256(), iterations=10**5, length=length,
                       backend=default_backend())
    key = pbkdf.derive(password)

    return key

def add_padding(message_block, algorithm):
    if algorithm == "3DES":
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


"""This function is used to encrypt the data"""
def encrypt(password, message, algorithm_name, cipherMode=None):
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
    if algorithm_name != "ChaCha20" and cipherMode != "ECB":
        iv = token_bytes(block_length)

    if cipherMode == "CFB":
        cipher_mode = modes.CFB(iv)
    elif cipherMode == "OFB":
        cipher_mode = modes.OFB(iv)
    elif cipherMode == "ECB":
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


"""This function is used to decrypt the data"""
def decrypt(password, encrypted_message, algorithm_name, cipherMode=None):
    message = b""
    pointer = 0

    salt = encrypted_message[pointer:pointer + math.ceil(16 / 3) * 4]
    pointer += math.ceil(16 / 3) * 4
    salt = b64decode(salt)
    key = generate_key(algorithm_name, salt, password)


    if algorithm_name == 'ChaCha20':
        nonce = encrypted_message[pointer:pointer + math.ceil( 16 / 3) *4]
        pointer += math.ceil(16 / 3) * 4
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
        iv = encrypted_message[pointer:pointer + math.ceil(block_length / 3) * 4]
        pointer+= math.ceil(block_length / 3) * 4
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
    next_block = b64decode(encrypted_message[pointer:pointer + math.ceil(block_length / 3) * 4])
    pointer+= math.ceil(block_length / 3) * 4

    while True:
        block = next_block
        next_block = b64decode(encrypted_message[pointer:pointer + math.ceil(block_length /3 ) *4])
        pointer+= math.ceil(block_length/3)*4
        block = decryptor.update(block)

        if next_block == b"":
            break
        message = message + block

    if algorithm_name != "ChaCha20":
        block = remove_padding(block)

    message = message + block

    return message


"""This function is used to return the Diffie Hellman parameters"""
def diffie_hellman_parameters(key_size=2048):
    parameters = dh.generate_parameters(generator=2, key_size=key_size)
    parameter_numbers = parameters.parameter_numbers()
    p = parameter_numbers.p
    g = parameter_numbers.g

    return [p,g]

"""This function is used to return the derived key"""
def diffie_hellman_common_secret(my_private_key, peer_public_number_y):
    parameters = my_private_key.parameters()
    parameter_numbers = parameters.parameter_numbers()

    peer_public_numbers = dh.DHPublicNumbers(peer_public_number_y, parameter_numbers)

    peer_public_key = peer_public_numbers.public_key()

    shared_key = my_private_key.exchange(peer_public_key)

    derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data').derive(shared_key)
    return derived_key


"""This function is used to generate a private key used in the exchange"""
def diffie_hellman_generate_private_key(parameters):
    p = parameters[0]
    g = parameters[1]
    parameter_numbers = dh.DHParameterNumbers(p, g)
    parameters = parameter_numbers.parameters()

    private_key = parameters.generate_private_key()
    return private_key


"""This function is used to generate e public key"""
def diffie_hellman_generate_public_key(private_key):
    public_key = private_key.public_key()
    public_number_y = public_key.public_numbers().y
    return public_number_y


"""This function is used to generate a public key"""
def generate_rsa_public_key(private_key, file_to_be_saved=None):
    public_key = private_key.public_key()

    if file_to_be_saved != None:
        pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                      format=serialization.PublicFormat.SubjectPublicKeyInfo)
        file_to_be_saved_public_key = open(file_to_be_saved, 'wb')
        file_to_be_saved_public_key.write(pem)
        file_to_be_saved_public_key.close()

    return public_key


"""This function is used to generate a private key"""
def generate_rsa_private_key(key_size, file_to_be_saved=None, password=None):
    private_key = generate_private_key(public_exponent=65537, key_size=key_size)

    if file_to_be_saved != None:
        if password != None:
            password = password.encode()
            encrypt_algorithm = serialization.BestAvailableEncryption(password)
        else:
            encrypt_algorithm = serialization.NoEncryption()

        pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                        encryption_algorithm=encrypt_algorithm)

        file_to_be_saved_private_key = open(file_to_be_saved, 'wb')
        file_to_be_saved_private_key.write(pem)
        file_to_be_saved_private_key.close()

    return private_key


def generate_rsa_key_pair(key_size, file_to_be_saved=None, password=None):
    private_key = generate_rsa_private_key(key_size, file_to_be_saved, password)

    if file_to_be_saved != None:
        file_to_be_saved = str(file_to_be_saved + ".pub")
    public_key = generate_rsa_public_key(private_key, file_to_be_saved)

    return (private_key, public_key)


def load_rsa_private_key(sorceFile_name, password=None):
    if password != None:
        password = password.encode()

    key_file = open(sorceFile_name, 'rb')
    private_key = serialization.load_pem_private_key(key_file.read(),
                                                     password=password)
    key_file.close()

    return private_key


def rsa_sign(private_key,message):
    signature = private_key.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA384()),
                                                      salt_length=padding.PSS.MAX_LENGTH), hashes.SHA384())
    return signature


def certificate_object(certificate):
    return x509.load_der_x509_certificate(
        certificate,
        default_backend()
    )

def certificate_object_from_pem(pem_data):
    return x509.load_pem_x509_certificate(pem_data, default_backend())


def load_certificate_from_disk(file_name):
    with open(file_name, 'rb') as file:
        pem_data = file.read()
    return pem_data


def certificate_chain(chain, cert, certificates):
    chain.append(cert)

    issuer = cert.issuer.rfc4514_string()
    subject = cert.subject.rfc4514_string()

    if issuer == subject and subject in certificates:
        return True

    if issuer in certificates:
        return certificate_chain(chain, certificates[issuer], certificates)

    return False


def build_certificate_chain(chain, cert, certificates):
    chain.append(cert)

    issuer = cert.issuer.rfc4514_string()
    subject = cert.subject.rfc4514_string()

    if issuer == subject and subject in certificates:
        return True

    if issuer in certificates:
        return build_certificate_chain(chain, certificates[issuer], certificates)

    return False


def validate_certificate_chain(chain):
    error_messages = []
    try:
        return (validate_purpose_certificate_chain(chain,error_messages)
                and validity_certificate_chain_validation(chain, error_messages)
                and validate_revocation_certificate_chain_crl(chain,error_messages)
                and validate_signatures_certificate_chain(chain, error_messages)), error_messages
    except Exception as e:
        error_messages.append("An error occurred while verifying the certificate chain")
        return False, error_messages


def validate_purpose_certificate_chain(chain, error_messages):
    result = certificate_without_purposes(chain[0], ["key_cert_sign", "crl_sign"])
    for i in range(1, len(chain)):

        if not result:

            error_messages.append("The purpose of at least one chain certificate is wrong")
            return result

        result = certificate_without_purposes(chain[i], ["digital_signature", "content_commitment", "key_encipherment", "data_encipherment"])

    if not result:
        error_messages.append("The purpose of at least one chain certificate is not correct")
    return result


def validity_certificate_chain_validation(chain, error_messages):
    for cert in chain:
        dates = (cert.not_valid_before.timestamp(), cert.not_valid_after.timestamp())

        if datetime.now().timestamp() < dates[0] or datetime.now().timestamp() > dates[1]:
            error_messages.append("One of the chain certificates is not valid")
            return False
    return True


def revoked_certificate_validation(serial_number, crl_url):
    r = requests.get(crl_url)
    try:
        crl = x509.load_der_x509_crl(r.content, default_backend())
    except ValueError as e:
        crl = x509.load_pem_x509_crl(r.content, default_backend())
    return crl.get_revoked_certificate_by_serial_number(serial_number) is not None


def validate_revocation_certificate_chain_crl(chain, error_messages):
    for i in range(1, len(chain)):
        subject = chain[i - 1]
        issuer = chain[i]
        for e in issuer.extensions:
            if isinstance(e.value, CRLDistributionPoints):
                crl_url = e.value._distribution_points[0].full_name[0].value
                if revoked_certificate_validation(subject.serial_number,crl_url):
                    error_messages.append("One of the certificates is revoked")
                    return False
    return True


def validate_signatures_certificate_chain(chain, error_messages):
    for i in range(1, len(chain)):
        try:
            subject = chain[i - 1]
            issuer = chain[i]
            issuer_public_key = issuer.public_key()
            issuer_public_key.verify(
                subject.signature,
                subject.tbs_certificate_bytes,
                padding.PKCS1v15(),
                subject.signature_hash_algorithm,
            )
        except InvalidSignature:
            error_messages.append("One of the certificates isn't signed by its issuer")
            return False
    return True


def certificate_without_purposes(certificate, purposes):
    result = True
    for purpose in purposes:
        result &= not getattr(certificate.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value, purpose)
    return result


def verify_signature(certificate, signature, nonce):
    try:
        issuer_public_key = certificate.public_key()
        issuer_public_key.verify(
            signature,
            nonce,
            padding.PKCS1v15(),
            hashes.SHA1(),
        )
    except InvalidSignature:
        return False

    return True


def load_private_key_file(path):
    with open(path, "rb") as key_file:
        pem = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
        return pem


def sign_with_private_key(pk, nonce):
    return pk.sign(nonce, padding.PKCS1v15(), hashes.SHA1())


def load_cert_from_disk(file_name):
    with open(file_name, 'rb') as file:
        pem_data = file.read()

    return pem_data


class MediaServer(resource.Resource):
    isLeaf = True

    def __init__(self):
        self.dh_parameters = None
        self.diffie_hellman_private_key = None
        self.secret_key = None
        self.ciphers = None
        self.server_nonce = None
        self.users = []


    #Send the list of media files to clients
    def do_list(self, request):
        #Build list
        media_list = []
        for media_id in CATALOG:
            media = CATALOG[media_id]
            media_list.append({
                'id': encrypt(self.secret_key, media_id, self.ciphers[0], self.ciphers[1]).decode('latin'),
                'name': encrypt(self.secret_key, media['name'], self.ciphers[0], self.ciphers[1]).decode('latin'),
                'description': encrypt(self.secret_key, media['description'], self.ciphers[0],
                                       self.ciphers[1]).decode('latin'),
                'chunks': encrypt(self.secret_key, str(math.ceil(media['file_size'] / CHUNK_SIZE)),
                                  self.ciphers[0], self.ciphers[1]).decode('latin'),
                'duration': encrypt(self.secret_key, str(media['duration']), self.ciphers[0],
                                    self.ciphers[1]).decode('latin')
            })

        #Return list to client
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps(media_list, indent=4).encode('latin')


    #Send a media chunk to the client
    def do_download(self, request):
        logger.debug(f'Download: args: {request.args}')

        media_id = request.args.get(b'id', [None])[0]
        logger.debug(f'Download: id: {media_id}')

        #Check if the media_id is not None as it is required
        if media_id is None:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': encrypt(self.secret_key, 'invalid media id', self.ciphers[0],
                                                self.ciphers[1]).decode('latin')}).encode('latin')

        #Convert bytes to str
        media_id = media_id.decode('latin')

        #Search media_id in the catalog
        if media_id not in CATALOG:
            request.setResponseCode(404)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': encrypt(self.secret_key, 'media file not found', self.ciphers[0],
                                                               self.ciphers[1]).decode('latin')}).encode('latin')

        #Get the media item
        media_item = CATALOG[media_id]

        #Check if a chunk is valid
        chunk_id = request.args.get(b'chunk', [b'0'])[0]
        valid_chunk = False
        try:
            chunk_id = int(chunk_id.decode('latin'))
            if chunk_id >= 0 and chunk_id < math.ceil(media_item['file_size'] / CHUNK_SIZE):
                valid_chunk = True
        except:
            logger.warn("Chunk format is invalid")

        if not valid_chunk:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': encrypt(self.secret_key, 'invalid chunk id', self.ciphers[0],
                                                               self.ciphers[1]).decode('latin')}).encode('latin')

        logger.debug(f'Download: chunk: {chunk_id}')
        offset = chunk_id * CHUNK_SIZE

        #Open file, seek to correct position and return the chunk
        with open(os.path.join(CATALOG_BASE, media_item['file_name']), 'rb') as f:
            f.seek(offset)
            data = f.read(CHUNK_SIZE)

            data_signature = rsa_sign(load_rsa_private_key("rsa_key.pem"), data)


            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({
                    'media_id': encrypt(self.secret_key, media_id, self.ciphers[0], self.ciphers[1]).decode('latin'),
                    'chunk': encrypt(self.secret_key, str(chunk_id), self.ciphers[0], self.ciphers[1]).decode('latin'),
                    'data': encrypt(self.secret_key, binascii.b2a_base64(data).decode('latin').strip(),
                                    self.ciphers[0], self.ciphers[1]).decode('latin'),
                    'data_signature': encrypt(self.secret_key, data_signature, self.ciphers[0],
                                                             self.ciphers[1]).decode('latin')},
                indent=4).encode('latin')

        #File was not open?
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps({'error': encrypt(self.secret_key, 'unknown', self.ciphers[0],
                                            self.ciphers[1]).decode('latin')}, indent=4).encode('latin')


    """Handle a GET request"""
    def render_GET(self, request):
        logger.debug(f'Received request for {request.uri}')

        try:

            if request.path == b'/api/protocols':
                return self.do_get_protocols(request)

            elif request.path == b'/api/dh-parameters':
                dh_parameters = diffie_hellman_parameters()
                self.dh_parameters = dh_parameters
                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                return json.dumps(dh_parameters, indent=4).encode('latin')

            elif request.path == b'/api/cipher-suite':
                list_of_ciphers = [algs, mods, digest_algorithms]
                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                return json.dumps(list_of_ciphers, indent=4).encode('latin')

            elif request.path == b'/api/list':
                return self.do_list(request)

            elif request.path == b'/api/download':
                return self.do_download(request)

            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods: /api/list /api/download'

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''


    """Handle a POST request"""
    def render_POST(self, request):
        logger.debug(f'Received POST for {request.uri}')
        try:

            if request.uri == b'/api/rsa_exchange':
                return self.rsa_exchange(request)
            elif request.uri == b'/api/server_auth':
                return self.server_authentication(request)
            elif request.uri == b'/api/client_auth':
                return self.client_authentication(request)

            if request.path == b'/api/dh-handshake':
                """Generate a private key, a public key and public number of client"""
                public_number_of_client = json.loads(request.content.read())[0]
                self.diffie_hellman_private_key = diffie_hellman_generate_private_key(self.dh_parameters)
                diffie_hellman_public_number = diffie_hellman_generate_public_key(self.diffie_hellman_private_key)
                self.secret_key = diffie_hellman_common_secret(self.diffie_hellman_private_key, public_number_of_client)
                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                return json.dumps([diffie_hellman_public_number], indent=4).encode('latin')

            elif request.path == b'/api/chosen-ciphers':
                """Generate a client public key"""
                self.ciphers = json.loads(request.content.read())
                print(self.ciphers)
                message = "The Cryptography Pattern was established"
                message = encrypt(self.secret_key, message, self.ciphers[0], self.ciphers[1])
                #print(message)
                message = message.decode('latin')
                #print(message)
                #print(type(message))
                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                return json.dumps({"data": message}, indent=4).encode('latin')

            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods: /api/protocols /api/list /api/download'

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''


    def server_authentication(self, request):
        dict = request.content.read()
        data = json.loads(dict)
        logger.debug(f"Received nonce from client")

        client_nonce = data["nonce"].encode('latin')
        client_nonce = decrypt(self.secret_key, client_nonce, self.ciphers[0], self.ciphers[1])

        private_key = load_private_key_file("ServerCertKey.pem")
        signed_client_nonce = sign_with_private_key(private_key, client_nonce)
        certificate = load_cert_from_disk("ServerCert.pem")

        self.server_nonce = os.urandom(64)

        certificate = encrypt(self.secret_key, certificate, self.ciphers[0], self.ciphers[1]).decode('latin')
        signed_client_nonce = encrypt(self.secret_key, signed_client_nonce, self.ciphers[0], self.ciphers[1]).decode('latin')
        server_nonce = encrypt(self.secret_key, self.server_nonce, self.ciphers[0], self.ciphers[1]).decode('latin')

        return json.dumps({
                "server_certificate": certificate,
                "signed_client_nonce": signed_client_nonce,
                "server_nonce": server_nonce
            }).encode('latin')


    def client_authentication(self, request):
        dict = request.content.read()
        data = json.loads(dict)

        signed_server_nonce = data["signed_server_nonce"].encode('latin')
        signed_server_nonce = decrypt(self.secret_key, signed_server_nonce,
                                                     self.ciphers[0], self.ciphers[1])

        client_cc_certificate = data["client_cc_certificate"].encode('latin')
        client_cc_certificate = decrypt(self.secret_key, client_cc_certificate,
                                                       self.ciphers[0], self.ciphers[1])

        client_cc_certificate = certificate_object(client_cc_certificate)
        logger.debug(f"Received Client Certificate and signed Nonce")

        path = "../certificates1"
        certificates = {}

        for filename in os.listdir(path):
            if filename.endswith(".pem"):
                certificate_data = load_certificate_from_disk(os.path.join(path, filename))
                certificate = certificate_object_from_pem(certificate_data)
                certificates[certificate.subject.rfc4514_string()] = certificate

        chain = []
        chain_completed = build_certificate_chain(chain, client_cc_certificate, certificates)

        if not chain_completed:
            logger.debug(f"Didn't complete the certificate chain")
            status = False

        else:
            valid_chain, error_messages = validate_certificate_chain(chain)

            if not valid_chain:
                logger.debug(error_messages)
                status = False
            else:
                status = verify_signature(client_cc_certificate, signed_server_nonce, self.server_nonce)

        if status:
            logger.debug(f"Client certificate chain validated and nonce signed by the client")
            object_identifier = ObjectIdentifier("2.5.4.5")
            self.users.append(client_cc_certificate.subject.get_attributes_for_oid(object_identifier)[0].value)

            logger.debug(f"User logged in with success")

        status_enc = encrypt(self.secret_key, str(status), self.ciphers[0], self.ciphers[1]).decode('latin')

        return json.dumps({"status": status_enc}).encode('latin')


    def rsa_exchange(self, request):
        private_key, public_key = generate_rsa_key_pair(2048, "rsa_key.pem")

        dict = request.content.read()
        data = json.loads(dict)

        rsa_public_key = data["client_rsa_pub_key"].encode()
        rsa_public_key = decrypt(self.secret_key, rsa_public_key, self.ciphers[0], self.ciphers[1])

        file_to_be_saved_public_key = open("public_k.pem", 'wb')
        file_to_be_saved_public_key.write(rsa_public_key)
        file_to_be_saved_public_key.close()
        logger.debug(f"Received Client Public RSA Key")

        pubk_enc = encrypt(self.secret_key, public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                                    format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
                           self.ciphers[0], self.ciphers[1]).decode('latin')

        return json.dumps({"server_rsa_public_key":pubk_enc}).encode('latin')


print("Server started")
print("URL is: http://IP:8083")

s = server.Site(MediaServer())
reactor.listenTCP(8083, s)
reactor.run()
