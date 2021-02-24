#!/usr/bin/env python

"""
83069 - Eleandro Laureano
78444 - Nuno Matamba
"""

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

algs = ['AES', '3DES']
mods = ['ECB', 'CFB', 'OFB']
digest_algorithms = ['SHA256', 'SHA512', 'SHA3256']

ciphers = {}
dKey = {}
readings = {}
users = []
CSUIT = {}


"""This function is used to generate a key"""
def generate_key(algorithm, salt):
    password = getpass()
    password = password.encode()

    if algorithm == 'AES':
        length = 16
    else:
        length = 24

    pbkdf = PBKDF2HMAC(salt=salt, algorithm=hashes.SHA256(), iterations=10 ** 5, length=length,
                       backend=default_backend()
                       )

    key = pbkdf.derive(password)
    return key


"""This function is used to encrypt the data"""
def encrypt(algorithm, cipherMode, file_to_be_encrypted, file_to_be_saved):
    salt = os.urandom(16)
    key = generate_key(algorithm, salt)

    if algorithm == 'AES':
        block_size = 16
        algorithm = algorithms.AES(key)
    else:
        block_size = 8
        algorithm = algorithms.TripleDES(key)

    iv = None
    if cipherMode == 'ECB':
        cipher_mode = modes.ECB(iv)
    elif cipherMode == 'CFB':
        cipher_mode = modes.CFB(iv)
    else:
        cipher_mode = modes.OFB(iv)

    cipher = Cipher(algorithm, cipher_mode)
    encryptor = cipher.encryptor()

    encrypted_file = open(file_to_be_encrypted, 'r')
    saved_file = open(file_to_be_saved, 'wb')

    saved_file.write(b64encode(salt))
    if iv != None:
        saved_file.write(b64encode(iv))

    while True:
        block = encrypted_file.read(block_size)
        if block == "":
            break

        if len(block) != block_size:
            break

        block = encryptor.update(block.encode())
        saved_file.write(b64encode(block))
        block = block.encode()
        block = encryptor.update(block)

        saved_file.write(b64encode(block))

        encrypted_file.close()
        saved_file.close()


"""This function is used to decrypt the data"""
def decrypt(algorithm, cipherMode, file_to_be_decrypted, file_to_be_saved):
    decrypted_file = open(file_to_be_decrypted, 'rb')
    saved_file = open(file_to_be_saved, 'w')

    salt = decrypted_file.read(math.ceil(16 / 3) * 4)
    salt = b64decode(salt)
    key = generate_key(algorithm, salt)

    if algorithm == 'AES':
        block_size = 16
        algorithm = algorithms.AES(key)
    else:
        block_size = 8
        algorithm = algorithms.TripleDES(key)

    iv = None
    if cipherMode == 'ECB':
        cipher_mode = modes.ECB(iv)
    elif cipherMode == 'CFB':
        cipher_mode = modes.CFB(iv)
    else:
        cipher_mode = modes.OFB(iv)

    cipher = Cipher(algorithm, cipher_mode)
    decryptor = cipher.decryptor()
    next_block = b64decode(decrypted_file.read(math.ceil(block_size / 3) * 4))

    while True:
        block = next_block
        next_block = b64decode(decrypted_file.read(math.ceil(block_size / 3) * 4))
        block = decryptor.update(block)
        if next_block == b"":
            break
        saved_file.write(block.decode())

    saved_file.write(block.decode())
    decrypted_file.close()
    saved_file.close()

"""This function is used to return the Diffie Hellman parameters"""
def diffie_hellman_parameters(key=2048):
    parameters = dh.generate_parameters(generator=2, key_size=key)
    return parameters

"""This function is used to return the derived key"""
def diffie_hellman_common_secret(peer_public_key, private_key):
    shared_key = private_key.exchange(peer_public_key)
    derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data').derive(shared_key)
    return derived_key

"""This function is used to generate a private key used in the exchange"""
def diffie_hellman_generate_private_key(parameters):
    private_key = parameters.generate_private_key()
    return private_key

"""This function is used to generate e public key"""
def diffie_hellman_generate_public_key(private_key):
    public_key = private_key.public_key()
    return public_key

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


class MediaServer(resource.Resource):
    isLeaf = True

    def __init__(self):
        self.diffie_hellman_parameters = None
        self.diffie_hellman_private_key = None
        self.secret_key = None
        self.ciphers = None
        self.nonce = None
        self.users = []

    #Send the list of media files to clients
    def do_list(self, request):

        # object identifier OID
        # auth = request.getHeader('Authorization')
        # if not auth:
        #    request.setResponseCode(401)
        #    return 'Not authorized'

        #object_identifier = request.getHeader('Object Identifier')
        #if object_identifier not in self.users:
        #    request.setResponseCode(401)
        #    return json.dumps(encrypt(self.secret_key, 'Not authorized', self.ciphers[0],
        #                                             self.ciphers[1]).decode('latin')).encode()

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
    def do_download(self, request, who):
        logger.debug(f'Download: args: {request.args}')

        media_id = request.args.get(b'id', [None])[0]
        logger.debug(f'Download: id: {media_id}')

        #Object identifier
        #object_identifier = request.getHeader('oid')
        #if object_identifier not in self.users:
        #    request.setResponseCode(401)
        #    return json.dumps(encrypt(self.secret_key, 'Not authorized', self.ciphers[0],
        #                              self.ciphers[1]).decode('latin')).encode()

        #Check if the media_id is not None as it is required
        if media_id is None:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': encrypt(self.secret_key, 'invalid Media ID',
                                                self.ciphers[0], self.ciphers[1]).decode('latin')}).encode('latin')

        #Convert bytes to str
        media_id = media_id.decode('latin')

        #Search media_id in the catalog
        if media_id not in CATALOG:
            request.setResponseCode(404)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': encrypt(self.secret_key, 'media file not found',
                                                               self.ciphers[0],
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
            return json.dumps({'error': encrypt(self.secret_key, 'invalid chunk id',
                                                               self.ciphers[0],
                                                               self.ciphers[1]).decode('latin')}).encode('latin')

        # if(who not in readings.keys()):
        #    readings[who] = {media_id:0}
        # elif(media_id not in readings[who].keys()):
        #    readings[who][media_id] = 0

        # logger.debug(f'Download: chunk: {chunk_id} - readingsByChunk: {math.ceil((readings[who][media_id]*100) / media_item["file_size"])/100} ')

        logger.debug(f'Download: chunk: {chunk_id}')

        offset = chunk_id * CHUNK_SIZE

        #readings[who][media_id] += CHUNK_SIZE

        #Open file, seek to correct position and return the chunk
        with open(os.path.join(CATALOG_BASE, media_item['file_name']), 'rb') as f:
            f.seek(offset)
            data = f.read(CHUNK_SIZE)

            #signature!  a ir buscar os rsa's
            #data_signature = rsa_sign(rsa_utils.load_rsa_private_key(), data)

            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps(
                {
                    'media_id': encrypt(self.secret_key, media_id, self.ciphers[0], self.ciphers[1]).decode('latin'),
                    'chunk': encrypt(self.secret_key, str(chunk_id), self.ciphers[0], self.ciphers[1]).decode('latin'),
                    'data': encrypt(self.secret_key, binascii.b2a_base64(data).decode('latin').strip(),
                                    self.ciphers[0], self.ciphers[1]).decode('latin'),
                    #'data_signature': symmetriccrypt.encrypt(self.secret_key, data_signature, self.client_chosen_ciphers[0], self.client_chosen_ciphers[1]).decode('latin')
                }, indent=4
            ).encode('latin')

        #File was not open?
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps({'error': encrypt(self.secret_key, 'unknown', self.ciphers[0],
                                            self.ciphers[1]).decode('latin')}, indent=4).encode('latin')

    #server authenticate
    def client_authentication(self, request):
        dict = request.content.read()
        data = json.loads(dict)

        server_nonce = data["server_nonce"].encode('latin')
        server_nonce = decrypt(self.secret_key, server_nonce,
                                                     self.ciphers[0], self.ciphers[1])

        client_cc_certificate = data["client_cc_certificate"].encode('latin')
        client_cc_certificate = decrypt(self.secret_key, client_cc_certificate,
                                                       self.ciphers[0], self.ciphers[1])

        client_cc_certificate = certificate_object(client_cc_certificate)
        logger.debug(f"Received Client Certificate and signed Nonce")

        path = "../cc_certificates"
        certificates = {}

        for filename in os.listdir(path):
            if filename.endswith(".pem"):
                certificate_data = load_certificate_from_disk(os.path.join(path, filename))
                certificate = certificate_object_from_pem(certificate_data)
                certificates[certificate.subject.rfc4514_string()] = certificate

        chain = []
        chain_completed = build_certificate_chain(chain, client_cc_certificate, certificates)

        if not chain_completed:
            logger.debug(f"Couldn't complete the certificate chain")
            status = False

        else:
            valid_chain, error_messages = validate_certificate_chain(chain)

            if not valid_chain:
                logger.debug(error_messages)
                status = False
            else:
                status = verify_signature(client_cc_certificate, server_nonce, self.nonce)

        if status:
            logger.debug(f"Client certificate chain validated and nonce signed by the client")
            object_identifier = ObjectIdentifier("2.5.4.5")
            self.authorized_users.append(client_cc_certificate.subject.get_attributes_for_oid(object_identifier)[0].value)

            logger.debug(f"User logged in with success")

        status_enc = encrypt(self.secret_key, str(status), self.client_chosen_ciphers[0],
                                            self.client_chosen_ciphers[1]).decode('latin')

        return json.dumps({
            "status": status_enc
        }).encode('latin')


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

        pubk_enc = encrypt(self.secret_key,
                           public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
                           self.ciphers[0], self.ciphers[1]).decode('latin')

        return json.dumps({
                "server_rsa_public_key":pubk_enc
            }).encode('latin')


    """Handle a GET request"""
    def render_GET(self, request):
        logger.debug(f'Received request for {request.uri}')

        try:
            if request.path == b'/api/list':
                return self.do_list(request)

            elif request.path == b'/api/download':
                return self.do_download(request)

            elif request.path == b'/api/dh-parameters':
                dh_parameters = diffie_hellman_parameters()
                self.diffie_hellman_parameters = dh_parameters
                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                return json.dumps(dh_parameters, indent=4).encode('latin')

            elif request.path == b'/api/protocols':
                return self.do_get_protocols(request)

            elif request.path == b'/api/cipher-suite':
                list_of_ciphers = [algs, mods, digest_algorithms]
                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                return json.dumps(list_of_ciphers, indent=4).encode('latin')

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

            # server auth
            # client auth
            # rsa exchange

            if request.path == b'/api/dh-handshake':
                """Generate a private key, a public key and public number of client"""
                public_number_of_client = json.loads(request.content.read())[0]
                self.diffie_hellman_private_key = diffie_hellman_generate_private_key(self.diffie_hellman_parameters)
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
                print(message)
                message = message.decode('latin')
                print(message)
                print(type(message))
                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                return json.dumps({"data": message}, indent=4).encode('latin')

            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods: /api/csuit /api/hello /api/bye /api/diffiehellman'

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''


print("Server started")
print("URL is: http://IP:8083")

s = server.Site(MediaServer())
reactor.listenTCP(8083, s)
reactor.run()
