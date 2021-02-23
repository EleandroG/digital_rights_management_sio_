#!/usr/bin/env python

"""
83069 - Eleandro Laureano
78444 - Nuno Matamba
"""

from twisted.web import server, resource
from twisted.internet import reactor, defer
from getpass import getpass
from base64 import b64encode, b64decode
import logging
import binascii
import json
import os
import math
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


CATALOG = { '898a08080d1840793122b7e118b27a95d117ebce':
            {
                'name': 'Sunny Afternoon - Upbeat Ukulele Background Music',
                'album': 'Upbeat Ukulele Background Music',
                'description': 'Nicolai Heidlas Music: http://soundcloud.com/nicolai-heidlas',
                'duration': 3*60+33,
                'file_name': '898a08080d1840793122b7e118b27a95d117ebce.mp3',
                'file_size': 3407202
            }
        }

CATALOG_BASE = 'catalog'
CHUNK_SIZE = 1024 * 4

algs = ['AES', '3DES']
mods = ['ECB', 'CFB', 'OFB']
digest_algorithm =['SHA256', 'SHA512', 'SHA3256']

ciphers = {}
dKey = {}
readings = {}
users = []
CSUIT = {}

#"""Parameters"""
#p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
#g = 2
#params_numbers = dh.DHParameterNumbers(p,g)
#parameters = params_numbers.parameters(default_backend())


"""This function is used to initialize hmac based on key and user id"""
def start_hmac(key, who):
    global CSUIT

    alg, mod, dig = CSUIT[who].split("_")
    if(dig == "SHA256"):
        digest = hashes.SHA256()
    elif(dig == "SHA512"):
        digest = hashes.SHA512()
    elif(dig == "SHA3256"):
        digest = hashes.SHA3_256()
    return hmac.HMAC(key, digest, backend=default_backend())

""" """
def generate_key(algorithm, salt):
    password = getpass()
    password = password.encode()

    if algorithm == 'AES':
        length = 16
    else:
        length = 24

    pbkdf = PBKDF2HMAC(salt=salt, algorithm=hashes.SHA256(), iterations=10**5, length=length,
        backend=default_backend()
    )

    key = pbkdf.derive(password)
    return key

"""This function is used to encrypt the data"""
def encrypt(algorithm, cipherMode, file_to_be_encrypted, file_to_be_saved):
    salt = os.urandom(16)
    key = generate_key(algorithm, salt)

    if algorithm == 'AES':
        blockLength = 16
        algorithm = algorithms.AES(key)
    else:
        blockLength = 8
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
        block = encrypted_file.read(blockLength)
        if block == "":
            break

        if len(block) != blockLength:
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

    salt = file_to_be_decrypted.read(math.ceil(16 / 3) * 4)
    salt = b64decode(salt)
    key = generate_key(algorithm, salt)

    if algorithm == 'AES':
        blockLength = 16
        algorithm = algorithms.AES(key)
    else:
        blockLength = 8
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
    nextBlock = b64decode(file_to_be_decrypted.read(math.ceil(blockLength / 3) * 4))

    while True:
        block = nextBlock
        nextBlock = b64decode(file_to_be_decrypted.read(math.ceil(blockLength / 3) * 4))
        block = decryptor.update(block)
        if nextBlock == b"":
            break
        file_to_be_saved.write(block.decode())

        file_to_be_decrypted.close()
        file_to_be_saved.close()

def diffie_helman_param(key=2048):
    parameters = dh.generate_parameters(generator=2, key_size=key)
    return parameters


class MediaServer(resource.Resource):
    isLeaf = True

    #Send the list of media files to clients
    def do_list(self, request, who):

        #auth = request.getHeader('Authorization')
        #if not auth:
        #    request.setResponseCode(401)
        #    return 'Not authorized'

        # Build list
        media_list = []
        for media_id in CATALOG:
            media = CATALOG[media_id]
            media_list.append({
                'id': media_id,
                'name': media['name'],
                'description': media['description'],
                'chunks': math.ceil(media['file_size'] / CHUNK_SIZE),
                'duration': media['duration']
                })

        #Return list to client
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return encrypt_data(json.dumps(media_list, indent=4), who)

    #Send a media chunk to the client
    def do_download(self, request,who):
        global dKey
        global readings
        global CSUIT
        logger.debug(f'Download: args: {request.args}')

        media_id = request.args.get(b'id', [None])[0]
        logger.debug(f'Download: id: {media_id}')

        #Check if the media_id is not None as it is required
        if media_id is None:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return encrypt_data(json.dumps({'error': 'invalid media id'}),who)

        #Convert bytes to str
        media_id = media_id.decode('latin')

        #Search media_id in the catalog
        if media_id not in CATALOG:
            request.setResponseCode(404)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return encrypt_data(json.dumps({'error': 'media file not found'}),who)

        #Get the media item
        media_item = CATALOG[media_id]

        #Check if a chunk is valid
        chunk_id = request.args.get(b'chunk', [b'0'])[0]
        valid_chunk = False
        try:
            chunk_id = int(chunk_id.decode('latin'))
            if chunk_id >= 0 and chunk_id  < math.ceil(media_item['file_size'] / CHUNK_SIZE):
                valid_chunk = True
        except:
            logger.warn("Chunk format is invalid")

        if not valid_chunk:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return encrypt_data(json.dumps({'error': 'invalid chunk id','data': 'brak'}),who)
        if(who not in readings.keys()):
            readings[who] = {media_id:0}
        elif(media_id not in readings[who].keys()):
            readings[who][media_id] = 0

        logger.debug(f'Download: chunk: {chunk_id} - readingsByChunk: {math.ceil((readings[who][media_id]*100) / media_item["file_size"])/100} ')

        offset = chunk_id * CHUNK_SIZE

        readings[who][media_id] += CHUNK_SIZE
        #Open file, seek to correct position and return the chunk
        with open(os.path.join(CATALOG_BASE, media_item['file_name']), 'rb') as f:
            f.seek(offset)
            data = f.read(CHUNK_SIZE)

            request.responseHeaders.addRawHeader(b"content-type", b"application/json")

            """Encrypt with key rotation"""
            alg, mod, dige = CSUIT[who].split("_")
            blocksize = 16*8
            if(alg == 'AES'):
                blocksize = algorithms.AES.block_size
            elif(alg == 'SEED'):
                blocksize = algorithms.SEED.block_size
            elif(alg == 'CAST5'):
                blocksize = algorithms.CAST5.block_size
            elif(alg == 'TripleDES'):
                blocksize = algorithms.TripleDES.block_size

            new_IV = os.urandom(int(blocksize/8))
            crypt = cipher(dKey[who],new_IV,who).encryptor()
            encrypted_data = crypt.update(json.dumps(
                    {
                        'media_id': media_id,
                        'chunk': chunk_id,
                        'data': binascii.b2a_base64(data).decode('latin').strip()
                    },indent=4
                ).encode('latin')) + crypt.finalize()
            dKey[who] = HKDF(
                algorithm=hashes.SHA256(),
                length=16,
                salt=None,
                info=b'handshake data').derive(dKey[who] + encrypt_data(encrypted_data.decode('latin'), who))
            hmacing = start_hmac(dKey[who],who).copy()
            hmacing.update(encrypted_data)
            hmac_encrypted = hmacing.finalize()
            dict = {'data': encrypted_data.decode('latin'), 'HMAC': hmac_encrypted.decode('latin'), 'iv':new_IV.decode('latin')}
            return encrypt_data(json.dumps(dict, indent=4),who)

        #File was not open?
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return encrypt_data(json.dumps({'error': 'unknown'}, indent=4),who)

    """Handle a GET request"""
    def render_GET(self, request):
        who = request.received_cookies["session_id".encode('latin')].decode('latin')
        logger.debug(f'{who} : Received request for {request.uri}')

        try:
            if request.path == b'/api/list':
                return self.do_list(request,who)

            elif request.path == b'/api/download':
                return self.do_download(request,who)
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
        global users
        global CSUIT
        global keys
        global ciphers
        global digests
        global dkey

        who = request.received_cookies["session_id".encode('latin')].decode('latin')
        logger.debug(f'{who} : Received POST for {request.uri}')
        try:
            if request.path == b'/api/csuit':
                vars = (request.content.getvalue().decode('latin')).split("_")
                if vars[0] in algs and vars[1] in mods and vars[2] in digest_algorithm:
                    request.setResponseCode(200)
                    CSUIT[who] = request.content.getvalue().decode('latin')
                    return b''
                else:
                    request.setResponseCode(201)
                    return b''

            elif request.path == b'/api/ok':
                logger.debug(f'{who} : Received {decrypt_data(request.content.getvalue(),who)}')
                return encrypt_data("NO",who)

            elif request.path == b'/api/diffiehellman':
                """Generate a private key for use in the exchange"""
                private_key = parameters.generate_private_key()
                public_key = private_key.public_key()
                peer_public_key = serialization.load_pem_public_key(
                    request.content.getvalue())
                pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo)
                shared_key = private_key.exchange(peer_public_key)
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

                dKey[who] = HKDF(
                    algorithm=hashes.SHA256(),
                    length=16,
                    salt=None,
                    info=b'handshake data').derive(key1+key2+key3)

                alg, mod, dige = CSUIT[who].split("_")
                blocksize = 16*8
                if (alg == 'AES'):
                    blocksize = algorithms.AES.block_size
                elif (alg == 'SEED'):
                    blocksize = algorithms.SEED.block_size
                elif (alg == 'CAST5'):
                    blocksize = algorithms.CAST5.block_size
                elif (alg == 'TripleDES'):
                    blocksize = algorithms.TripleDES.block_size


                iv1 = os.urandom(int(blocksize/8))
                iv2 = os.urandom(int(blocksize/8))
                cf1 = cipher(key1,iv1,who)
                cf2 = cipher(key2,iv2,who)
                cf3 = start_hmac(key3,who)
                ciphers[who] = [cf1,cf2,cf3]
                return json.dumps({'pem':pem.decode('latin'),'ivs':[iv1.decode('latin'),iv2.decode('latin')]}, indent=4).encode('latin')

            elif request.path == b'/api/bye':
                if decrypt_data(request.content.getvalue(),who) == "encrypted bye message":
                    users.remove(who)
                    return b"bye"
                return b"No"

            elif request.path == b'/api/hello':

                if(who in users):
                    return b"hello"
                who = os.urandom(16)
                while(who.decode('latin') in users):
                    who = os.urandom(16)
                users += [who.decode('latin')]
                return who

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
