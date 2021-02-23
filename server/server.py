#!/usr/bin/env python

"""
83069 - Eleandro Laureano
78444 - Nuno Matamba
"""
import base64
import logging
import binascii
import json
import os
import math
import sys
from twisted.web import server, resource
from twisted.internet import reactor, defer


#TODO: Arranjar o import
#sys.path.insert(1, '../client/s')
#import secure_functions

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


class MediaServer(resource.Resource):

    def __init__(self, signal):
        self.signal = signal
        #self.state = STATE_CONNECT
        self.file = None
        self.file_name = None
        self.file_path = None
        #self.storage_dir = storage_dir
        self.buffer = ""
        self.peername = ""

        self.ciphers = ["AES", "3DES", "ChaCha20"]
        self.cipher_modes = ["ECB", "CBC", "GCM", "None"]
        self.digest_algorithms = ["SHA256", "SHA512", "BLAKE2"]

        self.used_cipher = None
        self.used_cipher_mode = None
        self.used_digest_algorithm = None

        self.p = None
        self.g = None
        self.private_key = None
        self.shared_key = None
        self.public_key_pem = None

    isLeaf = True

    """This function sends the list of media files to clients"""
    def do_list(self, request):

        #auth = request.getHeader('Authorization')
        #if not auth:
        #    request.setResponseCode(401)
        #    return 'Not authorized'


        #Build list
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
        return json.dumps(media_list, indent=4).encode('latin')


    """This function sends a media chunk to the client"""
    def do_download(self, request):




        logger.debug(f'Download: args: {request.args}')
        
        media_id = request.args.get(b'id', [None])[0]
        logger.debug(f'Download: id: {media_id}')

        #Check if the media_id is not None as it is required
        if media_id is None:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'invalid media id'}).encode('latin')
        
        #Convert bytes to str
        media_id = media_id.decode('latin')

        #Search media_id in the catalog
        if media_id not in CATALOG:
            request.setResponseCode(404)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'media file not found'}).encode('latin')
        
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
            return json.dumps({'error': 'invalid chunk id'}).encode('latin')
            
        logger.debug(f'Download: chunk: {chunk_id}')

        offset = chunk_id * CHUNK_SIZE

        #Open file, seek to correct position and return the chunk
        with open(os.path.join(CATALOG_BASE, media_item['file_name']), 'rb') as f:
            f.seek(offset)
            data = f.read(CHUNK_SIZE)

            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps(
                    {
                        'media_id': media_id, 
                        'chunk': chunk_id, 
                        'data': binascii.b2a_base64(data).decode('latin').strip()
                    },indent=4
                ).encode('latin')

        #File was not open?
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps({'error': 'unknown'}, indent=4).encode('latin')


    """This function handles a GET request"""
    def render_GET(self, request):
        logger.debug(f'Received request for {request.uri}')

        try:
            if request.path == b'/api/protocols':
                return self.do_get_protocols(request)
            #elif request.uri == 'api/key':
            #...
            #elif request.uri == 'api/auth':

            elif request.path == b'/api/list':
                return self.do_list(request)

            elif request.path == b'/api/download':
                return self.do_download(request)
            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods: /api/protocols /api/list /api/download'

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''


    #Handle a POST request
    def render_POST(self, request):
        logger.debug(f'Received POST for {request.uri}')
        request.setResponseCode(501)
        return b''


    """1. This function processes a negotiation with the client and server"""
    def negotiation(self, media_titles: str):
        logger.debug(f"Process Negotation: {media_titles}")

        ciphers = media_titles["algorithms"]["ciphers"]
        cipher_modes = media_titles["algorithms"]["cipher_modes"]
        digest_algorithms = media_titles["algorithms"]["digest_algorithms"]

        for cipher in ciphers:
            if cipher in self.ciphers:
                self.used_cipher = cipher
                break

        for cipher_md in cipher_modes:
            if cipher_md in self.cipher_modes:
                self.used_cipher_mode = cipher_md
                break

        for digest_alg in digest_algorithms:
            if digest_alg in self.digest_algorithms:
                self.used_digest_algorithm = digest_alg
                break

        media_titles = {
            "type": "NEGO_REP",
            "algorithms": {
                "_cipher": self.used_cipher,
                "cipher_mode": self.used_cipher_mode,
                "digest_algorithm": self.used_digest_algorithm,
            },
        }

        if (
            self.used_cipher is not None
            and self.used_chiper_mode is not None
            and self.used_digest_algorithm is not None
        ):
            self._send(media_titles)
            return True

        return False

    """2. This function negotiate ephemeral keys between the client and server using Diffie-Hellman"""
    def negotiate_keys(self, media_titles: str):
        self.p = media_titles["parameters"]["p"]
        self.g = media_titles["parameters"]["g"]
        public_key_pem_client = bytes(media_titles["parameters"]["public_key"], "ISO-8859-1")

        try:
            self.private_key, self.public_key_pem = secure_funtions.diffie_hellman_server(
                self.p, self.g, public_key_pem_client
            )

            media_titles = {
                "type": "DH_SERVER_KEY",
                "key": str(self.public_key_pem, "ISO-8859-1"),
            }

            self._send(media_titles)

            self.shared_key = secure_funtions.generate_shared_key(
                self.private_key, public_key_pem_client, self.used_digest_algorithm
            )

            return True
        except Exception as e:
            print(e)
            return False

    """4. This function is used to validate the integrity of all messages and chunks"""
    def validate_integrity(self, request, frame: str) -> None:
        #Verify integrity of all messages
        try:
            message = json.loads(frame) #TODO: Mudar o nome de "frame" para outra coisa.
        except:
            logger.exception("Could not decode JSON message: {}".format(frame)) #TODO: Mudar mensagem de erro
            self.transport.close()
            return
        mtype = message.get("type", "").upper()

        if mtype == "MEDIA_FILES":
            actual_message = base64.b64decode(message["payload"])
            mac = base64.b64decode(message["mac"])
            if message["iv"] != None:
                iv = base64.b64decode(message["iv"])
            else:
                iv = None
            if message["nonce"] != None:
                nonce = base64.b64decode(message["nonce"])
            else:
                nonce = None
            if message["tag"] != None:
                tag = base64.b64decode(message["tag"])
            else:
                tag = None

            digest = secure_functions.mac_generator(
                actual_message, self.shared_key, self.used_digest_algorithm
            )
            if mac != digest:
                if self.file_path != None:  #If we created a file delete it!
                    os.remove(self.file_path)
                logger.warning("The integrity of this message has been compromised")
                ret = False
            else:
                actual_message = secure_functions.symmetric_decryptor(
                    actual_message,
                    self.shared_key,
                    self.used_symetric_cipher,
                    self.used_chiper_mode,
                    iv,
                    nonce,
                    tag,
                )

                actual_message = actual_message.decode()
                actual_message = actual_message.split("}")[0] + "}"
                message = json.loads(actual_message)
                mtype = message["type"]             #TODO: Como resolver o "mtype" ?

        elif mtype == "NEGO_REP":
            ret = self.process_negotiation(message)
        else:
            logger.warning("Invalid message type: {}".format(message["type"]))
            ret = False

        if not ret:
            try:
                self._send({"type": "ERROR", "message": "See server"})
            except:
                pass  #Silently ignore

            logger.info("Closing transport")
            if self.file is not None:
                self.file.close()
                self.file = None

        #Verify integrity of chunks
        #Check if a chunk is valid
        chunk_id = request.args.get(b'chunk', [b'0'])[0]
        media_id = request.args.get(b'id', [None])[0]
        valid_chunk = False
        media_item = CATALOG[media_id]
        try:
            chunk_id = int(chunk_id.decode('latin'))
            if chunk_id >= 0 and chunk_id < math.ceil(media_item['file_size'] / CHUNK_SIZE):
                valid_chunk = True
        except:
            logger.warn("Chunk format is invalid")

        if not valid_chunk:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'invalid chunk id'}).encode('latin')

        logger.debug(f'Chunk: {chunk_id} was sent')


print("Server started")
print("URL is: http://IP:8080")

s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()