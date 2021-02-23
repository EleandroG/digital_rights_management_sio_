import requests
import logging
import binascii
import json
import os
import subprocess
import time
import sys
import asyncio

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)


SERVER_URL = 'http://127.0.0.1:8080'

STATE_CONNECT = 0
STATE_OPEN = 1
STATE_DATA = 2
STATE_CLOSE = 3
STATE_NEGOTIATE = 4
STATE_DH = 5
class Client(asyncio.Protocol):
    
    def __init__(self):
        "Client "
        self.symetric_ciphers = ["AES", "ChaCha20", "3DES"]
        self.cipher_modes = ["GCM", "None", "ECB", "CBC"]
        self.digest_algorithms = ["SHA256", "SHA512", "BLAKE2"]

        self.used_symetric_cyphers = None
        self.used_cypher_modes = None
        self.used_digest_algorithms = None

        self.p = None
        self.g = None
        self.private_key = None
        self.shared_key = None
        self.public_key_pem = None

        self.state = STATE_CONNECT  # Initial State
        self.buffer = ""  # Buffer to receive data chunks

    def connection_made(self, transport) -> None:
        self.transport = transport

        logger.debug("Connected to server")
        message = {
            "type": "NEGO_REQ", #request to server
            "algorithms": {
                "symetric_ciphers": self.symetric_ciphers,
                "chiper_modes": self.cipher_modes,
                "digest_algorithms": self.digest_algorithms,
            },
        }

        self._send(message)

        self.state = STATE_NEGOTIATE

    def data_received(self, data : str):

        logger.debug("List: ".format(data))
        try:
            self.buffer += data.decode()
        except:
            logger.exception("Could not decode data from client")

        idx = self.buffer.find("\r\n")

    ...

    def connection_lost(self, exc):
        logger.info("The connections has been closed by the server")
        self.loop.stop()
        
        



def main():
    print("|-------------------------------serve-------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    # Get a list of media files
    print("Contacting Server")
    
    # TODO: Secure the session

    req = requests.get(f'{SERVER_URL}/api/list')
    if req.status_code == 200:
        print("Got Server List")

    media_list = req.json()


    # Present a simple selection menu    
    idx = 0
    print("MEDIA CATALOG\n")
    for item in media_list:
        print(f'{idx} - {media_list[idx]["name"]}')
    print("----")

    while True:
        selection = input("Select a media file number (q to quit): ")
        if selection.strip() == 'q':
            sys.exit(0)

        if not selection.isdigit():
            continue

        selection = int(selection)
        if 0 <= selection < len(media_list):
            break

    # Example: Download first file
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
        req = requests.get(f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}')
        chunk = req.json()
       
        # TODO: Process chunk

        data = binascii.a2b_base64(chunk['data'].encode('latin'))
        try:
            proc.stdin.write(data)
        except:
            break

if __name__ == '__main__':
    while True:
        main()
        time.sleep(1)