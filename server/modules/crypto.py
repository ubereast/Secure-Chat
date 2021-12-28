from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

import itertools
import time
import threading

keyPair = None
AES_KEY = get_random_bytes(16)
public_key = None
private_key = None
cipher = None


def generate_key():
    global public_key, private_key, cipher
    done = False

    def animate():
        for c in itertools.cycle(['|', '/', '-', '\\']):
            if done:
                break
            print('Generating key pair ' + c, end="\r")
            time.sleep(0.1)

    threading.Thread(target=animate).start()
    # keyPair = RSA.generate(4096)
    private_key = open("server/modules/private.pem", "r").read()
    public_key = open("server/modules/public.pem", "r").read()
    done = True
    return True


def encrypt(data, public_key):
    if type(data) != bytes:
        data = data.encode()
    rsa_public_key = RSA.importKey(public_key)
    rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
    encrypted = rsa_public_key.encrypt(data)
    return encrypted


def decrypt(data, decodeData=True):
    rsa_private_key = RSA.importKey(private_key)
    rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
    decrypted = rsa_private_key.decrypt(data)
    if decodeData:
        decrypted = decrypted.decode()
    return decrypted
