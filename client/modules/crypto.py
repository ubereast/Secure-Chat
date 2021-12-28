from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

import itertools
import time
import threading

keyPair = None
AES_KEY = None
public_key = None
private_key = None
cipher = None


def generate_key():
    global public_key, private_key, keyPair

    done = False
    if keyPair:
        raise BaseException

    def animate():
        for c in itertools.cycle(['|', '/', '-', '\\']):
            if done:
                break
            print('Generating key pair ' + c, end="\r")
            time.sleep(0.1)

    threading.Thread(target=animate).start()
    keyPair = RSA.generate(1024)
    private_key = keyPair.export_key("PEM")
    public_key = keyPair.publickey().exportKey("PEM")
    done = True
    return True


def generate_aes_key():
    global AES_KEY
    AES_KEY = get_random_bytes(16)


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


def aes_encrypt(data):
    if type(data) != bytes:
        data = data.encode()
    cipher = AES.new(AES_KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, cipher.nonce


def aes_decrypt(data, AES_KEY=AES_KEY, nonce=None, decodeData=True):
    cipher = AES.new(AES_KEY, AES.MODE_EAX, nonce)
    ciphertext = cipher.decrypt(data)
    if decodeData:
        ciphertext = ciphertext.decode()
    return ciphertext
