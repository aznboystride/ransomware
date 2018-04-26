from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import padding as p
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib, hmac, constants, os

def AESCiphers(key, iv):
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
	return (cipher.encryptor(), cipher.decryptor())

def RSACiphers(RSA_Folder_Path):

	if constants.RSA_PUBLIC_KEY_FILE not in os.listdir(RSA_Folder_Path) or constants.RSA_PRIVATE_KEY_FILE not in os.listdir(RSA_Folder_Path):
		genKeyPair(RSA_Folder_Path)
	
	with open(os.path.join(RSA_Folder_Path, constants.RSA_PRIVATE_KEY_FILE), 'rb') as key:
		private_key = serialization.load_pem_private_key(
			key.read(),
			password=None,
			backend=default_backend()
		)
		public_key = private_key.public_key()

	return (public_key, private_key)



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


def genKeyPair(RSA_Folder_Path):

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

	with open(os.path.join(constants.RSA_FOLDER_PATH, constants.RSA_PRIVATE_KEY_FILE), 'wb') as key:
		key.write(private_key_raw)

	public_key = private_key.public_key()

	public_key_raw = public_key.public_bytes(
		encoding = serialization.Encoding.PEM,
		format = serialization.PublicFormat.SubjectPublicKeyInfo
	)

	with open(os.path.join(constants.RSA_FOLDER_PATH, constants.RSA_PUBLIC_KEY_FILE), 'wb') as key:
		key.write(public_key_raw)