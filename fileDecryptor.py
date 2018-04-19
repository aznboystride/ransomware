from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from base64 import b64decode
from cryptography.hazmat.primitives import padding
import os
import json
import hmac
import hashlib
import sys

# Removes the extra characters that the encryptor added to
# make the length of the message a multiple of 16

BLOCK_SIZE_BITS = 128

def unpad(msg):
    unpadder = padding.PKCS7(BLOCK_SIZE_BITS).unpadder()
    data = unpadder.update(msg)
    data += unpadder.finalize()
    return data

def RSA_Decrypt(data, priv_path):
	with open(priv_path, 'rb') as key_file:
		private_key = RSA.importKey(key_file.read())
	decryptor = PKCS1_OAEP.new(private_key)
	return decryptor.decrypt(data)

def verify(data, tag, key):
	return tag == hmac.new(key, data, hashlib.sha256).hexdigest()

def decrypt_folder(path):
	for file in os.listdir(path):
		nameOfFile = os.path.join(path, file)
		priv_path = '/Users/Pey/Desktop/key.pem'

		decryption_info = json.load(open(nameOfFile))

		keys = RSA_Decrypt(b64decode(decryption_info['key']), priv_path)

		extension = b64decode(decryption_info['extension'])

		iv = b64decode(decryption_info['iv'])

		key, hmac_key = keys[:len(keys)/2], keys[len(keys)/2:]

		tag = b64decode(decryption_info['tag'])

		ciphertext = b64decode(decryption_info['ciphertext'])

		if not verify(ciphertext, tag, hmac_key):
			print('\n[!] Ciphertext has been altered! \n')
			sys.exit(1)

		decryptor = AES.new(key=key,mode=AES.MODE_CBC,IV=iv)

		decrypted_content = decryptor.decrypt(ciphertext)

		plaintext = unpad(decrypted_content)

		file = open(nameOfFile[:nameOfFile.find('.')] + extension, 'w')
		file.write(plaintext)

decrypt_folder(input('\n[+] Specify Folder TO UNfucked\n'))