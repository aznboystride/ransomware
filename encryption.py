import os
import json
import cryptools
import constants

class Cipher(object):

	def __init__(self):
		raise NotImplementedError('This is an Abstract Class')

	def Encrypt(self):
		raise NotImplementedError('This is an Abstract Class')

	def Decrypt(self):
		raise NotImplementedError('This is an Abstract Class')


class SymmetricCipher(Cipher):

	def __init__(self, key=None, iv=None):
		
		if None in (key, iv):
			raise Exception("You must pass in KEY and IV")
		
		self.key = key
		
		self.iv = iv
		
		self.cipher, self.decipher = cryptools.AESCiphers(key, iv)
		

	def Encrypt(self, text):
		
		padded_text = cryptools.pad(text)
		
		return self.cipher.encrypt(padded_text)


	def Decrypt(self, ciphertext):
		
		decrypted_content = self.decipher.decrypt(ciphertext)
		
		unpadded_text = cryptools.unpad(decrypted_content)
		
		return unpadded_text


class AsymmetricCipher(Cipher):

	def __init__(self, RSA_Folder_Path):
		
		if not os.path.isdir(RSA_Folder_Path):
			os.makedirs(RSA_Folder_Path)
		
		self.cipher, self.decipher = cryptools.RSACiphers(RSA_Folder_Path)


	def Encrypt(self, text):
		
		return self.cipher.encrypt(text)


	def Decrypt(self, ciphertext):
		
		return self.decipher.decrypt(ciphertext)
