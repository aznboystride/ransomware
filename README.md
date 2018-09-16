# RansomWare

This is a web based ransomware created for a class project at Long Beach State University. This ransomware when launched on a MacOSx or Windows computer, will encrypt all of the files in the disk drive using AES and RSA encryption. Every file will be encrypted using AES256 Encryption and deleted. The AES256 key will be encrypted using RSA 2048. A json file containing base 64 encoded information of the encrypted file and the corresponding encrypted AES key will be created on the victim computer. The json file will also include the public key used in the encryption.

### The project consists of two python files. One file is used for encrypting and the other file is used for decrypting. The ransomware interacts with a webserver when the file 
