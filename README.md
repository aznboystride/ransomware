# Ransomware

This is a secured ransomware built using python with secured backend built with NodeJS.

## Getting Started

First clone the repository: 
```
git clone https://github.com/aznboystride/ransomware
```

## Running the ransomware

open a terminal and run `python infect.py`. This program will encrypt all of the files recursively where `infect.py` is placed to. The original files will be deleted and replaced with `.json` files containing ciphertext and other information that will be required to retrieve back the original file.

## Warning

When running `infect.py`, it will encrypt recursively absolutely everything outside of the folder it's placed in.
Be sure to place the folder containing `infect.py` into the directory you want to encrypt. Make sure to not delete the `.json` files, or there will be no way to retrieve back the original file.

## Decrypting the files

open a terminal and run `python cure.py`. This program will decrypt all of the files recursively where `cure.py` is placed to. This will reverse all the encryption and recover all of the original files.
