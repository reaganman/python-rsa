# python RSA

This Python script implements the RSA encryption and decryption protocol. It allows you to generate RSA key pairs and encrypt/decrypt files using the generated keys.

## Contents

- [RSA Encryption Script](#rsa-encryption-script)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Usage](#usage)
    - [Generate RSA Keys](#generate-rsa-keys)
    - [Encrypt a File](#encrypt-a-file)
    - [Decrypt a File](#decrypt-a-file)

## Introduction

This python RSA script allows you to generate RSA key pairs, encrypt plaintext files, and decrypt encrypted files using the generated keys. It employs the RSA encryption algorithm with Miller-Rabin primality testing.

## Prerequisites

Make sure you have Python installed on your machine. You can download it from [python.org](https://www.python.org/).

## Installation

Clone the repository to your local machine:

```bash
git clone https://github.com/reaganman/python-rsa.git
cd python-rsa
```
## Usage

### Generate RSA Keys

To generate RSA keys, run `rsa.py` with the `--keygen` option:

```bash
python3 rsa_script.py keyphrase.txt --keygen
```
Replace keyphrase.txt with the path to a text file containing two lines of input strings to use a keypharse for key generation

### Encrypt a File

To encrypt a plaintext file using the generated public key, run the following command:

```bash
python3 rsa_script.py keyfile.txt --encrypt input.txt
```
Replace keyfile.txt with the same key file used for key generation, and input.txt with the path to the file you want to encrypt.

This command will read the public key generated from keyphrase.txt, encrypt the contents of input.txt, and save the encrypted result to an output file. The output file will be named based on the input file, appended with "_encrypted.txt".

### Decrypt a File
To decrypt a plaintext file using the generated private key, run the following command:
```bash
python3 rsa_script.py keyfile.txt --decrypt encrypted_file.txt
```
Replace keyfile.txt with the same key file used for key generation, and encrypted_file.txt with the path to the file you want to decrypt.

The output file will be named based on the input file, appended with "_decrypted.txt".

