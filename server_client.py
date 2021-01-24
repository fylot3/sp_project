#!/usr/bin/env python3

import os
import sys
import hmac
import hashlib

from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme

from donna25519 import PrivateKey, PublicKey
from binascii import hexlify, unhexlify


def read_line(fd):
    data = b''

    while not data.endswith(b'\n'):
        byte = fd.read(1)
        if byte == b'':
            return data
        data += byte

    return data[:-1]


def read_binary(fd):
    return unhexlify(read_line(fd))


def write_line(fd, msg):
    fd.write(msg + b'\n')
    fd.flush()


def write_binary(fd, data):
    write_line(fd, hexlify(data))


def compute_mac(key, data):
    return hmac.new(key, data, digestmod=hashlib.sha256).digest()


def is_valid_mac(key, data, mac):
    return hmac.compare_digest(compute_mac(key, data), mac)


def AES_encrypt(key, message, iv=None):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return cipher.encrypt(pad(message, AES.block_size))


def AES_decrypt(key, message, iv=None):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(message), AES.block_size)


def increment_iv(iv):
    return iv


class Server(object):
    def __init__(self, priv_key, password, flag, reader, writer):
        self.password = password
        self.flag = flag
        self.reader = reader
        self.writer = writer
        self.priv_key = RSA.importKey(priv_key)
        self.signer = PKCS115_SigScheme(self.priv_key)
        self.nonce = None

    def sign(self, message):
        return self.signer.sign(SHA256.new(message))

    def handshake(self):
        nonce = os.urandom(32)
        priv_k = PrivateKey()
        pub_k = priv_k.get_public().public
        signature = self.sign(pub_k)

        # Send the public key, nonce and auth signature to a client
        write_binary(self.writer, pub_k)
        write_binary(self.writer, nonce)
        write_binary(self.writer, signature)

        # Receive a public key and nonce from a client
        client_pub_k = read_binary(self.reader)
        client_nonce = read_binary(self.reader)

        # Save the nonce values for later use
        self.nonce = nonce
        self.client_nonce = client_nonce

        # Some checks
        if nonce == client_nonce:
            return None
        if client_pub_k in (b'\x00'*32, b'\x01' + (b'\x00' * 31)):
            return None

        # Authenticate the client
        client_pub_k = PublicKey(client_pub_k)
        shared_key = priv_k.do_exchange(client_pub_k)
        mac = compute_mac(shared_key, client_nonce + self.password)

        write_binary(self.writer, mac)
        client_mac = read_binary(self.reader)

        if not is_valid_mac(shared_key, nonce + self.password, client_mac):
            return None

        # Successful authentication
        return shared_key

    def run(self):
        # Run the handshake process
        shared_key = self.handshake()
        if shared_key is None:
            write_line(self.writer, b'Error: nope.')
            return 1

        # Use AES-CBC for both encryption and decryption. Initialize IVs.
        server_iv = self.nonce[:16]
        client_iv = self.client_nonce[:16]

        # Authenticate the client
        write_binary(self.writer, AES_encrypt(shared_key, b"AUTHENTICATED",
                                              server_iv))
        server_iv = increment_iv(server_iv)

        # Process commands
        while True:
            cmd = AES_decrypt(shared_key, read_binary(self.reader), client_iv)
            client_iv = increment_iv(client_iv)

            if cmd == b'help':
                answer = b'help|exit|whoami|getflag'
            elif cmd == b'exit':
                return 0
            elif cmd == b'whoami':
                answer = b'root'
            elif cmd == b'getflag':
                answer = self.flag
            else:
                return 1

            write_binary(self.writer, AES_encrypt(shared_key, answer,
                                                  server_iv))
            server_iv = increment_iv(server_iv)


class Client(object):
    def __init__(self, pub_key, password, reader, writer):
        self.password = password
        self.reader = reader
        self.writer = writer
        self.pub_key = RSA.importKey(pub_key)
        self.verifier = PKCS115_SigScheme(self.pub_key)
        self.nonce = None
        self.server_nonce = None

    def is_valid_signature(self, msg, signature):
        try:
            self.verifier.verify(SHA256.new(msg), signature)
            return True
        except:
            return False

    def handshake(self):
        nonce = os.urandom(32)
        priv_k = PrivateKey()

        # Send the public key and nonce to the server
        write_binary(self.writer, priv_k.get_public().public)
        write_binary(self.writer, nonce)

        # Receive the public key, nonce and auth signature from the server
        server_pub_k = read_binary(self.reader)
        server_nonce = read_binary(self.reader)
        server_signature = read_binary(self.reader)

        # Save the nonce values for later use
        self.server_nonce = server_nonce
        self.nonce = nonce

        # Some checks
        if nonce == server_nonce:
            return None
        if server_pub_k in (b'\x00'*32, b'\x01' + (b'\x00' * 31)):
            return None
        if not self.is_valid_signature(server_pub_k, server_signature):
            return None

        # Authenticate the client
        server_pub_k = PublicKey(server_pub_k)
        shared_key = priv_k.do_exchange(server_pub_k)
        mac = compute_mac(shared_key, server_nonce + self.password)

        write_binary(self.writer, mac)
        server_mac = read_binary(self.reader)

        if not is_valid_mac(shared_key, nonce + self.password, server_mac):
            return None

        # Successful authentication
        return shared_key

    def run(self):
        # Run the handshake process
        shared_key = self.handshake()
        if shared_key is None:
            write_line(self.writer, b'Error: nope.')
            return 1

        # Use AES-CBC for both encryption and decryption. Initialize IVs.
        server_iv = self.server_nonce[:16]
        client_iv = self.nonce[:16]

        # Check if authenticated
        is_authenticated = AES_decrypt(shared_key, read_binary(self.reader),
                                       server_iv)
        server_iv = increment_iv(server_iv)

        if is_authenticated != b"AUTHENTICATED":
            write_line(self.writer, b'Error: nope.')
            return 1

        # Check the user
        write_binary(self.writer, AES_encrypt(
            shared_key, b"whoami"), client_iv)
        client_iv = increment_iv(client_iv)

        user = AES_decrypt(shared_key, read_binary(self.reader), server_iv)
        server_iv = increment_iv(server_iv)

        if user != b'root':
            return 1

        # Exit
        write_binary(self.writer, AES_encrypt(shared_key, b"exit"), client_iv)
        return 0


def run_challenge(priv_key, pub_key, password, flag, reader, writer):
    try:
        entity_choice = read_line(reader)

        if entity_choice[0] in b'sS':
            return Server(priv_key, password, flag, reader, writer).run()
        elif entity_choice[0] in b'cC':
            return Client(pub_key, password, reader, writer).run()
        else:
            write_line(writer,
                       b'Error: Invalid argument. Select either (s)erver or (c)lient.')
            return 1

    except Exception as e:
        write_line(writer, b'Error')
        return 1


def main():
    # Get the RSA key, password and CTF flag
    priv_key, pub_key, passwd, flag = map(lambda f: open(f, 'rb').read().strip(),
                                          sys.argv[1:5])

    # Check if the flag is valid
    assert(flag.startswith(b'CRYPTO-CTF{') and flag.endswith(b'}'))

    # Run the challenge
    return run_challenge(priv_key, pub_key, passwd, flag, sys.stdin.buffer, sys.stdout.buffer)


if __name__ == '__main__':
    sys.exit(main())
