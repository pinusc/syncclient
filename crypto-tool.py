#!/usr/bin/env python3

import os
import argparse
import base64
import json
from cryptography.hazmat.backends.openssl import backend as openssl
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from nacl.public import PrivateKey, SealedBox

class CryptoTool(object):

    def __init__(self, mode='base64'):
        self._backend = openssl
        self._mode = mode

    def _print(self, data):
        if isinstance(data, dict):
            for key, value in data.items():
                data[key] = self._print(value)
            return json.dumps(data)

        if isinstance(data, list) or isinstance(data, tuple):
            return json.dumps([self._print(d) for d in data])

        if isinstance(data, bytes):
            m = self._mode
            if m == 'base64':
                return base64.b64encode(data).decode('ascii')
            if m == 'hex':
                return data.hex()

            return data

        return data

    def hkdf_namespace(self, name, extra=None):
        if isinstance(name, str):
            name = name.encode("utf-8")

        kw = b"identity.mozilla.com/picl/v1/" + name

        if extra is not None:
            if isinstance(extra, str):
                extra = extra.encode("utf-8")
            kw = kw + b":" + extra

        return kw

    def hkdf_derive(self, secret, obj_class, obj_id=None, size=32):
        kdf = HKDF(algorithm=hashes.SHA256(), length=size, salt=None,
                   info=self.hkdf_namespace(obj_class, obj_id),
                   backend=self._backend)
        return kdf.derive(secret)

    def derive_key_scrypt(self, secret, info, n=16, size=32):
        if isinstance(n, str):
            n = int(n)

        salt = info

        if isinstance(salt, str):
            salt = salt.encode('utf-8')

        if isinstance(secret, str):
            secret = secret.encode('utf-8')

        kdf = Scrypt(salt=salt, length=size, n=2**n, r=8, p=1,
                     backend=self._backend)

        return kdf.derive(secret)

    def derive_key_scrypt_ext(self, secret, info, n=16, size=32):
        return self._print(self.derive_key_scrypt(secret, info, n, size))

    def generate_key(self, keyB, object_id):
        if isinstance(keyB, str):
            keyB = bytes.fromhex(keyB)

        object_key = self.derive_key_scrypt(keyB, object_id)

        return PrivateKey(object_key)

    def generate_key_ext(self, keyB, object_id):
        secret_key = self.generate_key(keyB, object_id)
        public_key = secret_key.public_key

        data = {"sk":secret_key._private_key, "pk":public_key._public_key}
        return self._print(data)

    def encrypt(self, keyB, filename):
        key = self.generate_key(keyB, filename)
        box = SealedBox(key.public_key)

        with open(filename, "rb") as fp:
            return box.encrypt(fp.read())

    def encrypt_ext(self, keyB, filename):
        data = self.encrypt(keyB, filename)
        return self._print(data)

    def decrypt(self, keyB, filename, filename_enc):
        key = self.generate_key(keyB, filename)
        box = SealedBox(key)

        with open(filename_enc, "rb") as fp:
            return box.decrypt(fp.read())

    def decrypt_ext(self, keyB, filename, filename_enc):
        data = self.decrypt(keyB, filename, filename_enc)
        return self._print(data)

def main():
    parser = argparse.ArgumentParser(
        description="""CLI for invoking crypto utility functions""",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument('-m', '--mode', dest='mode', default='base64',
                        choices=['base64','hex'],
                        help='The output mode')
    parser.add_argument(dest='action', nargs='?',
                        help='The action to be executed')

    args, extra = parser.parse_known_args()

    func = args.action + "_ext"

    tool = CryptoTool(mode=args.mode)
    print(getattr(tool, func)(*extra))

if __name__ == '__main__':
    main()

