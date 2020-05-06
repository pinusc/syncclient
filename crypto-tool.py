#!/usr/bin/env python3

import argparse
import fxa.crypto

class CryptoTool(object):

    def derive_key(self, secret, namespace):
        return fxa.crypto.derive_key(secret.encode('utf-8'), namespace).hex()

def main():
    parser = argparse.ArgumentParser(
        description="""CLI for invoking crypto utility functions""",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(dest='action', help='The action to be executed')

    args, extra = parser.parse_known_args()

    tool = CryptoTool()
    print(getattr(tool, args.action)(*extra))

if __name__ == '__main__':
    main()

