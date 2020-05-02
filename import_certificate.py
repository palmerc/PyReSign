#!/usr/bin/env python3

import argparse
import pathlib
import sys

from keychains import Keychain


def main():
    parser = argparse.ArgumentParser(description='Create, unlock and import signing certificates for keychains')
    parser.add_argument('-k', '--keychain', dest='keychain_name', required=True,
            help='create and use the named keychain')
    parser.add_argument('--keychain-pass', dest='keychain_pass',
            help='keychain password')
    parser.add_argument('--cert', dest='dist_cert',
            help='p12 certificate to import')
    parser.add_argument('--cert-pass', dest='dist_cert_pass',
            help='password for p12 certificate')
    args = parser.parse_args()

    keychain = Keychain(args.keychain_name, args.keychain_pass)

    if not keychain.exists():
        keychain.create_and_configure()
    else:
        keychain.unlock()

    if args.dist_cert:
        dist_cert_path = pathlib.Path(args.dist_cert).resolve()
        if not keychain.has_signing_certificates(dist_cert_path, args.dist_cert_pass):
            keychain.import_codesign_certificate(dist_cert_path, args.dist_cert_pass)


if __name__ == "__main__":
    if sys.version_info < (3, 0):
        sys.stdout.write("Requires Python 3.x\n")
        sys.exit(1)

    main()

