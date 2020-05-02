import unittest

from cryptography.hazmat.primitives import serialization
from keychains import Keychains, Keychain, TemporaryKeychain
from OpenSSL import crypto
from misc import signer_hash


class TestKeychains (unittest.TestCase):
    def test_can_find_keychain_containing_certificate(self):
        with TemporaryKeychain() as tk, open('./TestCertificate.p12', 'rb') as f:
            tk.import_codesign_certificate('./TestCertificate.p12', dist_cer_pass='test')
            p12 = crypto.load_pkcs12(f.read(), b'test')
            cryptography = p12.get_certificate().to_cryptography()
            certificate = cryptography.public_bytes(serialization.Encoding.DER)
            keychains = Keychains.find_keychains_with_certificate(certificate)
            self.assertTrue(tk.path in keychains)

    def test_cleanup_keychain_search_removes_keychains_that_do_not_exist(self):
        deadend = Keychain('DeadEnd.keychain')
        deadend.add_to_keychain_search()
        self.assertTrue(deadend.path in Keychains.list_keychain_paths())
        Keychains.cleanup_keychain_search()
        self.assertFalse(deadend.path in Keychains.list_keychain_paths())

