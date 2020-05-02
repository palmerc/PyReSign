import pathlib
import random
import tempfile
import unittest

from collections import Counter
from keychains import Keychain, Keychains, TemporaryKeychain


class TestKeychain (unittest.TestCase):
    def setUp(self) -> None:
        self.keychain_name = TestKeychain.random_keychain_name()
        self.user_keychain_path = '~/Library/Keychains/{}.keychain-db'.format(self.keychain_name)

    def test_keychain_full_path(self):
        # Full path to final file
        fq_path = pathlib.Path(self.user_keychain_path).expanduser()
        keychain = Keychain(fq_path, password=self.keychain_name)
        self.assertEqual(self.keychain_name, keychain.name)
        self.assertEqual(fq_path, keychain.path)

    def test_keychain_short_name(self):
        # Just the name without .keychain or .keychain-db
        keychain = Keychain(self.keychain_name, password=self.keychain_name)
        fq_path = pathlib.Path(self.user_keychain_path).expanduser()
        self.assertEqual(self.keychain_name, keychain.name)
        self.assertEqual(fq_path, keychain.path)

    def test_keychain_keychain_name(self):
        # If the caller provides .keychain
        fq_path = pathlib.Path(self.user_keychain_path).expanduser()
        keychain = Keychain(self.keychain_name + '.keychain', password=self.keychain_name)
        self.assertEqual(self.keychain_name, keychain.name)
        self.assertEqual(fq_path, keychain.path)

    def test_keychain_keychain_db_name(self):
        # If the caller provides .keychain-db
        fq_path = pathlib.Path(self.user_keychain_path).expanduser()
        keychain = Keychain(self.keychain_name + '.keychain-db', password=self.keychain_name)
        self.assertEqual(self.keychain_name, keychain.name)
        self.assertEqual(fq_path, keychain.path)

    def test_create_keychain_in_tmp(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fq_path = pathlib.Path('{}/{}.keychain-db'.format(tmpdir, self.keychain_name)).expanduser()
            keychain = Keychain(fq_path, password=self.keychain_name, create=True)
            self.assertEqual(self.keychain_name, keychain.name)
            self.assertTrue(keychain.exists())
            self.assertTrue(keychain.searchable())
            keychain.delete()
            self.assertTrue(not keychain.exists())

    def test_import_certificate(self):
        with TemporaryKeychain() as tk:
            tk.import_codesign_certificate('./TestCertificate.p12', dist_cer_pass='test')
            shasum = tk.get_codesign_identities()[0][1]
            self.assertEqual(shasum, 'D14B0D8B333BE0451C9CF1E88F14D99087435623')

    def test_adding_keychain_to_search_list_adds_it_exactly_once(self):
        deadend = Keychain('DeadEnd.keychain')
        deadend.add_to_keychain_search()
        deadend.add_to_keychain_search()
        deadend.add_to_keychain_search()
        paths = Keychains.list_keychain_paths()
        count = Counter(paths)
        self.assertEqual(count[deadend.path], 1)

    @staticmethod
    def random_keychain_name():
        return 'TemporaryKeychain-' + str(random.randrange(0x1000000000))

