import os
import pathlib
import random
import re
import subprocess
import sys

from collections import OrderedDict
from misc import paths_from_lines, remove_ends, signer_hash


class Keychains:
    @staticmethod
    def cleanup_keychain_search(only_user_keychains=True):
        valid_keychains = []
        user_home_dir = pathlib.Path.home().as_posix()
        keychains = list(OrderedDict.fromkeys(Keychains.keychains()))
        for keychain in keychains:
            is_user_keychain = keychain.path.as_posix().startswith(user_home_dir)
            if only_user_keychains and not is_user_keychain:
                valid_keychains.append(keychain)
                continue

            if keychain.path.is_file():
                valid_keychains.append(keychain)

        if Keychains.keychains() != valid_keychains:
            Keychains.rewrite_keychain_search(valid_keychains)

    @staticmethod
    def find_keychains_with_certificate(certificate):
        keychains = []

        certificate_hash = signer_hash(certificate)
        for keychain in Keychains.keychains():
            identities = keychain.get_codesign_identities()
            for identity in identities:
                identity_hash = identity[1].upper()
                if identity_hash == certificate_hash:
                    keychains.append(keychain.path)

        return keychains

    @staticmethod
    def is_valid_signing_certificate_available(certificate):
        keychains = Keychains.find_keychains_with_certificate(certificate)
        if len(keychains) > 0:
            return True
        else:
            return False

    @staticmethod
    def keychains():
        keychains = []
        for keychain_path in Keychains.list_keychain_paths():
            keychains.append(Keychain(keychain_path))
        return keychains

    @staticmethod
    def clean_keychain_name(name):
        return remove_ends(name, ['.keychain', '.keychain-db'])

    @staticmethod
    def list_keychain_paths():
        paths = subprocess.check_output(['security', 'list-keychains']).decode(sys.stdout.encoding)
        return paths_from_lines(paths)

    @staticmethod
    def rewrite_keychain_search(keychains):
        keychain_paths = [keychain.path.as_posix() for keychain in keychains]
        list_keychains_cmd = ['security', 'list-keychains', '-s']
        list_keychains_cmd.extend(keychain_paths)
        subprocess.run(list_keychains_cmd, check=True)


class Keychain:
    def __init__(self, keychain, password=None, create=False):
        is_user_keychain = False
        if isinstance(keychain, str):
            if keychain == os.path.basename(keychain):
                is_user_keychain = True
            keychain_path = pathlib.Path(keychain)
        else:
            keychain_path = keychain

        self.name = Keychains.clean_keychain_name(keychain_path.name)
        if is_user_keychain:
            user_keychain_dir = pathlib.Path.home().joinpath('Library', 'Keychains')
            self.path = user_keychain_dir.joinpath(self.name + '.keychain-db')
        else:
            self.path = keychain_path

        self.password = password

        if not self.exists() and create:
            self.create_and_configure()

    def __str__(self):
        return self.path.as_posix()

    def exists(self):
        return self.path.is_file()

    def searchable(self):
        return self.path.resolve() in Keychains.list_keychain_paths()

    def create(self):
        if not self.exists():
            create_keychain_cmd = ['security', 'create-keychain']
            if self.password:
                create_keychain_cmd.extend(['-p', self.password])
            create_keychain_cmd.append(self.path.as_posix())
            subprocess.run(create_keychain_cmd, check=True)
        else:
            raise Exception('Keychain creation failed. Keychain {} already exists'.format(self.name))

    def lock(self):
        if self.exists():
            lock_keychain_cmd = ['security', 'lock-keychain', self.path.as_posix()]
            subprocess.run(lock_keychain_cmd, check=True)
        else:
            raise Exception('Keychain lock failed. Keychain {} does not exist'.format(self.name))

    def unlock(self):
        if self.exists():
            unlock_keychain_cmd = ['security', 'unlock-keychain']
            if self.password:
                unlock_keychain_cmd.extend(['-p', self.password])
            unlock_keychain_cmd.append(self.path.as_posix())
            subprocess.run(unlock_keychain_cmd, check=True)
        else:
            raise Exception('Keychain unlock failed. Keychain {} does not exist'.format(self.name))

    def set_unlock_no_timeout(self):
        if self.exists():
            set_keychain_settings_cmd = ['security', 'set-keychain-settings', self.path.as_posix()]
            subprocess.run(set_keychain_settings_cmd, check=True)
        else:
            raise Exception('Keychain setting defaults failed. Keychain {} does not exist'.format(self.name))

    def set_partition_list(self, partition_list):
        if self.exists():
            key_partition_list_cmd = ['security', 'set-key-partition-list',
                                      '-S', partition_list,
                                      '-s']
            if self.password:
                key_partition_list_cmd.extend(['-k', self.password])
            key_partition_list_cmd.append(self.path.as_posix())
            subprocess.run(key_partition_list_cmd, check=True, stdout=subprocess.DEVNULL)
        else:
            raise Exception('Keychain set partition list failed. Keychain {} does not exist'.format(self.name))

    def set_apple_tool_partition_list(self):
        self.set_partition_list('apple-tool:,apple:')

    def create_and_configure(self):
        self.create()
        self.add_to_keychain_search()
        self.unlock()
        self.set_unlock_no_timeout()

    def has_signing_certificates(self, dist_cert, dist_cert_pass):
        existing_hashes = {codesign_identity[1] for codesign_identity in self.get_codesign_identities()}
        with TemporaryKeychain() as tk:
            tk.import_codesign_certificate(dist_cert, dist_cert_pass)
            codesign_identities = tk.get_codesign_identities()
            p12_hashes = {codesign_identity[1] for codesign_identity in codesign_identities}
            return p12_hashes.issubset(existing_hashes)

    def import_codesign_certificate(self, dist_cer_path, dist_cer_pass=None):
        if isinstance(dist_cer_path, str):
            dist_cer_path = pathlib.Path(dist_cer_path)

        posix_path = dist_cer_path.as_posix()
        import_keychain_cmd = ['security', 'import', posix_path]
        if dist_cer_pass:
            import_keychain_cmd.extend(['-P', dist_cer_pass])

        import_keychain_cmd.extend(['-k', self.path.as_posix()])
        import_keychain_cmd.extend(['-T', '/usr/bin/codesign'])
        subprocess.run(import_keychain_cmd, check=True, stdout=subprocess.DEVNULL)
        self.set_apple_tool_partition_list()

    def delete(self):
        if self.exists():
            delete_keychain_cmd = ['security', 'delete-keychain', self.path.as_posix()]
            subprocess.run(delete_keychain_cmd, check=True)
        else:
            raise Exception('Keychain deletion failed. Keychain {} does not exist'.format(self.name))

    def add_to_keychain_search(self):
        if not self.searchable():
            existing_search_paths = [path.as_posix() for path in Keychains.list_keychain_paths()]
            list_keychains_cmd = ['security', 'list-keychains']
            list_keychains_cmd.extend(['-s', self.path.as_posix()])
            list_keychains_cmd.extend(existing_search_paths)
            subprocess.run(list_keychains_cmd, check=True)

    def get_codesign_identities(self):
        identity_re = re.compile(r'^\s+(?P<number>\d+)\) (?P<hash>[0-9A-F]+) "(?P<name>.+)"$')

        find_identity_cmd = ['security', 'find-identity', '-p', 'codesigning', '-v', self.path.as_posix()]
        identities = subprocess.check_output(find_identity_cmd).decode(sys.stdout.encoding).split('\n')
        valid_identities = []
        for identity in identities:
            matches = identity_re.match(identity)
            if matches:
                valid_identities.append((matches['number'], matches['hash'], matches['name']))

        return valid_identities


class TemporaryKeychain(Keychain):
    def __init__(self):
        name = 'TemporaryKeychain-' + str(random.randrange(0x1000000000))
        Keychain.__init__(self, name, password=name, create=True)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.delete()

