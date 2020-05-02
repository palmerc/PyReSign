import pathlib
import plistlib
import subprocess

from keychains import TemporaryKeychain
from misc import signer_hash


class Mobileprovision:
    def __init__(self, mobileprovision):
        self.mobileprovision = pathlib.Path(mobileprovision).resolve()

    def plist(self):
        with TemporaryKeychain() as tk:
            cms_cmd = ['security', 'cms', '-D']
            cms_cmd.extend(['-k', tk.path.as_posix()])
            cms_cmd.extend(['-i', self.mobileprovision.as_posix()])
            plist_string = subprocess.check_output(cms_cmd)
            return plistlib.loads(plist_string)

    def developer_certificates(self):
        return self.plist()['DeveloperCertificates']

    def entitlements(self):
        return self.plist()['Entitlements']

    def signer_hash(self):
        certs = self.developer_certificates()
        if certs:
            return signer_hash(certs[-1])

        return None

