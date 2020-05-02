#!/usr/bin/env python3

import argparse
import pathlib
import plistlib
import shutil
import subprocess
import sys
import tempfile
import zipfile

from mobileprovision import Mobileprovision


def platform_sdk_path(platform):
    return subprocess.check_output(['xcrun', '--sdk', platform, '--show-sdk-platform-path'])


def find_developer_tool(developer_tool):
    return subprocess.check_output(['xcrun', '--find', developer_tool]).decode(sys.stdout.encoding).strip()


def codesign_allocate_path():
    return find_developer_tool('codesign_allocate')


def codesign_path():
    return find_developer_tool('codesign')


def find(path, item):
    return list(path.glob('**/' + item))


def find_app_paths(path):
    return find(path, '*.app')


def find_codesign_elements(path):
    elements = find(path, '*.appex')
    elements.extend(find(path, '*.framework'))
    elements.extend(find(path, '*.dylib'))
    return elements


def find_codesign_artifacts(path):
    artifacts = find(path, '_CodeSignature')
    artifacts.extend(find(path, 'CodeResources'))
    artifacts.extend(find(path, '*.mobileprovision'))
    return artifacts


def codesign(signable_path, signer_hash, entitlements_path=None):
    codesign_cmd = [codesign_path(), '--force', '--sign', signer_hash]
    if entitlements_path:
        codesign_cmd.extend(['--entitlements', entitlements_path.as_posix()])
    codesign_cmd.append('--timestamp=none')
    codesign_cmd.append(signable_path.as_posix())
    return subprocess.run(codesign_cmd, check=True, env={'CODESIGN_ALLOCATE': codesign_allocate_path()})


def main():
    parser = argparse.ArgumentParser(description='Re-sign an ipa or app')
    parser.add_argument('--app', dest='app',
                        help='path to .app or .ipa to sign', required=True)
    parser.add_argument('-p', '--profile', dest='profile',
                        help='mobileprovision to use for signing', required=True)
    parser.add_argument('-o', '--output', dest='output',
                        help='path to resigned app or ipa')
    args = parser.parse_args()

    app_path = pathlib.Path(args.app)
    if args.output:
        resigned_bundle_path = pathlib.Path(args.output)
    else:
        resigned_bundle_path = app_path.resolve().parent
        resigned_bundle_name = app_path.stem + '-resigned' + app_path.suffix
        resigned_bundle_path = resigned_bundle_path.joinpath(resigned_bundle_name)

    if app_path.suffix == '.app':
        is_zipped = False
    elif app_path.suffix == '.ipa':
        is_zipped = True
    else:
        raise Exception('Unknown app type: ' + app_path.suffix)

    mobileprovision_path = pathlib.Path(args.profile).resolve()
    mobileprovision = Mobileprovision(mobileprovision_path)
    entitlements = mobileprovision.entitlements()
    developer_certificate_hash = mobileprovision.signer_hash()

    with tempfile.TemporaryDirectory(prefix='iresign-') as t:
        temp_root = pathlib.Path(t)
        temp_app_path = temp_root.joinpath('app')
        temp_app_path.mkdir(parents=True)

        if is_zipped:
            with zipfile.ZipFile(app_path) as z:
                z.extractall(path=temp_app_path)
        else:
            shutil.copytree(app_path, temp_app_path)

        artifacts = find_codesign_artifacts(temp_app_path)
        for artifact in artifacts:
            if artifact.is_dir():
                shutil.rmtree(artifact)
            else:
                artifact.unlink()

        shutil.copy(mobileprovision_path, temp_app_path.joinpath('embedded.mobileprovision'))

        for codesign_element in find_codesign_elements(temp_app_path):
            codesign(codesign_element, developer_certificate_hash)

        entitlements_path = temp_root.joinpath('entitlements.plist')
        with open(entitlements_path, 'wb') as f:
            plist = plistlib.dumps(entitlements)
            f.write(plist)

        app_paths = find_app_paths(temp_app_path)
        for app_path in app_paths:
            codesign(app_path, developer_certificate_hash, entitlements_path=entitlements_path)

        if is_zipped:
            with zipfile.ZipFile(resigned_bundle_path, 'w') as z:
                for item in temp_app_path.glob('**/*'):
                    z.write(item, arcname=item.relative_to(temp_app_path))
        else:
            shutil.copytree(temp_app_path, resigned_bundle_path)


if __name__ == '__main__':
    main()

