import hashlib
import pathlib


def paths_from_lines(string):
    return [pathlib.Path(x.strip(' "')) for x in string.split()]


def remove_ends(text, suffixes):
    for suffix in suffixes:
        if text.endswith(suffix):
            return text[:-len(suffix)]
    return text


def remove_end(text, suffix):
    return remove_ends(text, [suffix])


def signer_hash(certificate):
    return hashlib.sha1(certificate).hexdigest().upper()

