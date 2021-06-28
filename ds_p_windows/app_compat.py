"""Decode app compat cache data stored in Windows registry

https://github.com/libyal/winreg-kb/blob/main/documentation/Application%20Compatibility%20Cache%20key.asciidoc#windows-10-application-compat-cache-entry

Offset  Size    Value                   Description
0       4       "10ts"                  Signature
4       4                               Unknown
8       4       Cache entry data size   The size of the cache entry without the first 12 bytes
12      2       Path size
14      ...     Path                    UTF-16 little-endian string without end-of-character
...     8       Last modification time  Contains a FILETIME
...     4       Data size
...     ...     Data
"""
from struct import unpack
from binascii import unhexlify
from . import LOGGER

ENTRY_SIG = b'10ts'


def app_compat_cache_handler(properties, _match, name, data):
    properties.setdefault(name, set()).add(data)


def decode_app_compat_cache(data):
    entries = []
    data = unhexlify(data)
    offset = 0
    while True:
        offset = data.find(ENTRY_SIG, offset)
        if offset < 0:
            break
        offset += 4 + 4 + 4
        path_size = unpack('<H', data[offset : offset + 2])[0]
        offset += 2
        entries.append(data[offset : offset + path_size].decode('utf-16'))
    return entries
