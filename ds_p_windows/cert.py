"""Decode x509 certificates stored in Windows Registry

https://blog.nviso.eu/2019/08/28/extracting-certificates-from-the-windows-registry/

"""
from struct import unpack
from binascii import unhexlify
from cryptography.x509 import load_der_x509_certificate
from . import LOGGER

CERT_SIG = b'\x20\x00\x00\x00\x01\x00\x00\x00'


def cert_handler(properties, match, name, data):
    guid = match.group('guid')
    subject = decode_x509_cert(data)
    properties.setdefault(name, set()).add(f'{guid}:{subject}')


def decode_x509_cert(data):
    data = unhexlify(data)
    offset = 0
    while True:
        offset = data.find(CERT_SIG, offset)
        if offset < 0:
            break
        offset += 8
        der_size = unpack('<I', data[offset : offset + 4])[0]
        offset += 4
        cert = load_der_x509_certificate(data[offset : offset + der_size])
        return cert.subject.rfc4514_string()
