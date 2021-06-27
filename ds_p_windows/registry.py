"""Windows Registry Forensics
"""
import re
from struct import unpack
from pathlib import Path
from binascii import unhexlify
import pyregf
from ds_core.api import Artifact
from ds_core.yara import match_sig
from ds_core.plugin import Plugin
from . import LOGGER

REGISTRY_HIVE_MAGIC = b'regf'

CONVERT_FMAP = {
    1: lambda val: val.get_data_as_string(),
    2: lambda val: val.get_data_as_string(),
    4: lambda val: val.get_data_as_integer(),
}

_REGISTRY_ARTIFACTS = {
    # os version
    r'/Microsoft/Windows NT/CurrentVersion:CurrentBuild': ('win_build', None),
    r'/Microsoft/Windows NT/CurrentVersion:CurrentBuildNumber': (
        'win_build_number',
        None,
    ),
    r'/Microsoft/Windows NT/CurrentVersion:CurrentVersion': (
        'win_nt_version',
        None,
    ),
    r'/Microsoft/Windows NT/CurrentVersion:EditionID': (
        'win_edition_id',
        None,
    ),
    r'/Microsoft/Windows NT/CurrentVersion:InstallationType': (
        'win_installation_type',
        None,
    ),
    r'/Microsoft/Windows NT/CurrentVersion:ProductName': (
        'win_product_name',
        None,
    ),
    # updates
    r'/Microsoft/Windows/CurrentVersion/Component Based Servicing/Packages/.+(KB\d+).+:CurrentState': (
        'win_updates',
        None,
    ),
    # network cards
    r'/Microsoft/Windows NT/CurrentVersion/NetworkCards/\d+:Description': (
        'win_network_cards',
        None,
    ),
    # wifi SSIDs
    r'/Microsoft/WlanSvc/Interfaces/[^/]+/Profiles/[^/]+/MetaData:Channel Hints': (
        'win_wifi_ssids',
        lambda data: unhexlify(data)[
            4 : 4 + unpack('<I', unhexlify(data)[:4])[0]
        ].decode(),
    ),
    # user profiles
    r'/Microsoft/Windows NT/CurrentVersion/ProfileList/(.*):ProfileImagePath': (
        'win_user_profiles',
        None,
    ),
    # datetime
    r'/(?:Current)?ControlSet\d*/Control/TimeZoneInformation:TimeZoneKeyName': (
        'win_time_zone',
        None,
    ),
    # bluetooth devices
    r'/(?:Current)?ControlSet\d*/Enum/BTHENUM/[^/]+/.*:FriendlyName': (
        'win_bluetooth_devices',
        None,
    ),
    # SCSI devices
    r'/(?:Current)?ControlSet\d*/Enum/SCSI/[^/]+/.*:FriendlyName': (
        'win_scsi_devices',
        None,
    ),
    # USB printers
    r'/(?:Current)?ControlSet\d*/Enum/USBPRINT/[^/]+/.*:DeviceDesc': (
        'win_usb_printers',
        None,
    ),
    # USB storages
    r'/(?:Current)?ControlSet\d*/Enum/USBSTOR/[^/]+/.*:FriendlyName': (
        'win_usb_storages',
        None,
    ),
}
REGISTRY_ARTIFACTS = {
    re.compile(key): val for key, val in _REGISTRY_ARTIFACTS.items()
}


def _iter_sub_keys(reg_key, prefixes):
    prefixes.append(reg_key.name)
    keypath = '/'.join(prefixes)
    if reg_key.number_of_values:
        for value in reg_key.values:
            data = CONVERT_FMAP.get(
                value.type,
                lambda val: val.data.hex() if val.data else val.data,
            )(value)
            yield f'{keypath}:{value.name}', data
    else:
        yield f'{keypath}:', None
    for sub_key in reg_key.sub_keys:
        yield from _iter_sub_keys(sub_key, prefixes)
    prefixes.pop()


def _enumerate_registry_keys(plugin: Plugin, artifact: Artifact):
    regf_file = pyregf.file()
    regf_file.open(
        str(
            artifact.filepath(
                plugin.config.get('datashark.core.directory.temp', type=Path)
            )
        )
    )
    try:
        for sub_key in regf_file.root_key.sub_keys:
            yield from _iter_sub_keys(sub_key, [''])
    except:
        LOGGER.exception("exception while processing!")
    regf_file.close()


def is_registry_hive(plugin: Plugin, artifact: Artifact):
    return match_sig(plugin.config, artifact, REGISTRY_HIVE_MAGIC)


def process_registry_hive(plugin: Plugin, artifact: Artifact):
    properties = {}
    for keyval, data in _enumerate_registry_keys(plugin, artifact):
        print(keyval)
        print(data)
        for key_pattern, prop in REGISTRY_ARTIFACTS.items():
            name, data_decode_func = prop
            match = key_pattern.search(keyval)
            if match:
                print(name)
                if data_decode_func:
                    data = data_decode_func(data)
                extra = '+'.join([grp for grp in match.groups() if grp])
                if extra:
                    data = f'{extra}:{data}'
                properties.setdefault(name, set()).add(data)
    # list to strings
    for prop, value in properties.items():
        properties[prop] = '|'.join(value)
    print(properties)
    # plugin.register_artifact_properties(artifact, properties)
