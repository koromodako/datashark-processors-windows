"""Windows registry hive processor

https://github.com/ForensicArtifacts/artifacts/blob/5df040a9e29ddca3cd06ec2c26eb00c5ab35ed71/data/windows.yaml
"""
import re
from json import dumps
from codecs import encode
from struct import unpack
from pathlib import Path
from binascii import unhexlify
import pyregf
from ds_core.api import Artifact
from ds_core.yara import match_sig
from ds_core.plugin import Plugin
from . import LOGGER
from .cert import cert_handler
from .app_compat import app_compat_cache_handler

REGISTRY_HIVE_MAGIC = b'regf'

CONVERT_FMAP = {
    1: lambda val: val.get_data_as_string(),
    2: lambda val: val.get_data_as_string(),
    4: lambda val: val.get_data_as_integer(),
}


def _default_match_handler(properties, _match, name, data):
    properties.setdefault(name, set()).add(data)


def _extra_match_handler(properties, match, name, data):
    extra = match.group('extra')
    properties.setdefault(name, set()).add(f'{extra}:{data}')


def _channel_hints_handler(properties, _match, name, data):
    data = unhexlify(data)
    ssid = data[4 : 4 + unpack('<I', data[:4])[0]].decode()
    properties.setdefault(name, set()).add(ssid)


def _user_assist_handler(properties, match, name, _data):
    path = match.group('path')
    path = encode(path, 'rot_13')
    properties.setdefault(name, set()).add(path)


_REGISTRY_ARTIFACTS = {
    # hardware info
    r'/HardwareConfig/.*:BaseBoardManufacturer': {
        'name': 'win_base_board_man'
    },
    r'/HardwareConfig/.*:BaseBoardProduct': {
        'name': 'win_base_board_prod',
    },
    r'/HardwareConfig/.*:BIOSReleaseDate': {
        'name': 'win_bios_rel_date',
    },
    r'/HardwareConfig/.*:BIOSVendor': {
        'name': 'win_bios_vendor',
    },
    r'/HardwareConfig/.*:BIOSVersion': {
        'name': 'win_bios_version',
    },
    r'/HardwareConfig/.*:SystemBiosVersion': {
        'name': 'win_sys_bios_version',
    },
    r'/HardwareConfig/.*:SystemFamily': {
        'name': 'win_sys_family',
    },
    r'/HardwareConfig/.*:SystemManufacturer': {
        'name': 'win_sys_man',
    },
    r'/HardwareConfig/.*:SystemProductName': {
        'name': 'win_sys_prod_name',
    },
    r'/HardwareConfig/.*:SystemSKU': {
        'name': 'win_sys_sku',
    },
    r'/HardwareConfig/.*:SystemVersion': {
        'name': 'win_system_version',
    },
    # os version
    r'/Microsoft/Windows NT/CurrentVersion:CurrentBuild': {
        'name': 'win_build',
    },
    r'/Microsoft/Windows NT/CurrentVersion:CurrentBuildNumber': {
        'name': 'win_build_number'
    },
    r'/Microsoft/Windows NT/CurrentVersion:CurrentVersion': {
        'name': 'win_nt_version'
    },
    r'/Microsoft/Windows NT/CurrentVersion:EditionID': {
        'name': 'win_edition_id'
    },
    r'/Microsoft/Windows NT/CurrentVersion:InstallationType': {
        'name': 'win_install_type'
    },
    r'/Microsoft/Windows NT/CurrentVersion:ProductName': {
        'name': 'win_product_name'
    },
    # updates
    r'/Microsoft/Windows/CurrentVersion/Component Based Servicing/Packages/.+(?P<extra>KB\d+).+:CurrentState': {
        'name': 'win_updates',
        'handler': _extra_match_handler,
    },
    # network cards
    r'/Microsoft/Windows NT/CurrentVersion/NetworkCards/\d+:Description': {
        'name': 'win_network_cards'
    },
    # wifi SSIDs
    r'/Microsoft/WlanSvc/Interfaces/[^/]+/Profiles/[^/]+/MetaData:Channel Hints': {
        'name': 'win_wifi_ssids',
        'handler': _channel_hints_handler,
    },
    # user profiles
    r'/Microsoft/Windows NT/CurrentVersion/ProfileList/(.*):ProfileImagePath': {
        'name': 'win_user_profiles'
    },
    # autorun keys
    r'/Microsoft/Windows/CurrentVersion/Run:(?P<extra>.+)': {
        'name': 'win_autorun_run_keys',
        'handler': _extra_match_handler,
    },
    r'/Microsoft/Windows/CurrentVersion/RunOnce:(?P<extra>.+)': {
        'name': 'win_autorun_runonce_keys',
        'handler': _extra_match_handler,
    },
    r'/Microsoft/Windows NT/CurrentVersion/Winlogon:AppSetup': {
        'name': 'win_autorun_logon_appsetup'
    },
    r'/Policies/Microsoft/Windows/System/Scripts/(?P<extra>[^/]+)/.*:Script': {
        'name': 'win_autorun_scripts',
        'handler': _extra_match_handler,
    },
    r'/Microsoft/Windows/CurrentVersion/Group Policy/Scripts/(?P<extra>[^/]+)/.*:Script': {
        'name': 'win_autorun_gpo_scripts',
        'handler': _extra_match_handler,
    },
    r'/Microsoft/Windows NT/CurrentVersion/Winlogon:Shell': {
        'name': 'win_autorun_logon_shell'
    },
    r'/Microsoft/Windows/CurrentVersion/Policies/System:Shell': {
        'name': 'win_autorun_system_shell'
    },
    r'/(Current)?ControlSet\d*/Control/Terminal Server/Wds/rdpwd:StartupPrograms': {
        'name': 'win_autorun_rdpwd'
    },
    r'/(Current)?ControlSet\d*/Control/Terminal Server/WinStations/RDP-Tcp:InitialProgram': {
        'name': 'win_autorun_rdptcp'
    },
    r'/Microsoft/Windows/CurrentVersion/Explorer/User Shell Folders:Startup': {
        'name': 'win_startup_folder'
    },
    # history folder
    r'/Software/Microsoft/Windows/CurrentVersion/Explorer/User Shell Folders:History': {
        'name': 'win_history_folder'
    },
    # winlogon info
    r'/Microsoft/Windows NT/CurrentVersion/Winlogon:LastUsedUsername': {
        'name': 'win_logon_last_used_user'
    },
    r'/Microsoft/Windows NT/CurrentVersion/Winlogon:ShellInfrastructure': {
        'name': 'win_logon_shell_infra'
    },
    r'/Microsoft/Windows NT/CurrentVersion/Winlogon:Userinit': {
        'name': 'win_logon_userinit'
    },
    # scheduled tasks
    r'/Microsoft/Windows NT/CurrentVersion/Schedule/TaskCache/Tasks/.*:URI': {
        'name': 'win_scheduled_tasks'
    },
    # system certificates
    r'/Microsoft/SystemCertificates/AuthRoot/Certificates/(?P<guid>.+):Blob': {
        'name': 'win_cert_authroot',
        'handler': cert_handler,
    },
    r'/Microsoft/SystemCertificates/CA/Certificates/(?P<guid>.+):Blob': {
        'name': 'win_cert_ca',
        'handler': cert_handler,
    },
    # app init dlls
    r'/Microsoft/Windows NT/CurrentVersion/Windows:AppInit_DLLs': {
        'name': 'win_app_init_dlls'
    },
    # shell extensions
    r'/Microsoft/Windows/CurrentVersion/Shell Extensions/Approved:\{.*': {
        'name': 'win_shell_extensions'
    },
    # shell run & load
    r'/Microsoft/Windows NT/CurrentVersion/Windows:Load': {
        'name': 'win_shell_load'
    },
    r'/Microsoft/Windows NT/CurrentVersion/Windows:Run': {
        'name': 'win_shell_run'
    },
    # icon service library
    r'/Microsoft/Windows NT/CurrentVersion/Windows:IconServiceLib': {
        'name': 'win_icon_svc_lib'
    },
    # shell open & runas commands
    r'/\*/shell/open/command:(IsolatedCommand)?': {
        'name': 'win_shell_open_cmd'
    },
    r'/\*/shell/runas/command:(IsolatedCommand)?': {
        'name': 'win_shell_runas_cmd'
    },
    # shell service obj delay load
    r'/Microsoft/Windows/CurrentVersion/ShellServiceObjectDelayLoad:(?P<extra>.+)': {
        'name': 'win_shell_svc_obj_del_load',
        'handler': _extra_match_handler,
    },
    # stub path
    r'/Microsoft/Active Setup/Installed Components/[^/]+:StubPath': {
        'name': 'win_stub_paths'
    },
    # UAC status
    r'/Microsoft/Windows/CurrentVersion/Policies/System:EnableLUA': {
        'name': 'win_uac_enable_lua'
    },
    r'/Microsoft/Windows/CurrentVersion/Policies/System:ConsentPromptBehaviorAdmin': {
        'name': 'win_uac_consent_admin'
    },
    r'/Microsoft/Windows/CurrentVersion/Explorer/UserAssist/[^/]+/Count:(?P<path>.+)': {
        'name': 'win_user_assist',
        'handler': _user_assist_handler,
    },
    # datetime
    r'/(Current)?ControlSet\d*/Control/TimeZoneInformation:TimeZoneKeyName': {
        'name': 'win_time_zone'
    },
    # bluetooth devices
    r'/(Current)?ControlSet\d*/Enum/BTHENUM/[^/]+/.*:FriendlyName': {
        'name': 'win_bluetooth_devices'
    },
    # SCSI devices
    r'/(Current)?ControlSet\d*/Enum/SCSI/[^/]+/.*:FriendlyName': {
        'name': 'win_scsi_devices'
    },
    # USB printers
    r'/(Current)?ControlSet\d*/Enum/USBPRINT/[^/]+/.*:DeviceDesc': {
        'name': 'win_usb_printers'
    },
    # USB storages
    r'/(Current)?ControlSet\d*/Enum/USBSTOR/[^/]+/.*:FriendlyName': {
        'name': 'win_usb_storages'
    },
    # services
    r'/(Current)?ControlSet\d*/Services/(?P<extra>[^/]+):ImagePath': {
        'name': 'win_services',
        'handler': _extra_match_handler,
    },
    # IP settings
    r'/(Current)?ControlSet\d*/Services/Tcpip/Parameters:Domain': {
        'name': 'win_domain'
    },
    r'/(Current)?ControlSet\d*/Services/Tcpip/Parameters:HostName': {
        'name': 'win_hostname'
    },
    r'/(Current)?ControlSet\d*/Services/Tcpip/Parameters/Interfaces/(?P<extra>[^/]+):IpAddress': {
        'name': 'win_static_addresses',
        'handler': _extra_match_handler,
    },
    r'/(Current)?ControlSet\d*/Services/Tcpip/Parameters/Interfaces/(?P<extra>[^/]+):DhcpIpAddress': {
        'name': 'win_dynamic_addresses',
        'handler': _extra_match_handler,
    },
    r'/(Current)?ControlSet\d*/Services/Tcpip/Parameters/Interfaces/(?P<extra>[^/]+):SubnetMask': {
        'name': 'win_netmasks',
        'handler': _extra_match_handler,
    },
    # alternate shell
    r'/(Current)?ControlSet\d*/Control/SafeBoot:AlternateShell': {
        'name': 'win_alt_shell'
    },
    # app compat cache
    r'/(Current)?ControlSet\d*/Control/Session Manager/AppCompatibility:AppCompatCache': {
        'name': 'win_app_compat_cache',
        'handler': app_compat_cache_handler,
    },
    r'/(Current)?ControlSet\d*/Control/Session Manager/AppCompatCache:AppCompatCache': {
        'name': 'win_app_compat_cache',
        'handler': app_compat_cache_handler,
    },
    # boot info
    r'/(Current)?ControlSet\d*/Control/Session Manager:BootExecute': {
        'name': 'win_boot_execute'
    },
    r'/(Current)?ControlSet\d*/Control/Session Manager:BootShell': {
        'name': 'win_boot_shell'
    },
    r'/(Current)?ControlSet\d*/Control/Session Manager:SetupExecute': {
        'name': 'win_boot_setup_execute'
    },
    # prefetch
    r'/(Current)?ControlSet\d*/Control/Session Manager/Memory Management/PrefetchParameters:EnablePrefetcher': {
        'name': 'win_enable_prefetch'
    },
}
REGISTRY_ARTIFACTS = {
    re.compile(key, re.IGNORECASE): val
    for key, val in _REGISTRY_ARTIFACTS.items()
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
        for key_pattern, prop in REGISTRY_ARTIFACTS.items():
            match = key_pattern.search(keyval)
            if match:
                match_handler = prop.get('handler', _default_match_handler)
                data = match_handler(properties, match, prop['name'], data)
    # normalize properties
    for name, value in properties.items():
        properties[name] = dumps(list(map(str, value)))
    plugin.register_artifact_properties(artifact, properties)
