"""Datashark SigCheck Plugin
"""
from typing import Dict
from asyncio.subprocess import PIPE, DEVNULL
from datashark_core.meta import ProcessorMeta
from datashark_core.logging import LOGGING_MANAGER
from datashark_core.processor import ProcessorInterface
from datashark_core.model.api import Kind, System, ProcessorArgument

NAME = 'windows_sigcheck'
LOGGER = LOGGING_MANAGER.get_logger(NAME)


class SigCheckProcessor(ProcessorInterface, metaclass=ProcessorMeta):
    """SigCheck processor"""

    NAME = NAME
    SYSTEM = System.WINDOWS
    ARGUMENTS = [
        {
            'name': 's',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': "Recurse subdirectories"
        },
        {
            'name': 'e',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': "Scan executable images only (regardless of their extension)"
        },
        {
            'name': 'a',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': """
                Show extended version information. The entropy measure reported is the bits per byte of information of
                the file's contents.
            """
        },
        {
            'name': 'h',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': "Show file hashes"
        },
        {
            'name': 'r',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': "Disable check for certificate revocation"
        },
        {
            'name': 'u',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': """
                If VirusTotal check is enabled, show files that are unknown by VirusTotal or have non-zero detection,
                otherwise show only unsigned files.
            """
        },
        {
            'name': 'v',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': """
                Query VirusTotal (www.virustotal.com) for malware based on file hash.
            """
        },
        {
            'name': 'output',
            'kind': Kind.PATH,
            'required': True,
            'description': "Writes the output to the specified file."
        },
        {
            'name': 'filepath',
            'kind': Kind.PATH,
            'required': True,
            'description': "Input file or directory"
        },
    ]
    DESCRIPTION = """
    Processor for SysinternalsSuite's SigCheck
    """

    async def _run(self, arguments: Dict[str, ProcessorArgument]):
        """Process resources using srumecmd"""
        # invoke subprocess
        proc = await self._start_subprocess(
            'datashark.processors.sigcheck.bin',
            ['-nobanner', '-c', '-vt'],
            [
                # optional
                ('s', '-s'),
                ('e', '-e'),
                ('a', '-a'),
                ('h', '-h'),
                ('r', '-r'),
                ('u', '-u'),
                ('v', '-v'),
                ('output', '-w'),
                # positional
                ('filepath', None),
            ],
            arguments,
            stdout=DEVNULL,
            stderr=PIPE,
        )
        await self._handle_communicating_process(proc)
