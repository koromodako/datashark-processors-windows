"""Datashark Template Plugin
"""
from typing import Dict
from asyncio.subprocess import PIPE, DEVNULL
from datashark_core.meta import ProcessorMeta
from datashark_core.logging import LOGGING_MANAGER
from datashark_core.processor import ProcessorInterface, ProcessorError
from datashark_core.model.api import Kind, System, ProcessorArgument

NAME = 'windows_amcacheparser'
LOGGER = LOGGING_MANAGER.get_logger(NAME)


class AmCacheParserProcessor(ProcessorInterface, metaclass=ProcessorMeta):
    """AmCacheParser processor"""

    NAME = NAME
    SYSTEM = System.WINDOWS
    ARGUMENTS = [
        {
            'name': 'i',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': """
                Include file entries for Programs entries
            """,
        },
        {
            'name': 'mp',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': """
                When true, display higher precision for timestamps
            """,
        },
        {
            'name': 'nl',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': """
                When true, ignore transaction log files for dirty hives
            """,
        },
        {
            'name': 'dt',
            'kind': Kind.STR,
            'value': 'yyyy-MM-dd HH:mm:ss',
            'required': False,
            'description': """
                The custom date/time format to use when displaying timestamps. See https://goo.gl/CNVq0k for options
            """,
        },
        {
            'name': 'b',
            'kind': Kind.PATH,
            'required': False,
            'description': """
                Path to file containing SHA-1 hashes to include from the results. Blacklisting overrides whitelisting
            """,
        },
        {
            'name': 'w',
            'kind': Kind.PATH,
            'required': False,
            'description': """
                Path to file containing SHA-1 hashes to exclude from the results. Blacklisting overrides whitelisting
            """,
        },
        {
            'name': 'f',
            'kind': Kind.PATH,
            'required': True,
            'description': """
                Amcache.hve file to parse
            """,
        },
        {
            'name': 'csv',
            'kind': Kind.PATH,
            'required': True,
            'description': """
                Directory where CSV results will be saved to
            """,
        },
        {
            'name': 'csvf',
            'kind': Kind.STR,
            'required': False,
            'description': """
                File name to save CSV formatted results to. When present, overrides default name
            """,
        },
    ]
    DESCRIPTION = """
    Processor for Eric Zimmermann's AmCacheParser
    """

    async def _run(self, arguments: Dict[str, ProcessorArgument]):
        """Process resources using amcacheparser"""
        # invoke subprocess
        proc = await self._start_subprocess(
            'datashark.processors.amcacheparser.bin',
            [],
            [
                # optional
                ('i', '-i'),
                ('mp', '--mp'),
                ('nl', '--nl'),
                ('dt', '--dt'),
                ('b', '-b'),
                ('w', '-w'),
                ('f', '-f'),
                ('csv', '--csv'),
                ('csvf', '--csvf'),
                # positional
            ],
            arguments,
            stdout=DEVNULL,
            stderr=PIPE,
        )
        await self._handle_communicating_process(proc)
