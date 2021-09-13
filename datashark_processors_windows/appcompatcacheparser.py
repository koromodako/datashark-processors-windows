"""Datashark Template Plugin
"""
from typing import Dict
from asyncio.subprocess import PIPE, DEVNULL
from datashark_core.meta import ProcessorMeta
from datashark_core.logging import LOGGING_MANAGER
from datashark_core.processor import ProcessorInterface, ProcessorError
from datashark_core.model.api import Kind, System, ProcessorArgument

NAME = 'windows_appcompatcacheparser'
LOGGER = LOGGING_MANAGER.get_logger(NAME)


class AppCompatCacheParserProcessor(
    ProcessorInterface, metaclass=ProcessorMeta
):
    """AppCompatCacheParser processor"""

    NAME = NAME
    SYSTEM = System.WINDOWS
    ARGUMENTS = [
        {
            'name': 't',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': """
                Sorts last modified timestamps in descending order
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
            'name': 'c',
            'kind': Kind.STR,
            'required': False,
            'description': """
                The ControlSet to parse. Default is to extract all control sets
            """,
        },
        {
            'name': 'f',
            'kind': Kind.PATH,
            'required': True,
            'description': """
                Full path to SYSTEM hive to process
            """,
        },
        {
            'name': 'csv',
            'kind': Kind.PATH,
            'required': True,
            'description': """
                Directory to save CSV formatted results to
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
    Processor for Eric Zimmermann's AppCompatCacheParser
    """

    async def _run(self, arguments: Dict[str, ProcessorArgument]):
        """Process resources using appcompatcacheparser"""
        # invoke subprocess
        proc = await self._start_subprocess(
            'datashark.processors.appcompatcacheparser.bin',
            [],
            [
                # optional
                ('t', '-t'),
                ('nl', '--nl'),
                ('dt', '--dt'),
                ('c', '-c'),
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
