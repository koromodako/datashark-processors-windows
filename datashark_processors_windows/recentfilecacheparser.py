"""Datashark Template Plugin
"""
from typing import Dict
from asyncio.subprocess import PIPE, DEVNULL
from datashark_core.meta import ProcessorMeta
from datashark_core.logging import LOGGING_MANAGER
from datashark_core.processor import ProcessorInterface, ProcessorError
from datashark_core.model.api import Kind, System, ProcessorArgument

NAME = 'windows_recentfilecacheparser'
LOGGER = LOGGING_MANAGER.get_logger(NAME)


class RecentFileCacheParserProcessor(
    ProcessorInterface, metaclass=ProcessorMeta
):
    """RecentFileCacheParser processor"""

    NAME = NAME
    SYSTEM = System.WINDOWS
    ARGUMENTS = [
        {
            'name': 'csvf',
            'kind': Kind.STR,
            'required': False,
            'description': """
                File name to save CSV formatted results to
            """,
        },
        {
            'name': 'csv',
            'kind': Kind.PATH,
            'required': False,
            'description': """
                Directory to save CSV formatted results to. Either this or 'json' is required
            """,
        },
        {
            'name': 'json',
            'kind': Kind.PATH,
            'required': False,
            'description': """
                Directory to save json representation to
            """,
        },
        {
            'name': 'f',
            'kind': Kind.PATH,
            'required': True,
            'description': """File to process""",
        },
    ]
    DESCRIPTION = """
    Processor for Eric Zimmermann's RecentFileCacheParser
    """

    async def _run(self, arguments: Dict[str, ProcessorArgument]):
        """Process resources using recentfilecacheparser"""
        # invoke subprocess
        proc = await self._start_subprocess(
            'datashark.processors.recentfilecacheparser.bin',
            ['-q'],
            [
                # optional
                ('csvf', '--csvf'),
                ('csv', '--csv'),
                ('json', '--json'),
                ('f', '-f'),
                # positional
            ],
            arguments,
            stdout=DEVNULL,
            stderr=PIPE,
        )
        await self._handle_communicating_process(proc)
