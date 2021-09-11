"""Datashark Template Plugin
"""
from typing import Dict
from asyncio.subprocess import PIPE, DEVNULL
from datashark_core.meta import ProcessorMeta
from datashark_core.logging import LOGGING_MANAGER
from datashark_core.processor import ProcessorInterface, ProcessorError
from datashark_core.model.api import Kind, System, ProcessorArgument

NAME = 'windows_pecmd'
LOGGER = LOGGING_MANAGER.get_logger(NAME)


class PECmdProcessor(ProcessorInterface, metaclass=ProcessorMeta):
    """Template of a processor"""

    NAME = NAME
    SYSTEM = System.WINDOWS
    ARGUMENTS = [
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
            'name': 'vss',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': """
                Process all Volume Shadow Copies that exist on drive specified by 'f' or 'd'
            """,
        },
        {
            'name': 'dedupe',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': """
                Do not deduplicate 'f' or 'd' & VSCs based on SHA-1. First file found wins
            """,
        },
        {
            'name': 'k',
            'kind': Kind.STR,
            'value': '',
            'required': False,
            'description': """
                Comma separated list of keywords to highlight in output. By default, 'temp' and 'tmp' are highlighted.
                Any additional keywords will be added to these
            """,
        },
        {
            'name': 'o',
            'kind': Kind.PATH,
            'required': False,
            'description': """
                When specified, save prefetch file bytes to the given path. Useful to look at decompressed Win10 files
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
            'name': 'json',
            'kind': Kind.PATH,
            'required': False,
            'description': """Directory to save json representation to""",
        },
        {
            'name': 'jsonf',
            'kind': Kind.STR,
            'required': False,
            'description': """File name to save JSON formatted results to""",
        },
        {
            'name': 'csv',
            'kind': Kind.PATH,
            'required': False,
            'description': """
                Directory to save CSV results to. Be sure to include the full path in double quotes
            """,
        },
        {
            'name': 'csvf',
            'kind': Kind.STR,
            'required': False,
            'description': """File name to save CSV formatted results to""",
        },
        {
            'name': 'html',
            'kind': Kind.PATH,
            'required': False,
            'description': """Directory to save xhtml formatted results to""",
        },
        {
            'name': 'd',
            'kind': Kind.PATH,
            'required': False,
            'description': """
                Directory to recursively process. Either this or 'f' is required
            """,
        },
        {
            'name': 'f',
            'kind': Kind.PATH,
            'required': False,
            'description': """
                File to process. Either this or 'd' is required
            """,
        },
    ]
    DESCRIPTION = """
    Processor for Eric Zimmermann's PECmd
    """

    async def _run(self, arguments: Dict[str, ProcessorArgument]):
        """Process resources using pecmd"""
        # invoke subprocess
        proc = await self._start_subprocess(
            'datashark.processors.pecmd.bin',
            ['-q'],
            [
                # optional
                ('mp', '--mp'),
                ('vss', '--vss'),
                ('dedupe', '--dedupe'),
                ('k', '-k'),
                ('o', '-o'),
                ('dt', '--dt'),
                ('json', '--json'),
                ('jsonf', '--jsonf'),
                ('csv', '--csv'),
                ('csvf', '--csvf'),
                ('html', '--html'),
                ('d', '-d'),
                ('f', '-f'),
                # positional
            ],
            arguments,
            stdout=DEVNULL,
            stderr=PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise ProcessorError(stderr)
