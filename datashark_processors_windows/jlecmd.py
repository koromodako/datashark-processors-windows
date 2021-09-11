"""Datashark Template Plugin
"""
from typing import Dict
from asyncio.subprocess import PIPE, DEVNULL
from datashark_core.meta import ProcessorMeta
from datashark_core.logging import LOGGING_MANAGER
from datashark_core.processor import ProcessorInterface, ProcessorError
from datashark_core.model.api import Kind, System, ProcessorArgument

NAME = 'windows_jlecmd'
LOGGER = LOGGING_MANAGER.get_logger(NAME)


class JLECmdProcessor(ProcessorInterface, metaclass=ProcessorMeta):
    """JLECmd processor"""

    NAME = NAME
    SYSTEM = System.WINDOWS
    ARGUMENTS = [
        {
            'name': 'all',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': """
                Process all files in directory vs. only files matching *.automaticDestinations-ms
                or *.customDestinations-ms
            """,
        },
        {
            'name': 'ld',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': """
                Include more information about lnk files
            """,
        },
        {
            'name': 'mp',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': """
                Display higher precision for timestamps
            """,
        },
        {
            'name': 'fd',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': """
                Include full information about lnk files (Alternatively, dump lnk files using 'dumpTo'
                and process with LECmd)
            """,
        },
        {
            'name': 'withDir',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': """
                When true, show contents of Directory not accounted for in DestList entries
            """,
        },
        {
            'name': 'appIds',
            'kind': Kind.PATH,
            'required': False,
            'description': """
                Path to file containing AppIDs and descriptions (appid|description format). New appIds are
                added to the built-in list, existing appIds will have their descriptions updated
            """,
        },
        {
            'name': 'dumpTo',
            'kind': Kind.PATH,
            'required': False,
            'description': """Directory to save exported lnk files""",
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
            'name': 'csv',
            'kind': Kind.PATH,
            'required': False,
            'description': """Directory to save CSV formatted results to""",
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
            'name': 'json',
            'kind': Kind.PATH,
            'required': False,
            'description': """Directory to save json representation to""",
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
    Processor for Eric Zimmermann's JLECmd
    """

    async def _run(self, arguments: Dict[str, ProcessorArgument]):
        """Process resources using JLECmd"""
        # invoke subprocess
        proc = await self._start_subprocess(
            'datashark.processors.jlecmd.bin',
            ['-q'],
            [
                # optional
                ('all', '--all'),
                ('ld', '--ld'),
                ('mp', '--mp'),
                ('fd', '--fd'),
                ('withDir', '--withDir'),
                ('appIds', '--appIds'),
                ('dumpTo', '--dumpTo'),
                ('dt', '--dt'),
                ('csv', '--csv'),
                ('csvf', '--csvf'),
                ('html', '--html'),
                ('json', '--json'),
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
