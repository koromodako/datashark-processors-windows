"""Datashark Template Plugin
"""
from typing import Dict
from asyncio.subprocess import PIPE, DEVNULL
from datashark_core.meta import ProcessorMeta
from datashark_core.logging import LOGGING_MANAGER
from datashark_core.processor import ProcessorInterface, ProcessorError
from datashark_core.model.api import Kind, System, ProcessorArgument

NAME = 'windows_mftecmd'
LOGGER = LOGGING_MANAGER.get_logger(NAME)


class MFTECmdProcessor(ProcessorInterface, metaclass=ProcessorMeta):
    """Template of a processor"""

    NAME = NAME
    SYSTEM = System.WINDOWS
    ARGUMENTS = [
        {
            'name': 'blf',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': """When true, use LF vs CRLF for newlines""",
        },
        {
            'name': 'fls',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': """
                When true, displays contents of directory specified by 'de'
            """,
        },
        {
            'name': 'sn',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': """Include DOS file name types""",
        },
        {
            'name': 'fl',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': """
                Generate condensed file listing. Requires 'csv'
            """,
        },
        {
            'name': 'at',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': """
                When true, include all timestamps from 0x30 attribute vs only when they differ from 0x10
            """,
        },
        {
            'name': 'vss',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': """
                Process all Volume Shadow Copies that exist on drive specified by 'f'
            """,
        },
        {
            'name': 'dedupe',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': """
                Deduplicate 'f' & VSCs based on SHA-1. First file found wins
            """,
        },
        {
            'name': 'bdl',
            'kind': Kind.STR,
            'required': False,
            'description': """
                Drive letter (C, D, etc.) to use with bodyfile. Only the drive letter itself should be provided
            """,
        },
        {
            'name': 'dd',
            'kind': Kind.PATH,
            'required': False,
            'description': """
                Directory to save exported FILE record. 'do' is also required when using this option
            """,
        },
        {
            'name': 'do',
            'kind': Kind.INT,
            'required': False,
            'description': """
                Offset of the FILE record to dump as decimal or hex e.g. 5120 or 0x1400. Use 'de' to see offsets
            """,
        },
        {
            'name': 'de',
            'kind': Kind.STR,
            'required': False,
            'description': """
                Dump full details for entry/sequence #. Format is 'Entry' or 'Entry-Seq' as decimal or hex e.g. 5, 624-5 or 0x270-0x5
            """,
        },
        {
            'name': 'ds',
            'kind': Kind.INT,
            'required': False,
            'description': """
                Dump full details for Security Id as decimal or hex. Example: 624 or 0x270
            """,
        },
        {
            'name': 'dt',
            'kind': Kind.STR,
            'value': 'yyyy-MM-dd HH:mm:ss.fffffff',
            'required': False,
            'description': """
                The custom date/time format to use when displaying time stamps
            """,
        },
        {
            'name': 'json',
            'kind': Kind.PATH,
            'required': False,
            'description': """
                Directory to save JSON formatted results to. This or 'csv' required unless 'de' or 'body' is specified
            """,
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
                Directory to save CSV formatted results to. This or 'json' required unless 'de' or 'body' is specified
            """,
        },
        {
            'name': 'csvf',
            'kind': Kind.STR,
            'required': False,
            'description': """File name to save CSV formatted results to""",
        },
        {
            'name': 'body',
            'kind': Kind.PATH,
            'required': False,
            'description': """
                Directory to save bodyfile formatted results to. 'bdl' is also required when using this option
            """,
        },
        {
            'name': 'bodyf',
            'kind': Kind.STR,
            'required': False,
            'description': """File name to save body formatted results to""",
        },
        {
            'name': 'f',
            'kind': Kind.PATH,
            'required': True,
            'description': """
                File to process ($MFT | $J | $LogFile | $Boot | $SDS)
            """,
        },
    ]
    DESCRIPTION = """
    Processor for Eric Zimmermann's MFTECmd
    """

    async def _run(self, arguments: Dict[str, ProcessorArgument]):
        """Process resources using MFTECmd"""
        # invoke subprocess
        proc = await self._start_subprocess(
            'datashark.processors.mftecmd.bin',
            [],
            [
                # optional
                ('blf', '--blf'),
                ('fls', '--fls'),
                ('sn', '--sn'),
                ('fl', '--fl'),
                ('at', '--at'),
                ('vss', '--vss'),
                ('dedupe', '--dedupe'),
                ('bdl', '--bdl'),
                ('dd', '--dd'),
                ('do', '--do'),
                ('de', '--de'),
                ('ds', '--ds'),
                ('dt', '--dt'),
                ('json', '--json'),
                ('jsonf', '--jsonf'),
                ('csv', '--csv'),
                ('csvf', '--csvf'),
                ('body', '--body'),
                ('bodyf', '--bodyf'),
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
