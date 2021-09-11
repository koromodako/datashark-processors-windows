"""Datashark Template Plugin
"""
from typing import Dict
from asyncio.subprocess import PIPE, DEVNULL
from datashark_core.meta import ProcessorMeta
from datashark_core.logging import LOGGING_MANAGER
from datashark_core.processor import ProcessorInterface, ProcessorError
from datashark_core.model.api import Kind, System, ProcessorArgument

NAME = 'windows_srumecmd'
LOGGER = LOGGING_MANAGER.get_logger(NAME)


class SrumECmdProcessor(ProcessorInterface, metaclass=ProcessorMeta):
    """Template of a processor"""

    NAME = NAME
    SYSTEM = System.WINDOWS
    ARGUMENTS = [
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
            'name': 'r',
            'kind': Kind.PATH,
            'required': False,
            'description': """
                SOFTWARE hive to process. This is optional, but recommended
            """,
        },
        {
            'name': 'f',
            'kind': Kind.PATH,
            'required': False,
            'description': """
                SRUDB.dat file to process. Either this or "d" is required
            """,
        },
        {
            'name': 'd',
            'kind': Kind.PATH,
            'required': False,
            'description': """
                Directory to recursively process, looking for SRUDB.dat and SOFTWARE hive
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
    ]
    DESCRIPTION = """
    Processor for Eric Zimmermann's SrumECmd
    """

    async def _run(self, arguments: Dict[str, ProcessorArgument]):
        """Process resources using srumecmd"""
        # invoke subprocess
        proc = await self._start_subprocess(
            'datashark.processors.srumecmd.bin',
            [],
            [
                # optional
                ('dt', '--dt'),
                ('r', '-r'),
                ('f', '-f'),
                ('d', '-d'),
                ('csv', '--csv'),
                # positional
            ],
            arguments,
            stdout=DEVNULL,
            stderr=PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise ProcessorError(stderr)
