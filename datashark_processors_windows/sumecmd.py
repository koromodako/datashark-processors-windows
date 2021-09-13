"""Datashark Template Plugin
"""
from typing import Dict
from asyncio.subprocess import PIPE, DEVNULL
from datashark_core.meta import ProcessorMeta
from datashark_core.logging import LOGGING_MANAGER
from datashark_core.processor import ProcessorInterface, ProcessorError
from datashark_core.model.api import Kind, System, ProcessorArgument

NAME = 'windows_sumecmd'
LOGGER = LOGGING_MANAGER.get_logger(NAME)


class SumECmdProcessor(ProcessorInterface, metaclass=ProcessorMeta):
    """SumECmd processor"""

    NAME = NAME
    SYSTEM = System.WINDOWS
    ARGUMENTS = [
        {
            'name': 'wd',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': """
                Do not generate day level details in CSV
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
            'name': 'd',
            'kind': Kind.PATH,
            'required': True,
            'description': """
                Directory to recursively process, looking for SystemIdentity.mdb, Current.mdb, etc
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
    Processor for Eric Zimmermann's SumECmd
    """

    async def _run(self, arguments: Dict[str, ProcessorArgument]):
        """Process resources using sumecmd"""
        # invoke subprocess
        proc = await self._start_subprocess(
            'datashark.processors.sumecmd.bin',
            [],
            [
                # optional
                ('wd', '--wd'),
                ('dt', '--dt'),
                ('d', '-d'),
                ('csv', '--csv'),
                # positional
            ],
            arguments,
            stdout=DEVNULL,
            stderr=PIPE,
        )
        await self._handle_communicating_process(proc)
