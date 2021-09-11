"""Datashark Template Plugin
"""
from typing import Dict
from asyncio.subprocess import PIPE, DEVNULL
from datashark_core.meta import ProcessorMeta
from datashark_core.logging import LOGGING_MANAGER
from datashark_core.processor import ProcessorInterface, ProcessorError
from datashark_core.model.api import Kind, System, ProcessorArgument

NAME = 'windows_wxtcmd'
LOGGER = LOGGING_MANAGER.get_logger(NAME)


class WxTCmdProcessor(ProcessorInterface, metaclass=ProcessorMeta):
    """WxTCmd processor"""

    NAME = NAME
    SYSTEM = System.WINDOWS
    ARGUMENTS = [
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
            'name': 'f',
            'kind': Kind.PATH,
            'required': True,
            'description': """File to process""",
        },
        {
            'name': 'csv',
            'kind': Kind.PATH,
            'required': True,
            'description': """
                Directory to save CSV formatted results to. Be sure to include the full path in double quotes
            """,
        },
    ]
    DESCRIPTION = """
    Processor for Eric Zimmermann's WxTCmd
    """

    async def _run(self, arguments: Dict[str, ProcessorArgument]):
        """Process resources using wxtcmd"""
        # invoke subprocess
        proc = await self._start_subprocess(
            'datashark.processors.wxtcmd.bin',
            [],
            [
                # optional
                ('dt', '--dt'),
                ('f', '-f'),
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
